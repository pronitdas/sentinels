import { spawn } from 'child_process';
import fs from 'fs';
import http from 'http';
import https from 'https';
import os from 'os';
import path from 'path';
import { Queue, Worker } from 'bullmq';
import IORedis from 'ioredis';
import { emitScanEvent } from './events';
import {
  areAllScanRunsFinished,
  getScanById,
  insertFindings,
  markScanFailed,
  updateScanRunStatus,
  updateScanStatus,
} from './db';
import { COMMON_IGNORE_PATTERNS, toContainerPath, HOST_PATH_PREFIX } from './config';
import { parsers, SupportedScanner, UnifiedFinding } from './parsers';

const redisConnection = new IORedis(process.env.REDIS_URL || 'redis://localhost:36379', {
  maxRetriesPerRequest: null,
});

export interface ScanJobPayload {
  scanId: string;
  scanRunId: string;
  hostPath: string;
  // scanners: SupportedScanner[];
  scannerType: SupportedScanner;
}

export const scannerQueue = new Queue<ScanJobPayload>('scanner-queue', { connection: redisConnection });

interface ScannerCommandConfig {
  dockerArgs: string[];
  parser: (output: any) => UnifiedFinding[];
  transformOutput?: (rawOutput: string) => Promise<any>;
}

const parseJsonOutput = async (rawOutput: string) => {
  if (!rawOutput) {
    return {};
  }
  const trimmed = rawOutput.trim();
  try {
    return JSON.parse(trimmed);
  } catch (err) {
    const firstObject = trimmed.indexOf('{');
    const firstArray = trimmed.indexOf('[');
    const candidates = [firstObject, firstArray].filter((idx) => idx >= 0);
    if (candidates.length === 0) {
      throw err;
    }
    const start = Math.min(...candidates);
    const startChar = trimmed[start];
    const end = startChar === '{' ? trimmed.lastIndexOf('}') : trimmed.lastIndexOf(']');
    if (end <= start) {
      throw err;
    }
    const sliced = trimmed.slice(start, end + 1);
    return JSON.parse(sliced);
  }
};

const MAX_SCAN_FILE_SIZE_BYTES = 2 * 1024 * 1024;
const SEMGREP_CONFIGS = (process.env.SEMGREP_CONFIG || 'auto')
  .split(',')
  .map((cfg) => cfg.trim())
  .filter(Boolean);

function runDockerCommand(args: string[]) {
  return new Promise<void>((resolve, reject) => {
    const child = spawn('docker', args);
    let stderr = '';

    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`docker ${args.join(' ')} failed: ${stderr}`));
        return;
      }
      resolve();
    });
  });
}

function sanitizeTag(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9]+/g, '').slice(-24) || 'scan';
}

function importDirectoryAsImage(hostPath: string, imageTag: string) {
  return new Promise<void>((resolve, reject) => {
    const tarArgs = ['run', '--rm', '-v', `${hostPath}:/workspace:ro`, 'alpine:3.19', 'tar'];
    if (COMMON_IGNORE_PATTERNS.length > 0) {
      COMMON_IGNORE_PATTERNS.forEach((pattern) => {
        tarArgs.push('--exclude', pattern);
      });
    }
    tarArgs.push('-C', '/workspace', '-c', '.');
    const importArgs = ['import', '-', imageTag];

    const tarProcess = spawn('docker', tarArgs);
    const importProcess = spawn('docker', importArgs);
    let tarStderr = '';
    let importStderr = '';

    tarProcess.stderr.on('data', (chunk) => {
      tarStderr += chunk;
    });
    importProcess.stderr.on('data', (chunk) => {
      importStderr += chunk;
    });

    tarProcess.stdout.pipe(importProcess.stdin);

    let settled = false;
    const bail = (err: Error) => {
      if (settled) return;
      settled = true;
      importProcess.kill('SIGTERM');
      reject(err);
    };
    const succeed = () => {
      if (settled) return;
      settled = true;
      resolve();
    };

    tarProcess.on('error', (err) => bail(err));
    importProcess.on('error', (err) => {
      if (settled) return;
      settled = true;
      reject(err);
    });

    tarProcess.on('close', (code) => {
      if (code !== 0) {
        bail(new Error(`Failed to archive directory for Clair: ${tarStderr}`));
      } else {
        importProcess.stdin.end();
      }
    });

    importProcess.on('close', (code) => {
      if (code !== 0) {
        if (!settled) {
          settled = true;
          reject(new Error(`Failed to import Clair image: ${importStderr}`));
        }
      } else {
        succeed();
      }
    });
  });
}

async function prepareClairTarget(hostPath: string, scanId: string) {
  const imageTag = `sentinel-clair-${sanitizeTag(scanId)}-${Date.now().toString(36)}`;
  console.log(`Packaging ${hostPath} into temporary image ${imageTag} for Clair`);
  await importDirectoryAsImage(hostPath, imageTag);

  return {
    target: imageTag,
    async cleanup() {
      try {
        await runDockerCommand(['image', 'rm', '-f', imageTag]);
      } catch (err) {
        console.warn(`Failed to remove Clair temp image ${imageTag}: ${(err as Error).message}`);
      }
    },
  };
}

async function copyDirectoryWithLimit(src: string, dest: string, maxBytes: number) {
  await fs.promises.mkdir(dest, { recursive: true });
  const entries = await fs.promises.readdir(src, { withFileTypes: true });

  for (const entry of entries) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);

    if (entry.isDirectory()) {
      await copyDirectoryWithLimit(srcPath, destPath, maxBytes);
    } else if (entry.isFile()) {
      const { size } = await fs.promises.stat(srcPath);
      if (size <= maxBytes) {
        await fs.promises.copyFile(srcPath, destPath);
      }
    }
  }
}

async function prepareFilteredTarget(hostPath: string, scanId: string) {
  const tempDir = await fs.promises.mkdtemp(path.join(os.tmpdir(), `sentinel-filtered-${sanitizeTag(scanId)}-`));
  await copyDirectoryWithLimit(hostPath, tempDir, MAX_SCAN_FILE_SIZE_BYTES);

  return {
    target: tempDir,
    async cleanup() {
      try {
        await fs.promises.rm(tempDir, { recursive: true, force: true });
      } catch (err) {
        console.warn(`Failed to remove filtered temp directory ${tempDir}: ${(err as Error).message}`);
      }
    },
  };
}

interface SonarCredentials {
  token?: string;
  username?: string;
  password?: string;
}

function resolveSonarCredentials(): SonarCredentials {
  if (process.env.SONARQUBE_TOKEN) {
    return { token: process.env.SONARQUBE_TOKEN };
  }
  return {
    username: process.env.SONARQUBE_USERNAME || 'admin',
    password: process.env.SONARQUBE_PASSWORD || 'Admin@1234567',
  };
}

function resolveSonarScannerUrl() {
  return process.env.SONARQUBE_SCANNER_URL || process.env.SONARQUBE_URL || 'http://localhost:19000';
}

function resolveSonarScannerNetworkArgs() {
  const network = process.env.SONARQUBE_SCANNER_NETWORK;
  if (!network) {
    return ['--network', 'host'];
  }
  if (network === 'none') {
    return [];
  }
  return ['--network', network];
}

function sonarAuthHeader() {
  const creds = resolveSonarCredentials();
  if (creds.token) {
    return `Basic ${Buffer.from(`${creds.token}:`).toString('base64')}`;
  }
  return `Basic ${Buffer.from(`${creds.username}:${creds.password}`).toString('base64')}`;
}

function sonarRequest<T = any>(path: string, expectJson = true): Promise<T> {
  const sonarUrl = process.env.SONARQUBE_URL || 'http://localhost:19000';
  const targetUrl = new URL(path, sonarUrl);
  const client = targetUrl.protocol === 'https:' ? https : http;

  return new Promise<T>((resolve, reject) => {
    const req = client.request(
      targetUrl,
      {
        method: 'GET',
        headers: {
          Authorization: sonarAuthHeader(),
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (chunk) => {
          chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        });
        res.on('end', () => {
          const body = Buffer.concat(chunks).toString('utf-8');
          if (!res.statusCode || res.statusCode < 200 || res.statusCode >= 300) {
            reject(new Error(`SonarQube request failed: ${res.statusCode} ${body}`));
            return;
          }
          try {
            if (expectJson) {
              resolve(JSON.parse(body));
            } else {
              resolve(body as T);
            }
          } catch (err) {
            reject(err);
          }
        });
      }
    );

    req.on('error', (err) => reject(err));
    req.end();
  });
}

async function fetchSonarIssues(projectKey: string) {
  const params = new URLSearchParams({
    componentKeys: projectKey,
    ps: '500',
  });
  const issues = await sonarRequest(`/api/issues/search?${params.toString()}`, true);
  const version = await sonarRequest<string>('/api/server/version', false);
  return { ...issues, serverVersion: version?.trim() };
}

function buildScannerCommand(scannerType: SupportedScanner, target: string, scanId: string): ScannerCommandConfig {
  switch (scannerType) {
    case 'trivy':
      return {
        dockerArgs: [
          'run',
          '--rm',
          '-v',
          `${target}:/target:ro`,
          'aquasec/trivy:latest',
          'fs',
          '--format',
          'json',
          '/target',
        ],
        parser: parsers.trivy,
      };
    case 'semgrep': {
      const dockerArgs = [
        'run',
        '--rm',
        '-v',
        `${target}:/src:ro`,
        'returntocorp/semgrep',
        'semgrep',
        '--quiet',
        '--json',
        '--output',
        '/dev/stdout',
      ];
      SEMGREP_CONFIGS.forEach((cfg) => {
        dockerArgs.push('--config', cfg);
      });
      COMMON_IGNORE_PATTERNS.forEach((pattern) => {
        dockerArgs.push('--exclude', pattern);
      });
      dockerArgs.push('/src');
      return {
        dockerArgs,
        parser: parsers.semgrep,
      };
    }
    case 'bandit': {
      const dockerArgs = [
        'run',
        '--rm',
        '-v',
        `${target}:/target:ro`,
        'cytopia/bandit:latest',
        '-r',
        '/target',
        '-f',
        'json',
        '--exit-zero',
      ];
      if (COMMON_IGNORE_PATTERNS.length > 0) {
        dockerArgs.push('-x', COMMON_IGNORE_PATTERNS.join(','));
      }
      return {
        dockerArgs,
        parser: parsers.bandit,
      };
    }
    case 'clair':
      return {
        dockerArgs: [
          'run',
          '--rm',
          '--network',
          'host',
          '-v',
          '/var/run/docker.sock:/var/run/docker.sock',
          '-e',
          'DOCKER_API_VERSION=1.44',
          'ovotech/clair-scanner',
          'clair-scanner',
          '-c',
          'http://localhost:6060',
          '--report',
          '/dev/stdout',
          target,
        ],
        parser: parsers.clair,
      };
    case 'sonarqube': {
      const sonarScannerUrl = resolveSonarScannerUrl();
      const creds = resolveSonarCredentials();
      const projectKey = `sentinel-${sanitizeTag(scanId)}-${Date.now().toString(36)}`;
      const dockerArgs = [
        'run',
        '--rm',
        ...resolveSonarScannerNetworkArgs(),
        '-v',
        `${target}:/usr/src`,
        '-w',
        '/usr/src',
        '-e',
        `SONAR_HOST_URL=${sonarScannerUrl}`,
        '-e',
        'SONAR_SCANNER_OPTS=-Xmx1024m',
      ];

      if (creds.token) {
        dockerArgs.push('-e', `SONAR_TOKEN=${creds.token}`);
      } else if (creds.username && creds.password) {
        dockerArgs.push('-e', `SONAR_LOGIN=${creds.username}`, '-e', `SONAR_PASSWORD=${creds.password}`);
      }

      dockerArgs.push(
        'sonarsource/sonar-scanner-cli',
        `-Dsonar.projectKey=${projectKey}`,
        `-Dsonar.projectName=${projectKey}`,
        '-Dsonar.sources=.',
        '-Dsonar.qualitygate.wait=true'
      );
      if (COMMON_IGNORE_PATTERNS.length > 0) {
        dockerArgs.push(`-Dsonar.exclusions=${COMMON_IGNORE_PATTERNS.join(',')}`);
      }

      return {
        dockerArgs,
        parser: parsers.sonarqube,
        transformOutput: async () => fetchSonarIssues(projectKey),
      };
    }
    default:
      throw new Error(`Unknown scanner type: ${scannerType}`);
  }
}

async function runScannerProcess(scanId: string, scannerType: SupportedScanner, hostPath: string) {
  // Use original host path for Docker volume mounts (Docker runs on host)
  let target = hostPath;
  const cleanupTasks: Array<() => Promise<void>> = [];

  if (scannerType === 'clair') {
    const prepared = await prepareClairTarget(target, scanId);
    target = prepared.target;
    cleanupTasks.push(prepared.cleanup);
  }

  const { dockerArgs, parser, transformOutput } = buildScannerCommand(scannerType, target, scanId);
  const convertOutput = transformOutput || parseJsonOutput;

  const runPromise = new Promise<number>((resolve, reject) => {
    const child = spawn('docker', dockerArgs);
    let rawOutput = '';
    let errorOutput = '';

    child.stdout.on('data', (chunk) => {
      rawOutput += chunk;
    });
    child.stderr.on('data', (chunk) => {
      errorOutput += chunk;
    });

    child.on('close', async (code) => {
      if (code !== 0) {
        const errorMessage = `Scanner ${scannerType} failed for scan ${scanId}: ${errorOutput}`;
        console.error(errorMessage);
        emitScanEvent(scanId, {
          type: 'status',
          status: 'failed',
          scanner: scannerType,
          message: errorOutput,
          timestamp: new Date().toISOString(),
        });
        reject(new Error(errorMessage));
        return;
      }

      try {
        const parsed = await convertOutput(rawOutput);
        const unifiedFindings = parser(parsed);
        await insertFindings(scanId, unifiedFindings);
        emitScanEvent(scanId, {
          type: 'status',
          status: 'running',
          scanner: scannerType,
          message: `Collected ${unifiedFindings.length} findings from ${scannerType}`,
          timestamp: new Date().toISOString(),
        });
        resolve(unifiedFindings.length);
      } catch (err: any) {
        const parseError = `Failed to parse or insert findings for scan ${scanId}: ${err.message}`;
        console.error(parseError);
        emitScanEvent(scanId, {
          type: 'status',
          status: 'failed',
          scanner: scannerType,
          message: parseError,
          timestamp: new Date().toISOString(),
        });
        reject(new Error(parseError));
      }
    });
  });

  return runPromise.finally(async () => {
    while (cleanupTasks.length > 0) {
      const cleanup = cleanupTasks.pop();
      if (cleanup) {
        try {
          await cleanup();
        } catch (err) {
          console.warn(`Cleanup for scan ${scanId} failed: ${(err as Error).message}`);
        }
      }
    }
  });
}

export const scanWorker = new Worker<ScanJobPayload>(
  'scanner-queue',
  async (job) => {
    const { scanId, scanRunId, hostPath, scannerType } = job.data;

    try {
      const scanRecord = await getScanById(scanId);
      const firstStart = scanRecord?.started_at ? undefined : new Date();
      if (!scanRecord || scanRecord.status !== 'running') {
        await updateScanStatus(scanId, 'running', firstStart);
        if (!scanRecord?.started_at) {
          emitScanEvent(scanId, {
            type: 'status',
            status: 'running',
            message: 'Scan started',
            timestamp: new Date().toISOString(),
          });
        }
      }

      await updateScanRunStatus(scanRunId, 'running', new Date());
      emitScanEvent(scanId, {
        type: 'status',
        status: 'running',
        scanner: scannerType,
        message: `Starting ${scannerType}`,
        timestamp: new Date().toISOString(),
      });

      const findingsCount = await runScannerProcess(scanId, scannerType, hostPath);
      await updateScanRunStatus(scanRunId, 'completed', undefined, new Date(), undefined, findingsCount);
      console.log(`Scan job ${scanId} (${scannerType}) completed with ${findingsCount} findings.`);

      if (await areAllScanRunsFinished(scanId)) {
        const current = await getScanById(scanId);
        if (current && current.status !== 'failed') {
          await updateScanStatus(scanId, 'completed', undefined, new Date());
          emitScanEvent(scanId, {
            type: 'status',
            status: 'completed',
            message: 'Scan completed',
            timestamp: new Date().toISOString(),
          });
        }
      }
    } catch (err: any) {
      console.error(`Scan job ${scanId} failed`, err);
      await updateScanRunStatus(scanRunId, 'failed', undefined, new Date(), err?.message || 'Unknown failure');
      await markScanFailed(scanId, err?.message || 'Unknown failure');
      emitScanEvent(scanId, {
        type: 'status',
        status: 'failed',
        message: err?.message || 'Scan failed',
        timestamp: new Date().toISOString(),
      });
      throw err;
    }
  },
  { connection: redisConnection, concurrency: 1 }
);

scanWorker.on('failed', (job, err) => {
  console.error(`Job ${job?.id} failed with error ${err.message}`);
});

process.on('SIGINT', async () => {
  await scanWorker.close();
  await scannerQueue.close();
  await redisConnection.disconnect();
});

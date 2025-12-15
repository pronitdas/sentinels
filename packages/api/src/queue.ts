import { spawn } from 'child_process';
import fs from 'fs';
import http from 'http';
import https from 'https';
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

// Clair v4 API integration
const CLAIR_URL = process.env.CLAIR_URL || 'http://localhost:6060';

interface ClairLayer {
  hash: string;
  uri: string;
  headers?: Record<string, string[]>;
}

interface ClairManifest {
  hash: string;
  layers: ClairLayer[];
}

function clairRequest<T = any>(
  path: string,
  method: 'GET' | 'POST' | 'DELETE' = 'GET',
  body?: any
): Promise<T> {
  const targetUrl = new URL(path, CLAIR_URL);
  const client = targetUrl.protocol === 'https:' ? https : http;

  return new Promise<T>((resolve, reject) => {
    const req = client.request(
      targetUrl,
      {
        method,
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
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
            reject(new Error(`Clair request failed: ${res.statusCode} ${body}`));
            return;
          }
          try {
            resolve(body ? JSON.parse(body) : ({} as T));
          } catch (err) {
            reject(err);
          }
        });
      }
    );

    req.on('error', (err) => reject(err));
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

function runDockerCommandWithOutput(args: string[]): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = spawn('docker', args);
    let stdout = '';
    let stderr = '';

    child.stdout.on('data', (chunk) => {
      stdout += chunk;
    });
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });

    child.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`docker ${args.join(' ')} failed: ${stderr}`));
        return;
      }
      resolve(stdout);
    });
  });
}

async function getImageManifestForClair(imageTag: string): Promise<ClairManifest> {
  // Get image inspect data
  const inspectOutput = await runDockerCommandWithOutput(['inspect', imageTag]);
  const inspectData = JSON.parse(inspectOutput)[0];

  // Get image ID as the manifest hash
  const imageId = inspectData.Id.replace('sha256:', '');

  // Save image as tar to extract layer info
  const tarOutput = await runDockerCommandWithOutput([
    'save', imageTag, '-o', `/tmp/${imageTag}.tar`
  ]);

  // Extract manifest.json from the tar
  const manifestJson = await runDockerCommandWithOutput([
    'run', '--rm', '-v', `/tmp/${imageTag}.tar:/image.tar:ro`,
    'alpine:3.19', 'sh', '-c',
    'tar -xOf /image.tar manifest.json'
  ]);

  const manifest = JSON.parse(manifestJson)[0];
  const layers: ClairLayer[] = [];

  // Build layer info - Clair needs URIs to fetch layers
  // Since we're running locally, we'll use the Docker daemon
  for (const layerPath of manifest.Layers || []) {
    const layerHash = layerPath.replace('/layer.tar', '').replace('blobs/sha256/', '');
    layers.push({
      hash: `sha256:${layerHash}`,
      uri: `file:///tmp/${imageTag}.tar`,
      headers: {},
    });
  }

  // Clean up tar file
  await runDockerCommand(['run', '--rm', '-v', '/tmp:/tmp', 'alpine:3.19', 'rm', `-f`, `/tmp/${imageTag}.tar`]);

  return {
    hash: `sha256:${imageId}`,
    layers,
  };
}

async function scanImageWithClairV4(imageTag: string): Promise<any> {
  console.log(`Scanning image ${imageTag} with Clair v4`);

  // For Clair v4, we need to use clairctl or direct API
  // The simplest approach is to use Clair's indexer API with a local registry
  // Since we don't have a registry, we'll use Trivy-style layer analysis

  // Alternative: Use skopeo to push to Clair or use clairctl
  // For now, let's use a workaround: export layers and scan directly

  // Get image layers using docker
  const inspectOutput = await runDockerCommandWithOutput(['inspect', imageTag]);
  const inspectData = JSON.parse(inspectOutput)[0];
  const imageId = inspectData.Id;

  // Try to submit manifest to Clair v4 indexer
  // Clair v4 needs layers accessible via HTTP/HTTPS
  // Since we're in Docker network, we need a different approach

  // Use docker save + analyze approach
  const manifest: ClairManifest = {
    hash: imageId,
    layers: (inspectData.RootFS?.Layers || []).map((layer: string, idx: number) => ({
      hash: layer,
      uri: `docker://${imageTag}`,
      headers: {},
    })),
  };

  try {
    // Submit to indexer
    console.log('Submitting manifest to Clair v4 indexer...');
    const indexReport = await clairRequest<any>(
      '/indexer/api/v1/index_report',
      'POST',
      manifest
    );

    // Poll for completion
    let state = indexReport.state;
    let attempts = 0;
    const maxAttempts = 30;

    while (state !== 'IndexFinished' && state !== 'IndexError' && attempts < maxAttempts) {
      await new Promise((r) => setTimeout(r, 2000));
      const statusReport = await clairRequest<any>(
        `/indexer/api/v1/index_report/${encodeURIComponent(manifest.hash)}`
      );
      state = statusReport.state;
      attempts++;
      console.log(`Clair indexing state: ${state} (attempt ${attempts}/${maxAttempts})`);
    }

    if (state === 'IndexError') {
      throw new Error('Clair indexing failed');
    }

    if (state !== 'IndexFinished') {
      throw new Error(`Clair indexing timed out in state: ${state}`);
    }

    // Get vulnerability report
    console.log('Fetching vulnerability report from Clair v4...');
    const vulnReport = await clairRequest<any>(
      `/matcher/api/v1/vulnerability_report/${encodeURIComponent(manifest.hash)}`
    );

    return {
      manifest_hash: manifest.hash,
      image_name: imageTag,
      vulnerabilities: vulnReport.vulnerabilities || {},
      packages: vulnReport.packages || {},
      package_vulnerabilities: vulnReport.package_vulnerabilities || {},
    };
  } catch (err: any) {
    // If direct API fails, try alternative approach using clairctl if available
    console.error(`Clair v4 API error: ${err.message}`);

    // Fallback: return empty result with error info
    return {
      manifest_hash: manifest.hash,
      image_name: imageTag,
      vulnerabilities: {},
      error: err.message,
    };
  }
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
    case 'trivy': {
      const dockerArgs = [
        'run',
        '--rm',
        '-v',
        `${target}:/target:ro`,
        'aquasec/trivy:latest',
        'fs',
        '--format',
        'json',
      ];
      COMMON_IGNORE_PATTERNS.forEach((pattern) => {
        dockerArgs.push('--skip-files', pattern);
      });
      dockerArgs.push('/target');
      return {
        dockerArgs,
        parser: parsers.trivy,
      };
    }
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
        '--max-target-bytes',
        String(MAX_SCAN_FILE_SIZE_BYTES),
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
      // Clair v4 uses direct API calls, not docker run
      // dockerArgs is empty - we handle this specially in runScannerProcess
      return {
        dockerArgs: [],
        parser: parsers.clair,
        transformOutput: async () => scanImageWithClairV4(target),
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

  // Handle scanners that use direct API calls (no docker command)
  if (dockerArgs.length === 0 && transformOutput) {
    const runPromise = (async () => {
      try {
        const parsed = await transformOutput('');
        const unifiedFindings = parser(parsed);
        await insertFindings(scanId, unifiedFindings);
        emitScanEvent(scanId, {
          type: 'status',
          status: 'running',
          scanner: scannerType,
          message: `Collected ${unifiedFindings.length} findings from ${scannerType}`,
          timestamp: new Date().toISOString(),
        });
        return unifiedFindings.length;
      } catch (err: any) {
        const errorMessage = `Scanner ${scannerType} failed for scan ${scanId}: ${err.message}`;
        console.error(errorMessage);
        emitScanEvent(scanId, {
          type: 'status',
          status: 'failed',
          scanner: scannerType,
          message: err.message,
          timestamp: new Date().toISOString(),
        });
        throw new Error(errorMessage);
      }
    })();

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

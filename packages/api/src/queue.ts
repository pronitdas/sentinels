import { spawn } from 'child_process';
import { Queue, Worker } from 'bullmq';
import IORedis from 'ioredis';
import { emitScanEvent } from './events';
import { insertFindings, markScanFailed, updateScanStatus } from './db';
import { parsers, SupportedScanner } from './parsers';

const redisConnection = new IORedis(process.env.REDIS_URL || 'redis://localhost:6379', {
  maxRetriesPerRequest: null,
});

export interface ScanJobPayload {
  scanId: string;
  hostPath: string;
  // scanners: SupportedScanner[];
  scannerType: SupportedScanner;
}

export const scannerQueue = new Queue<ScanJobPayload>('scanner-queue', { connection: redisConnection });

function buildScannerCommand(scannerType: SupportedScanner, hostPath: string) {
  switch (scannerType) {
    case 'trivy':
      return {
        dockerArgs: [
          'run',
          '--rm',
          '-v',
          `${hostPath}:/target:ro`,
          'aquasec/trivy:latest',
          'fs',
          '--format',
          'json',
          '/target',
        ],
        parser: parsers.trivy,
      };
    case 'semgrep':
      return {
        dockerArgs: [
          'run',
          '--rm',
          '-v',
          `${hostPath}:/src:ro`,
          'returntocorp/semgrep',
          'semgrep',
          '--json',
          '--output',
          '/dev/stdout',
          '/src',
        ],
        parser: parsers.semgrep,
      };
    case 'bandit':
      return {
        dockerArgs: [
          'run',
          '--rm',
          '-v',
          `${hostPath}:/target:ro`,
          'pycqa/bandit',
          '-r',
          '/target',
          '-f',
          'json',
        ],
        parser: parsers.bandit,
      };
    case 'clair':
      return {
        dockerArgs: [
          'run',
          '--rm',
          '--network',
          'host',
          '-v',
          '/var/run/docker.sock:/var/run/docker.sock',
          'ovotech/clair-scanner',
          '-c',
          'http://localhost:6060',
          '--report',
          '/dev/stdout',
          hostPath,
        ],
        parser: parsers.clair,
      };
    default:
      throw new Error(`Unknown scanner type: ${scannerType}`);
  }
}

async function runScannerProcess(scanId: string, scannerType: SupportedScanner, hostPath: string) {
  const { dockerArgs, parser } = buildScannerCommand(scannerType, hostPath);

  return new Promise<void>((resolve, reject) => {
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
        const parsed = rawOutput ? JSON.parse(rawOutput) : {};
        const unifiedFindings = parser(parsed);
        await insertFindings(scanId, unifiedFindings);
        emitScanEvent(scanId, {
          type: 'status',
          status: 'running',
          scanner: scannerType,
          message: `Collected ${unifiedFindings.length} findings from ${scannerType}`,
          timestamp: new Date().toISOString(),
        });
        resolve();
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
}

export const scanWorker = new Worker<ScanJobPayload>(
  'scanner-queue',
  async (job) => {
    const { scanId, hostPath, scannerType } = job.data;
    // console.log(`Processing scan job ${scanId} for scanner [${scannerType}] on ${hostPath}`);

    try {
      await updateScanStatus(scanId, 'running', new Date());
      emitScanEvent(scanId, {
        type: 'status',
        status: 'running',
        message: 'Scan started',
        timestamp: new Date().toISOString(),
      });

      // for (const scannerType of scanners) {
      emitScanEvent(scanId, {
        type: 'status',
        status: 'running',
        scanner: scannerType,
        message: `Starting ${scannerType}`,
        timestamp: new Date().toISOString(),
      });
      await runScannerProcess(scanId, scannerType, hostPath);
      // }

      await updateScanStatus(scanId, 'completed', undefined, new Date());
      emitScanEvent(scanId, {
        type: 'status',
        status: 'completed',
        message: 'Scan completed',
        timestamp: new Date().toISOString(),
      });
      console.log(`Scan job ${scanId} completed successfully.`);
    } catch (err: any) {
      console.error(`Scan job ${scanId} failed`, err);
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

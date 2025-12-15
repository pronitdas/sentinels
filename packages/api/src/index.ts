import Fastify from 'fastify';
import cors from '@fastify/cors';
import {
  connectDb,
  createProject,
  createScan,
  createScanRun,
  createTables,
  getProjectById,
  getScanById,
  listFindings,
  listProjects,
  listScanRuns,
  listScanRunsByScanIds,
  listScansByProject,
} from './db';
import { scannerQueue } from './queue';
import { SupportedScanner } from './parsers';

const fastify = Fastify({
  logger: true,
});

fastify.register(cors, {
  origin: true, // Allow all origins for this local-first tool
});

// Register new codebase
fastify.post('/projects', async (request, reply) => {
  const { name, path } = request.body as { name: string; path: string };
  const project = await createProject(name, path);
  reply.status(201).send(project);
});

// List projects
fastify.get('/projects', async (request, reply) => {
  const projects = await listProjects();
  reply.send(projects);
});

// Trigger scan
fastify.post('/scans', async (request, reply) => {
  const { projectId, scanners } = request.body as { projectId: string; scanners: SupportedScanner[] };
  if (!scanners || scanners.length === 0) {
    reply.status(400).send({ error: 'Select at least one scanner' });
    return;
  }

  const project = await getProjectById(projectId);
  if (!project) {
    reply.status(404).send({ error: 'Project not found' });
    return;
  }

  const scanRecord = await createScan(projectId, scanners);

  for (const scannerType of scanners) {
    const run = await createScanRun(scanRecord.id, scannerType);
    await scannerQueue.add('scan-job', {
      scanId: scanRecord.id,
      scanRunId: run.id,
      hostPath: project.path,
      scannerType,
    });
  }

  reply.status(202).send(scanRecord);
});

// Get status & summary for a scan
fastify.get('/scans/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  const scan = await getScanById(id);
  if (!scan) {
    reply.status(404).send({ error: 'Scan not found' });
    return;
  }
  reply.send(scan);
});

// Scan runs for a project (history)
fastify.get('/projects/:id/scans', async (request, reply) => {
  const { id } = request.params as { id: string };
  const scans = await listScansByProject(id);
  const scanIds = scans.map((s) => s.id);
  const runs = await listScanRunsByScanIds(scanIds);
  const runsByScan = runs.reduce<Record<string, typeof runs>>((acc, run) => {
    acc[run.scan_id] = acc[run.scan_id] || [];
    acc[run.scan_id].push(run);
    return acc;
  }, {});

  const payload = scans.map((scan) => ({
    ...scan,
    runs: runsByScan[scan.id] || [],
  }));

  reply.send(payload);
});

fastify.get('/scans/:id/runs', async (request, reply) => {
  const { id } = request.params as { id: string };
  const runs = await listScanRuns(id);
  reply.send(runs);
});

// Global search findings
fastify.get('/findings', async (request, reply) => {
  const { severity, type } = request.query as { severity?: string; type?: string };
  const rows = await listFindings(severity, type);
  reply.send(rows);
});


const start = async () => {
  try {
    await connectDb();
    await createTables();
    await fastify.listen({ port: 4000, host: '0.0.0.0' });
    console.log(`API listening on http://0.0.0.0:4000`);
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
};

start();

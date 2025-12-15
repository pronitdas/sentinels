import Fastify from 'fastify';
import cors from '@fastify/cors';
import { connectDb, createTables, client } from './db';
import { scannerQueue } from './queue';
import { v4 as uuidv4 } from 'uuid';
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
  const result = await client.query(
    'INSERT INTO projects (name, path) VALUES ($1, $2) RETURNING id, name, path, created_at',
    [name, path]
  );
  reply.status(201).send(result.rows[0]);
});

// List projects
fastify.get('/projects', async (request, reply) => {
  const result = await client.query('SELECT id, name, path, created_at FROM projects');
  reply.send(result.rows);
});

// Trigger scan
fastify.post('/scans', async (request, reply) => {
  const { projectId, scanners } = request.body as { projectId: string; scanners: SupportedScanner[] };

  // Insert scan into DB
  const scanResult = await client.query(
    'INSERT INTO scans (project_id, scanners, status) VALUES ($1, $2, $3) RETURNING id, project_id, scanners, status, started_at',
    [projectId, scanners, 'pending']
  );
  const scanId = scanResult.rows[0].id;

  // Add a job to the queue for each scanner
  for (const scannerType of scanners) {
    // Fetch project path
    const projectResult = await client.query('SELECT path FROM projects WHERE id = $1', [projectId]);
    if (projectResult.rows.length === 0) {
      reply.status(404).send({ error: 'Project not found' });
      return;
    }
    const hostPath = projectResult.rows[0].path;

    await scannerQueue.add('scan-job', { scanId, hostPath, scannerType });
  }

  reply.status(202).send(scanResult.rows[0]);
});

// Get status & summary for a scan
fastify.get('/scans/:id', async (request, reply) => {
  const { id } = request.params as { id: string };
  const result = await client.query('SELECT * FROM scans WHERE id = $1', [id]);
  if (result.rows.length === 0) {
    reply.status(404).send({ error: 'Scan not found' });
    return;
  }
  reply.send(result.rows[0]);
});

// Global search findings
fastify.get('/findings', async (request, reply) => {
  const { severity, type } = request.query as { severity?: string; type?: string };
  let query = 'SELECT * FROM findings WHERE 1=1';
  const params: string[] = [];
  let paramIndex = 1;

  if (severity) {
    query += ` AND severity = $${paramIndex++}`;
    params.push(severity);
  }
  // 'type' is not directly a column in findings, it might be derived from scanner_name or rule_id
  // For now, ignoring 'type' or assuming it maps to scanner_name for simplicity
  if (type) {
    query += ` AND scanner_name = $${paramIndex++}`;
    params.push(type);
  }

  const result = await client.query(query, params);
  reply.send(result.rows);
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

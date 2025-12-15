import { Client } from 'pg';

const client = new Client({
  connectionString:
    process.env.DATABASE_URL || 'postgres://sentinel:sentinel@localhost:35432/sentinel',
});

async function connectDb() {
  await client.connect();
  console.log('Connected to PostgreSQL');
}

// Ensure the tables are created based on the schema in sentinel_architecture.md
async function createTables() {
  await client.query(`
    CREATE EXTENSION IF NOT EXISTS "pgcrypto";

    CREATE TABLE IF NOT EXISTS projects (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL,
      path TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scans (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
      scanners TEXT[],
      status TEXT DEFAULT 'pending',
      error_log TEXT,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS scan_runs (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
      scanner_name TEXT NOT NULL,
      status TEXT DEFAULT 'pending',
      error_log TEXT,
      findings_count INT DEFAULT 0,
      started_at TIMESTAMPTZ,
      completed_at TIMESTAMPTZ,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    ALTER TABLE scans ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();
    ALTER TABLE scan_runs ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT NOW();

    CREATE TABLE IF NOT EXISTS findings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
      scanner_name TEXT NOT NULL,
      scanner_version TEXT,
      rule_id TEXT NOT NULL,
      fingerprint TEXT NOT NULL,
      severity VARCHAR(10) NOT NULL,
      file_path TEXT NOT NULL,
      start_line INT,
      end_line INT,
      title TEXT NOT NULL,
      description TEXT,
      remediation TEXT,
      cwe_ids TEXT[],
      cve_ids TEXT[],
      raw_data JSONB,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
    CREATE INDEX IF NOT EXISTS idx_findings_project ON findings(scan_id);
    CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
    CREATE INDEX IF NOT EXISTS idx_scan_runs_scan_id ON scan_runs(scan_id);
  `);
  console.log('Tables ensured to exist.');
}

export type ScanStatus = 'pending' | 'queued' | 'running' | 'completed' | 'failed';
export type ScanRunStatus = ScanStatus;

export interface ProjectRow {
  id: string;
  name: string;
  path: string;
  created_at: string;
}

export interface ScanRow {
  id: string;
  project_id: string;
  scanners: string[];
  status: ScanStatus;
  error_log: string | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface ScanRunRow {
  id: string;
  scan_id: string;
  scanner_name: string;
  status: ScanRunStatus;
  error_log: string | null;
  findings_count: number | null;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export async function createProject(name: string, resolvedPath: string): Promise<ProjectRow> {
  const result = await client.query<ProjectRow>(
    'INSERT INTO projects (name, path) VALUES ($1, $2) RETURNING id, name, path, created_at',
    [name, resolvedPath]
  );
  return result.rows[0];
}

export async function listProjects(): Promise<ProjectRow[]> {
  const result = await client.query<ProjectRow>('SELECT id, name, path, created_at FROM projects ORDER BY created_at DESC');
  return result.rows;
}

export async function getProjectById(projectId: string): Promise<ProjectRow | null> {
  const result = await client.query<ProjectRow>(
    'SELECT id, name, path, created_at FROM projects WHERE id = $1',
    [projectId]
  );
  return result.rows[0] || null;
}

export async function createScan(projectId: string, scanners: string[]): Promise<ScanRow> {
  const result = await client.query<ScanRow>(
    'INSERT INTO scans (project_id, scanners, status) VALUES ($1, $2, $3) RETURNING id, project_id, scanners, status, error_log, started_at, completed_at, created_at',
    [projectId, scanners, 'queued']
  );
  return result.rows[0];
}

export async function getScanById(scanId: string): Promise<ScanRow | null> {
  const result = await client.query<ScanRow>('SELECT * FROM scans WHERE id = $1', [scanId]);
  return result.rows[0] || null;
}

export async function listScansByProject(projectId: string): Promise<ScanRow[]> {
  const result = await client.query<ScanRow>(
    'SELECT * FROM scans WHERE project_id = $1 ORDER BY created_at DESC',
    [projectId]
  );
  return result.rows;
}

export async function createScanRun(scanId: string, scannerName: string): Promise<ScanRunRow> {
  const result = await client.query<ScanRunRow>(
    `INSERT INTO scan_runs (scan_id, scanner_name, status)
     VALUES ($1, $2, $3)
     RETURNING id, scan_id, scanner_name, status, error_log, findings_count, started_at, completed_at, created_at`,
    [scanId, scannerName, 'pending']
  );
  return result.rows[0];
}

export async function listScanRunsByScanIds(scanIds: string[]): Promise<ScanRunRow[]> {
  if (scanIds.length === 0) return [];
  const result = await client.query<ScanRunRow>(
    `SELECT id, scan_id, scanner_name, status, error_log, findings_count, started_at, completed_at, created_at
     FROM scan_runs
     WHERE scan_id = ANY($1::uuid[])
     ORDER BY created_at DESC`,
    [scanIds]
  );
  return result.rows;
}

export async function listScanRuns(scanId: string): Promise<ScanRunRow[]> {
  const result = await client.query<ScanRunRow>(
    `SELECT id, scan_id, scanner_name, status, error_log, findings_count, started_at, completed_at, created_at
     FROM scan_runs
     WHERE scan_id = $1
     ORDER BY created_at DESC`,
    [scanId]
  );
  return result.rows;
}

export async function listFindings(severity?: string, scannerName?: string) {
  let query = 'SELECT * FROM findings WHERE 1=1';
  const params: any[] = [];
  let idx = 1;

  if (severity) {
    query += ` AND severity = $${idx++}`;
    params.push(severity);
  }

  if (scannerName) {
    query += ` AND scanner_name = $${idx++}`;
    params.push(scannerName);
  }

  query += ' ORDER BY created_at DESC';

  const result = await client.query(query, params);
  return result.rows;
}

export async function updateScanStatus(
  scanId: string,
  status: ScanStatus,
  startedAt?: Date | null,
  completedAt?: Date | null,
  errorLog?: string | null
) {
  const updates = ['status = $2'];
  const values: any[] = [scanId, status];
  if (startedAt !== undefined) {
    updates.push(`started_at = $${values.length + 1}`);
    values.push(startedAt);
  }
  if (completedAt !== undefined) {
    updates.push(`completed_at = $${values.length + 1}`);
    values.push(completedAt);
  }
  if (errorLog !== undefined) {
    updates.push(`error_log = $${values.length + 1}`);
    values.push(errorLog);
  }
  const query = `UPDATE scans SET ${updates.join(', ')} WHERE id = $1`;
  await client.query(query, values);
}

export async function markScanFailed(scanId: string, errorLog: string) {
  await updateScanStatus(scanId, 'failed', undefined, new Date(), errorLog);
}

export async function updateScanRunStatus(
  scanRunId: string,
  status: ScanRunStatus,
  startedAt?: Date | null,
  completedAt?: Date | null,
  errorLog?: string | null,
  findingsCount?: number
) {
  const updates = ['status = $2'];
  const values: any[] = [scanRunId, status];
  if (startedAt !== undefined) {
    updates.push(`started_at = $${values.length + 1}`);
    values.push(startedAt);
  }
  if (completedAt !== undefined) {
    updates.push(`completed_at = $${values.length + 1}`);
    values.push(completedAt);
  }
  if (errorLog !== undefined) {
    updates.push(`error_log = $${values.length + 1}`);
    values.push(errorLog);
  }
  if (findingsCount !== undefined) {
    updates.push(`findings_count = $${values.length + 1}`);
    values.push(findingsCount);
  }

  const query = `UPDATE scan_runs SET ${updates.join(', ')} WHERE id = $1`;
  await client.query(query, values);
}

export async function areAllScanRunsFinished(scanId: string) {
  const result = await client.query<{ remaining: string }>(
    `SELECT COUNT(*)::int AS remaining
     FROM scan_runs
     WHERE scan_id = $1 AND status NOT IN ('completed', 'failed')`,
    [scanId]
  );
  return Number(result.rows[0]?.remaining || 0) === 0;
}

interface UnifiedFinding {
  scanner_name: string;
  scanner_version?: string;
  rule_id: string;
  fingerprint: string;
  severity: string;
  file_path: string;
  start_line?: number;
  end_line?: number;
  title: string;
  description?: string;
  remediation?: string;
  cwe_ids?: string[];
  cve_ids?: string[];
  raw_data?: any;
}

export async function insertFindings(scanId: string, findings: UnifiedFinding[]) {
  if (findings.length === 0) {
    return;
  }

  for (const finding of findings) {
    await client.query(
      `INSERT INTO findings (
        scan_id, scanner_name, scanner_version, rule_id, fingerprint,
        severity, file_path, start_line, end_line, title,
        description, remediation, cwe_ids, cve_ids, raw_data
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
      [
        scanId,
        finding.scanner_name,
        finding.scanner_version,
        finding.rule_id,
        finding.fingerprint,
        finding.severity,
        finding.file_path,
        finding.start_line || null,
        finding.end_line || null,
        finding.title,
        finding.description,
        finding.remediation,
        finding.cwe_ids || null,
        finding.cve_ids || null,
        finding.raw_data,
      ]
    );
  }
}

export { client, connectDb, createTables };

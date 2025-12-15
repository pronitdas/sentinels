# Sentinel — Technical Design Specification

**Status:** Draft / Phase 1  
**Type:** Application Security Orchestration (ASOC)  
**Architecture:** Local-First, Containerized, Microservices

---

## 1. Executive Summary
**Sentinel** is a local-first, self-hosted security scanning orchestrator. It unifies disparate security tools (Trivy, Semgrep, Grype, ZAP) into a single orchestration engine, normalizing their outputs into a standardized database for unified reporting and tracking.

**Core Philosophy:**
* **Local-First:** Data never leaves the user's infrastructure.
* **Scanner Agnostic:** Normalized "Unified Finding Interface" regardless of the underlying tool.
* **Containerized:** Zero-dependency installation (Docker-out-of-Docker pattern).

---

## 2. High-Level Architecture

### System Diagram
```text
┌─────────────────────────────────────────────────────────────────┐
│                         Browser UI                              │
│            (Next.js 14 App Router + Tailwind/Shadcn)            │
└─────────────────────────────┬───────────────────────────────────┘
                              │ REST / SSE (Events)
┌─────────────────────────────▼───────────────────────────────────┐
│                      API Gateway                                │
│                (Fastify + BullMQ Producer)                      │
└───────┬─────────────┬─────────────┬─────────────────────────────┘
        │             │             │
        │      ┌──────▼──────┐      │
        │      │   Redis     │◄─────┘ Job Queue
        │      └──────┬──────┘
        │             │
┌───────▼─────────────▼───────────────────────────────────────────┐
│                     Worker Service                              │
│              (BullMQ Consumer + Docker Client)                  │
│                                                                 │
│   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐
│   │  Trivy  │   │ Semgrep │   │  Grype  │   │   ZAP   │   │  Clair  │   │  Bandit │
│   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘   └────┬────┘
│        │             │             │             │             │             │      │
└────────┴─────────────┴──────┬──────┴─────────────┴──────────────┘
                              │ Normalized Data
                   ┌──────────▼──────────┐
                   │     PostgreSQL      │
                   │   (Unified Store)   │
                   └─────────────────────┘
```

### Technology Stack

| Component | Technology | Rationale |
| :--- | :--- | :--- |
| **Frontend** | Next.js 14 | React Server Components for data fetching; robust routing. |
| **Backend** | Fastify (Node.js) | Low overhead, native schema validation (Zod). |
| **Queue** | BullMQ + Redis | Robust handling of long-running scan jobs and retries. |
| **Database** | PostgreSQL 15 | Relational integrity + JSONB for raw evidence. |
| **Runtime** | Docker (DooD) | "Docker out of Docker" pattern to spawn ephemeral scanners. |

-----

## 3. Database Schema

The core innovation is the **Unified Finding Interface**, allowing different scanners to map to a single table structure.

```sql
-- Projects (repos/directories to scan)
CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  path TEXT NOT NULL,           -- Absolute path on HOST machine or Git URL
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Scan runs
CREATE TABLE scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  project_id UUID REFERENCES projects(id) ON DELETE CASCADE,
  scanners TEXT[],              -- ['trivy', 'semgrep']
  status TEXT DEFAULT 'pending', -- pending | running | completed | failed
  error_log TEXT,               -- Capture stderr if failed
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ
);

-- Unified Findings
CREATE TABLE findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scans(id) ON DELETE CASCADE,
  
  -- Core Identity
  scanner_name TEXT NOT NULL,         -- 'trivy', 'semgrep'
  scanner_version TEXT,               -- 'v0.45.0'
  
  -- Deduplication & Fingerprinting
  rule_id TEXT NOT NULL,              -- e.g., 'rules.security.react-dangerously-set-inner-html'
  fingerprint TEXT NOT NULL,          -- SHA256(file_path + rule_id + code_snippet)
  
  -- Standardized Severity
  severity VARCHAR(10) NOT NULL,      -- 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'
  
  -- Location
  file_path TEXT NOT NULL,
  start_line INT,
  end_line INT,
  
  -- Context
  title TEXT NOT NULL,
  description TEXT,
  remediation TEXT,                   
  
  -- Metadata
  cwe_ids TEXT[],                     -- ['CWE-79', 'CWE-80']
  cve_ids TEXT[],                     -- ['CVE-2023-XXXX']
  raw_data JSONB,                     -- Original scanner output
  
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Indexes
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_project ON findings(scan_id);
CREATE INDEX idx_findings_fingerprint ON findings(fingerprint);
```

-----

## 4. Orchestration Strategy (The "Worker")

### Docker-out-of-Docker (DooD)

We do not run Docker *inside* Docker. We mount the host's socket.

  * **Challenge:** The API container cannot see the user's host filesystem directly.
  * **Solution:** Pass `HOST_PROJECT_ROOT` env var to the worker. When mapping volumes, we use the *Host's* path.

### Worker Logic (TypeScript)

```typescript
// jobs/scanWorker.ts
import { Worker } from 'bullmq';
import { spawn } from 'child_process';
import { db } from '../db';
import { parsers } from '../parsers'; // Custom parsers for each tool

const worker = new Worker('scanner-queue', async (job) => {
  const { scanId, hostPath, scannerType } = job.data;
  
  // 1. Update Status
  await db.updateScanStatus(scanId, 'running');

  // 2. Construct Command (Example: Trivy)
  // We mount the HOST path to /target inside the ephemeral container
  const dockerArgs = [
    'run', '--rm',
    '-v', `${hostPath}:/target:ro`, 
    'aquasec/trivy:latest', 
    'fs', '--format', 'json', '/target'
  ];

  return new Promise((resolve, reject) => {
    // Use spawn instead of execSync for stream handling
    const child = spawn('docker', dockerArgs);
    let rawOutput = '';
    let errorOutput = '';

    child.stdout.on('data', (chunk) => { rawOutput += chunk; });
    child.stderr.on('data', (chunk) => { errorOutput += chunk; });

    child.on('close', async (code) => {
      if (code !== 0) {
        await db.markScanFailed(scanId, errorOutput);
        reject(new Error(`Scanner failed: ${errorOutput}`));
        return;
      }
      
      // 3. Normalize Data
      try {
        const json = JSON.parse(rawOutput);
        const unifiedFindings = parsers[scannerType](json);
        await db.insertFindings(scanId, unifiedFindings);
        await db.updateScanStatus(scanId, 'completed');
        resolve(true);
      } catch (e) {
        reject(new Error('Failed to parse scanner output'));
      }
    });
  });
}, { connection: redisConnection, concurrency: 2 });
```

-----

## 5. API Endpoints

| Method | Endpoint | Description | Payload |
| :--- | :--- | :--- | :--- |
| `POST` | `/projects` | Register new codebase | `{ name, path }` |
| `GET` | `/projects` | List projects | - |
| `POST` | `/scans` | Trigger scan | `{ projectId, scanners: ['trivy'] }` |
| `GET` | `/scans/:id` | Get status & summary | - |
| `GET` | `/scans/:id/events` | **SSE** stream for progress | - |
| `GET` | `/findings` | Global search | `?severity=HIGH&type=sast` |

-----

## 6. Implementation Plan

### Phase 1: Foundation (Week 1)

  * Setup `docker-compose` with Postgres, Redis.
  * Create Fastify skeleton.
  * Implement Trivy integration (direct execution).
  * Define Zod schemas for the API.

### Phase 2: Orchestration (Week 2)

  * Implement BullMQ workers.
  * Solve "DooD" volume mapping.
  * Add Semgrep integration.
  * Build the Data Normalization Layer (Parsers).

### Phase 3: Dashboard (Week 3)

  * Next.js setup.
  * Project List & Create Project forms.
  * Scan Results view with Filtering.
  * Severity Charts (Chart.js or Recharts).

-----

## 7. Infrastructure (docker-compose.yml)

```yaml
version: '3.8'

services:
  ui:
    build: ./packages/ui
    ports:
      - "3000:3000"
    environment:
      - API_URL=http://api:4000
    depends_on:
      - api

  api:
    build: ./packages/api
    ports:
      - "4000:4000"
    environment:
      - DATABASE_URL=postgres://sentinel:sentinel@postgres:5432/sentinel
      - REDIS_URL=redis://redis:6379
      # Critical for mapping host paths to scanner containers
      - HOST_PROJECT_ROOT=${PWD}/projects 
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock  # Access host docker
      - ./projects:/app/projects                   # Access code
    depends_on:
      - postgres
      - redis

  postgres:
    image: postgres:18-alpine
    environment:
      POSTGRES_USER: sentinel
      POSTGRES_PASSWORD: sentinel
      POSTGRES_DB: sentinel
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
```

-----

## 8. Scanner Integration

### Clair (Container Vulnerability Scanning)
* **Type:** Container Image Scanner
* **Purpose:** Detects vulnerabilities in container images, leveraging vulnerability databases like NVD.
* **Integration Notes:**
    * Requires a running Clair instance or integration with a public Clair API. For local-first, running a private Clair instance is preferred.
    * Output is typically JSON, requiring a dedicated parser to map to the Unified Finding Interface.
    * Can be triggered on new image builds or periodically for images in a registry.

### Bandit (Python SAST)
* **Type:** Static Application Security Testing (SAST) for Python
* **Purpose:** Finds common security issues in Python code.
* **Integration Notes:**
    * Executed directly against the Python codebase.
    * Output can be configured to JSON, facilitating parsing into the Unified Finding Interface.
    * Focuses on issues like SQL injection, XSS, and dangerous function calls in Python applications.

-----

## 9. Risks & Mitigations

1.  **Large Output Parsing:**
      * *Risk:* A massive scan output crashes the Node.js memory.
      * *Mitigation:* Use streaming JSON parsers (`stream-json`) rather than `JSON.parse` for raw output.
2.  **Docker Rate Limits:**
      * *Risk:* Pulling `trivy:latest` repeatedly blocks IP.
      * *Mitigation:* Check for image existence before pulling; use local caches.
3.  **Zombie Containers:**
      * *Risk:* API crash leaves scanners running.
      * *Mitigation:* Use `--rm` flag on all scanner containers; add a startup script to the API to clean up labeled containers.

```
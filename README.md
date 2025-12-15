# Sentinel 🛡️

Sentinel is a **local-first** Application Security Orchestration (ASOC) platform. It unifies open-source security scanners into a single, private dashboard.

## Architecture

*   **Frontend**: Next.js 14 + Tailwind CSS (Port 3000)
*   **Backend**: Fastify + BullMQ (Port 4000)
*   **Database**: PostgreSQL 15
*   **Scanners**: Runs via **Docker-out-of-Docker**. The API spawns ephemeral containers on your host machine to scan code.

## Supported Scanners

The infrastructure automatically pulls the following images on startup:

| Tool | Type | Image |
| :--- | :--- | :--- |
| **Trivy** | SCA / Secret Scanning | `aquasec/trivy:latest` |
| **Semgrep** | SAST | `returntocorp/semgrep` |
| **Bandit** | Python Security Lints | `cytopia/bandit:latest` |
| **Clair** | Container Image Vulnerabilities | `ovotech/clair-scanner`, `quay.io/projectquay/clair:4.7.1` |
| **SonarQube** | Code Smells & Complexity | `sonarsource/sonar-scanner-cli`, `sonarqube:10.6.0-community` |

## Getting Started

1.  **Start the Stack**
    ```bash
    docker compose up --build
    ```
    *Note: The first run will take a moment to pull the security scanner images.*

2.  **Access Dashboard**
    Open [http://localhost:3000](http://localhost:3000)

3.  **Run a Scan**
    *   Create a project by providing the **Absolute Path** to a folder on your host machine (e.g., `/Users/me/code/my-app`).
    *   Click "Run Analysis".

## SonarQube Setup

The SonarQube service is exposed on [http://localhost:9000](http://localhost:9000). To enable Sonar scans:

1. Log in (default `admin`/`admin`).
2. Create a **User Token** and export it before starting the stack:
   ```bash
   export SONARQUBE_TOKEN=your_token_here
   docker compose up --build
   ```
   Alternatively, set `SONARQUBE_USERNAME` and `SONARQUBE_PASSWORD` environment variables if you prefer username/password auth.
3. Once the scanner runs, findings are fetched through the SonarQube REST API and normalized alongside the other tools.

## Troubleshooting

*   **FileSystem Access**: Ensure the directory you want to scan is accessible to the Docker daemon. 
*   **DooD Pattern**: The API container mounts `/var/run/docker.sock`. If you see permission errors, ensure your user has permissions to run docker commands.

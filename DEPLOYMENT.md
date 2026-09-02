# CodeSentinel — Production Deployment & Containerization Guide

This document provides complete, production-grade instructions for building, configuring, containerizing, and running CodeSentinel.

---

## 1. Architecture Overview

CodeSentinel is containerized as a lightweight, secure FastAPI ASGI microservice with static AST analysis, hybrid RAG knowledge ingestion, and LLM security analysis capabilities.

- **Backend Service**: FastAPI ASGI container running on port `8000`.
- **Runtime User**: Non-root system user (`codesentinel`, UID/GID 1000).
- **Health Check Probe**: Probes `GET /platform/health` every 30s.
- **Frontend Service**: Vite/React Stitch UI compiled via `npm run build`.

---

## 2. Environment Configuration

All runtime options are environment-driven. Secrets MUST ONLY be supplied via environment variables or secret store.

| Environment Variable | Default Value | Description |
| :--- | :--- | :--- |
| `APP_ENV` | `production` | Deployment environment mode (`development`, `staging`, `production`). |
| `DEBUG` | `False` | Application debug flag (**MUST BE `False` IN PRODUCTION**). |
| `BACKEND_HOST` | `0.0.0.0` | Container bind address. |
| `BACKEND_PORT` | `8000` | Container API listening port. |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | Comma-separated list of CORS allowed origins. |
| `MAX_REQUEST_SIZE_BYTES` | `10485760` | Request payload size limit in bytes (Default: 10MB). |
| `GROQ_API_KEY` | *(Secret)* | Primary LLM API key. |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Fallback LLM endpoint URL. |
| `GITHUB_TOKEN` | *(Secret)* | Optional GitHub Personal Access Token for PR integrations. |
| `WEBHOOK_SECRET` | *(Secret)* | Optional HMAC SHA-256 secret for GitHub webhook verification. |
| `CHROMA_DB_PATH` | `/app/data/chroma` | Persistent vector store directory path. |

---

## 3. Local Docker Build & Execution

### Build Docker Image
```bash
docker build -t codesentinel:latest .
```

### Run Container
```bash
docker run -d \
  --name codesentinel-backend \
  -p 8000:8000 \
  -e APP_ENV=production \
  -e DEBUG=False \
  -e ALLOWED_ORIGINS="http://localhost:3000" \
  -e GROQ_API_KEY="your_groq_api_key_placeholder" \
  codesentinel:latest
```

---

## 4. Docker Compose Deployment

To deploy using Docker Compose:

```bash
# Start backend service in detached mode
docker compose up -d

# Verify container status and health
docker compose ps

# View container logs
docker compose logs -f backend

# Stop containers
docker compose down
```

---

## 5. Health & Readiness Probes

CodeSentinel provides secret-safe health and readiness endpoints suitable for container orchestrators (Docker, Kubernetes, AWS ECS, GCP Cloud Run):

```bash
# Check platform health
curl -s http://localhost:8000/platform/health

# Check platform readiness
curl -s http://localhost:8000/platform/readiness

# Check platform info and capabilities
curl -s http://localhost:8000/platform/info
```

---

## 6. CLI Integration

The CodeSentinel CLI operates seamlessly against both local and containerized deployments:

```bash
# Check CLI version
python -m cli version

# Check platform health via CLI
python -m cli health

# Run a static security scan
python -m cli scan --target-dir . --policy default
```

---

## 7. Frontend Deployment

The Stitch React UI is built as a static production bundle:

```bash
cd frontend
npm install
npm run build
```

The resulting `frontend/dist/` bundle can be served via Nginx, AWS S3 / CloudFront, or any static HTTP web host.

---

## 8. Security Hardening Checklist

- [x] **Non-Root Runtime**: Container executes as unprivileged user `codesentinel` (UID 1000).
- [x] **Zero Hardcoded Secrets**: Secrets populated exclusively from environment variables.
- [x] **Production Debug Disabled**: `DEBUG=False` enforced in production.
- [x] **Request Size Limits**: Payload middleware blocks requests exceeding 10MB.
- [x] **Security Headers**: HSTS, X-Content-Type-Options, X-Frame-Options, and Content-Security-Policy headers active.
- [x] **Static Non-Execution Boundary**: Target repository code is NEVER executed.

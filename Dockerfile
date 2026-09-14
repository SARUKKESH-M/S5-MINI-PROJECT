# ==============================================================================
# CodeSentinel — Production Multi-Stage Dockerfile
# Autonomous Static Security Analysis & DevSecOps Platform
# ==============================================================================

FROM python:3.11-slim AS base

# 1. Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH="/app:/app/backend" \
    APP_ENV="production" \
    DEBUG="False" \
    BACKEND_HOST="0.0.0.0" \
    BACKEND_PORT="8000"

# 2. Create non-root system user & working directory
RUN groupadd -g 1000 codesentinel && \
    useradd -u 1000 -g codesentinel -m -s /bin/bash codesentinel && \
    mkdir -p /app/data /app/data/chroma /app/data/cache && \
    chown -R codesentinel:codesentinel /app

WORKDIR /app

# 3. Install system dependencies required for compilation/security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 4. Copy backend requirements & install Python dependencies as codesentinel user
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/backend/requirements.txt

# 5. Copy application source files
COPY --chown=codesentinel:codesentinel ast_engine /app/ast_engine
COPY --chown=codesentinel:codesentinel backend /app/backend
COPY --chown=codesentinel:codesentinel knowledge /app/knowledge
COPY --chown=codesentinel:codesentinel rag /app/rag
COPY --chown=codesentinel:codesentinel llm /app/llm
COPY --chown=codesentinel:codesentinel cli /app/cli

# 6. Set user permissions and switch to non-root user
USER codesentinel

# 7. Expose backend API port
EXPOSE 8000

# 8. Configure container health check probe targeting safe platform health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/platform/health')" || exit 1

# 9. Startup command using production uvicorn ASGI server
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]

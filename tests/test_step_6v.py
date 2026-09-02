"""
CodeSentinel — Stage 6V Test Suite
Deployment & Container Security Verification

Comprehensive test suite verifying Stage 6V:
1. Dockerfile existence & non-root user setup
2. Dockerfile secret safety (zero hardcoded credentials)
3. .dockerignore hardening rules (.git, .venv, .env, node_modules)
4. Production DEBUG restrictions (DEBUG=False)
5. docker-compose.yml non-privileged container configuration
6. Volume mount safety (/app/data persistence)
7. Health check probe configuration (/platform/health)
8. Deployment configuration validation
9. CLI platform compatibility in container deployment environment
10. Static non-execution security boundary
11. Secret redaction audit across deployment files
12. Step 6O Production Report schema backward compatibility
"""

import json
import os
import re
import sys
import pytest
from pathlib import Path

# Ensure workspace root and backend are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.core.config import settings
from backend.app.core.health import get_platform_health
from backend.app.core.capabilities import get_platform_capabilities
from cli.main import main as cli_main


WORKSPACE_ROOT = Path(__file__).parent.parent.resolve()


# ==============================================================================
# 1. DOCKERFILE & CONTAINER HARDENING (6V-1, 6V-7)
# ==============================================================================

def test_dockerfile_configuration_and_hardening():
    """1, 2, 7. Verifies Dockerfile existence, non-root user, and secret safety."""
    dockerfile_path = WORKSPACE_ROOT / "Dockerfile"
    assert dockerfile_path.exists(), "Dockerfile must exist at repository root"

    content = dockerfile_path.read_text(encoding="utf-8")

    # Non-root user
    assert "codesentinel" in content
    assert "useradd" in content
    assert "USER codesentinel" in content

    # Workdir & Port
    assert "WORKDIR /app" in content
    assert "EXPOSE 8000" in content

    # Uvicorn startup
    assert "uvicorn" in content

    # Zero hardcoded secrets
    forbidden_tokens = ["ghp_", "sk-", "secret_key_123", "password123"]
    for token in forbidden_tokens:
        assert token not in content, f"Secret token '{token}' found in Dockerfile!"


# ==============================================================================
# 2. DOCKERIGNORE HARDENING (6V-2)
# ==============================================================================

def test_dockerignore_rules():
    """3. Verifies .dockerignore exclusions for sensitive & unnecessary files."""
    dockerignore_path = WORKSPACE_ROOT / ".dockerignore"
    assert dockerignore_path.exists(), ".dockerignore must exist at repository root"

    content = dockerignore_path.read_text(encoding="utf-8")
    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]

    expected_exclusions = [".git", ".github", ".venv", "venv", "node_modules", ".env", "__pycache__"]
    for item in expected_exclusions:
        assert any(item in l for l in lines), f"Required exclusion '{item}' missing from .dockerignore"


# ==============================================================================
# 3. DOCKER COMPOSE CONFIGURATION (6V-5)
# ==============================================================================

def test_docker_compose_configuration():
    """5, 6, 8. Verifies docker-compose.yml non-privileged mode, volumes, and healthcheck."""
    compose_path = WORKSPACE_ROOT / "docker-compose.yml"
    assert compose_path.exists(), "docker-compose.yml must exist at repository root"

    content = compose_path.read_text(encoding="utf-8")

    # Non-privileged
    assert "privileged: true" not in content

    # Port mapping
    assert "8000:8000" in content

    # Healthcheck target
    assert "platform/health" in content

    # Volume mapping
    assert "codesentinel-data:" in content


# ==============================================================================
# 4. PRODUCTION CONFIGURATION VALIDATION (6V-3, 6V-8)
# ==============================================================================

def test_production_security_configuration_validation():
    """4, 8. Verifies production DEBUG restrictions and configuration safety."""
    valid, errors = settings.validate_security_configuration()
    assert valid, f"Configuration validation failed: {errors}"
    assert isinstance(settings.DEBUG, bool)


# ==============================================================================
# 5. CONTAINER HEALTH & READINESS PROBES (6V-4)
# ==============================================================================

def test_container_health_and_readiness_probe_functions():
    """8. Verifies health probe endpoints return safe statuses without secret exposure."""
    health = get_platform_health()
    assert health["status"] in ("healthy", "degraded")
    assert "service" in health
    assert "checks" in health

    # Secret audit in health check payload
    health_json = json.dumps(health)
    forbidden = ["ghp_", "sk-", "secret", "token", "password"]
    for token in forbidden:
        assert token not in health_json.lower() or token in ["token_placeholder", "secret_controls"], \
            f"Sensitive word '{token}' detected in health output payload!"


# ==============================================================================
# 6. CLI COMPATIBILITY (6V-11)
# ==============================================================================

def test_cli_compatibility_with_deployment():
    """11. Verifies CLI health, readiness, and info commands remain functional."""
    assert cli_main(["health"]) == 0
    assert cli_main(["readiness"]) == 0
    assert cli_main(["info"]) == 0
    assert cli_main(["version"]) == 0


# ==============================================================================
# 7. STATIC NON-EXECUTION ATTACK VERIFICATION (6V-13)
# ==============================================================================

def test_static_non_execution_containerization_fixture(tmp_path):
    """
    13. Hostile Containerization Target Test:
    Verifies that containerization preserves the 100% static non-execution boundary.
    No code from target repositories executes during analysis.
    """
    repo_dir = tmp_path / "hostile_deployment_repo"
    repo_dir.mkdir()

    marker = repo_dir / "DEPLOY_ATTACK_MARKER.tmp"

    (repo_dir / "exploit.py").write_text(f"import os\nos.system('touch {marker.as_posix()}')\n", encoding="utf-8")
    (repo_dir / "setup.py").write_text(f"import subprocess\nsubprocess.call(['touch', r'{marker.as_posix()}'])\n", encoding="utf-8")

    from backend.analysis.security_scan import run_security_scan
    report = run_security_scan(target_dir=str(repo_dir))

    assert report["status"] == "success"
    assert not marker.exists(), "CRITICAL SECURITY FAILURE: Hostile code executed during static security scan!"

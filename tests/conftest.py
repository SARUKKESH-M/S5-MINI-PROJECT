"""
Pytest configuration and global fixtures for CodeSentinel.
Ensures test isolation for persistent storage tables such as webhook_deliveries.
"""

import pytest

import sys
import os

root_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
backend_path = os.path.join(root_path, "backend")
if root_path not in sys.path:
    sys.path.insert(0, root_path)
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

try:
    from backend.analysis.storage.store import AnalysisStore
except ImportError:
    try:
        from analysis.storage.store import AnalysisStore
    except ImportError:
        AnalysisStore = None



@pytest.fixture(autouse=True)
def clean_webhook_deliveries():
    """Ensure each test starts with a clean webhook delivery and PR isolation table."""
    def _do_clean():
        if AnalysisStore is not None:
            try:
                store = AnalysisStore()
                with store._get_connection() as conn:
                    conn.execute("DELETE FROM webhook_deliveries;")
                    conn.execute("DELETE FROM pr_commit_reservations;")
                    conn.execute("DELETE FROM findings;")
                    conn.execute("DELETE FROM analyses;")
                    conn.commit()
            except Exception:
                pass

    _do_clean()
    yield
    _do_clean()


@pytest.fixture(autouse=True)
def configure_auth_for_test(request, monkeypatch):
    """Ensure legacy pre-auth tests run with AUTH_ENFORCED=False while auth suites run with AUTH_ENFORCED=True."""
    try:
        from backend.app.core.config import settings
    except ImportError:
        try:
            from app.core.config import settings
        except ImportError:
            return

    filename = os.path.basename(str(request.fspath))
    if not any(k in filename for k in ("auth", "phase_a", "storage_user", "session")):
        monkeypatch.setattr(settings, "AUTH_ENFORCED", False)
    else:
        monkeypatch.setattr(settings, "AUTH_ENFORCED", True)



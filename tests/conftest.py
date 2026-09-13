"""
Pytest configuration and global fixtures for CodeSentinel.
Ensures test isolation for persistent storage tables such as webhook_deliveries.
"""

import pytest

import sys
import os

backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
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
    """Ensure each test starts with a clean webhook delivery table."""
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


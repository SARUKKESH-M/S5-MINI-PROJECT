"""
CodeSentinel — CLI Security Scan Command

CLI interface for triggering CodeSentinel automated static security scans.
"""

import os
import sys

# Ensure workspace root and backend are in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.analysis.security_scan import main, run_security_scan

if __name__ == "__main__":
    sys.exit(main())

"""
CodeSentinel — CLI Module Main Entry Point

Executes unified CLI via `python -m cli`.
"""

import sys
from cli.main import main

if __name__ == "__main__":
    sys.exit(main())

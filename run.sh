#!/bin/bash
# `run.sh` single entry point for the logic flsaw scanner.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate venv if it exists, otherwise assume packages are installed globally.
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
else
    echo "[!] No venv found at venv/bin/activate — using system Python."
    echo "    If packages are missing, run: python3 -m venv venv && source venv/bin/activate && pip install -r requirements.txt"
fi

python launch.py "$@"
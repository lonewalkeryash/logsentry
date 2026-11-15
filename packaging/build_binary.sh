#!/usr/bin/env bash
# Build a single-file LogSentry executable (Python and PyYAML bundled in).
#   pip install . pyinstaller && bash packaging/build_binary.sh
set -euo pipefail
pyinstaller --onefile --clean --noconfirm --name logsentry \
    --collect-data logsentry packaging/logsentry_entry.py
echo "built: dist/logsentry$( [ "${OS:-}" = "Windows_NT" ] && echo .exe )"

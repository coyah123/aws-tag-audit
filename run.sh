#!/usr/bin/env bash
# AWS Tag Audit launcher for macOS / Linux.
#   ./run.sh              -> opens the GUI
#   ./run.sh scan ...     -> runs the CLI with those arguments (see README)
# First run creates a private Python environment in .venv and installs boto3.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="$HERE/.venv"
export PYTHONIOENCODING=utf-8

venv_python() {
  if [ -x "$VENV/bin/python" ]; then echo "$VENV/bin/python"
  elif [ -x "$VENV/Scripts/python.exe" ]; then echo "$VENV/Scripts/python.exe"   # Git Bash on Windows
  fi
}

PY="$(venv_python)"
if [ -z "$PY" ]; then
  BASEPY=""
  for c in python3 python; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then
      BASEPY="$c"; break
    fi
  done
  if [ -z "$BASEPY" ]; then
    echo "Python 3.8 or newer was not found."
    echo "  macOS: install from https://www.python.org/downloads/ (includes Tkinter for the GUI)"
    echo "         or: brew install python python-tk"
    echo "  Linux: sudo apt install python3 python3-venv python3-tk   (or your distro's equivalent)"
    exit 1
  fi
  echo "Creating Python environment in .venv ..."
  # --system-site-packages: reuse boto3 if it is already installed (helps on offline machines)
  "$BASEPY" -m venv --system-site-packages "$VENV"
  PY="$(venv_python)"
fi

if ! "$PY" -c 'import boto3' >/dev/null 2>&1; then
  echo "Installing boto3 ..."
  if ! "$PY" -m pip install --disable-pip-version-check -q -r "$HERE/requirements.txt"; then
    echo "pip could not install boto3. If this machine is offline, see 'Offline install' in README.md."
    exit 1
  fi
  # Optional: lets boto3 read profiles created with `aws login`. Not fatal if it fails.
  "$PY" -m pip install --disable-pip-version-check -q "botocore[crt]" >/dev/null 2>&1 || true
fi

if [ "$#" -gt 0 ]; then
  exec "$PY" "$HERE/aws_tag_audit.py" "$@"
fi

if ! "$PY" -c 'import tkinter' >/dev/null 2>&1; then
  echo "This Python has no Tkinter, which the GUI needs."
  echo "  macOS (Homebrew python): brew install python-tk"
  echo "  macOS (other):           install Python from https://www.python.org/downloads/"
  echo "  Linux:                   sudo apt install python3-tk"
  echo "The CLI still works without it, e.g.:  ./run.sh scan --profile myprofile"
  exit 1
fi
exec "$PY" "$HERE/aws_tag_audit_gui.py"

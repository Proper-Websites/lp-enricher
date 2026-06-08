#!/bin/bash
# LP Lead Enricher — Double-click to start
# This file starts the local server and opens your browser automatically.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "========================================"
echo "  LP Lead Enricher"
echo "========================================"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "ERROR: Python3 not found."
  echo "Download it from https://python.org"
  read -p "Press Enter to close..."
  exit 1
fi

# Check playwright
if ! python3 -c "import playwright" 2>/dev/null; then
  echo "Installing required tools (one time only)..."
  echo ""
  pip3 install playwright anthropic
  playwright install chromium
  echo ""
  echo "Setup complete!"
  echo ""
fi

echo "Starting server..."
echo "Browser will open automatically."
echo ""
echo "Press Ctrl+C to stop."
echo ""

cd "$SCRIPT_DIR"
python3 enricher_server.py

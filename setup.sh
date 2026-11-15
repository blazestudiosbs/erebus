#!/bin/zsh
# Erebus native setup for macOS. Run from the repo root:  zsh setup.sh
set -e
cd "$(dirname "$0")"

echo "==> Python: $(python3 --version)"
echo "==> Creating virtualenv (.venv)"
python3 -m venv .venv
source .venv/bin/activate

echo "==> Upgrading pip"
python -m pip install --upgrade pip -q

echo "==> Installing Erebus (editable, with dev extras)"
pip install -e ".[dev]" -q

echo ""
echo "==> Smoke test: intel correlate against the prebuilt database"
if [ -f ./intel.sqlite ]; then
  erebus intel --db ./intel.sqlite correlate "Apache" 2.4.49 | head -6
else
  echo "   (no intel.sqlite found — run:  erebus intel update )"
fi

echo ""
echo "============================================================"
echo " Erebus is installed. To use it in a new terminal, run:"
echo "   cd \"$(pwd)\""
echo "   source .venv/bin/activate"
echo "   ereconsole                               # the console"
echo "   erebus intel --db ./intel.sqlite correlate \"Fortinet\""
echo "============================================================"

#!/usr/bin/env bash
#
# Erebus VM provisioner
# ---------------------
# Sets up a working Erebus install in a fresh VM: a Python venv with every
# runtime dependency, plus the external tools the modules shell out to
# (nmap, nuclei, searchsploit/Exploit-DB, AFL++). Idempotent - re-running
# skips anything already present.
#
# Target:  Debian / Ubuntu / Kali (apt). macOS (brew) is handled too.
# Usage:   clone the repo, then from its root:  ./scripts/provision.sh
# Opt out of a tool:  EREBUS_SKIP="nuclei afl" ./scripts/provision.sh
#
set -euo pipefail

log()  { printf '\033[36m[erebus]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[erebus] warn:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[erebus] error:\033[0m %s\n' "$*" >&2; exit 1; }

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VENV="${EREBUS_VENV:-$REPO_ROOT/.venv}"
SKIP=" ${EREBUS_SKIP:-} "
skip() { [[ "$SKIP" == *" $1 "* ]]; }

[ -f "$REPO_ROOT/pyproject.toml" ] || die "run this from the Erebus repo (no pyproject.toml at $REPO_ROOT)"

# ---- privilege + package manager ------------------------------------------
SUDO=""
if [ "$(id -u)" -ne 0 ]; then command -v sudo >/dev/null 2>&1 && SUDO=sudo || warn "not root and no sudo; system packages may fail"; fi

PM=""
if   command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf     >/dev/null 2>&1; then PM=dnf
elif command -v brew    >/dev/null 2>&1; then PM=brew
else warn "no apt/dnf/brew found; install system packages yourself (see README)"; fi

pm_install() {  # pm_install <display> <pkg...>
  local name="$1"; shift
  case "$PM" in
    apt)  $SUDO apt-get install -y "$@" >/dev/null 2>&1 ;;
    dnf)  $SUDO dnf install -y "$@"     >/dev/null 2>&1 ;;
    brew) brew install "$@"             >/dev/null 2>&1 ;;
    *)    return 1 ;;
  esac && log "installed $name" || { warn "could not install $name via $PM (install it yourself)"; return 1; }
}

# ---- 1. base system packages ----------------------------------------------
if [ "$PM" = apt ]; then log "apt-get update"; $SUDO apt-get update -qq || warn "apt update failed"; fi
log "base packages (python, git, build tools, curl, unzip, nmap)"
case "$PM" in
  apt)  pm_install "base" python3 python3-venv python3-pip git build-essential curl unzip nmap || true ;;
  dnf)  pm_install "base" python3 python3-pip git gcc make curl unzip nmap || true ;;
  brew) pm_install "base" python git curl nmap || true ;;
esac

# ---- 2. Python venv + every runtime dependency ----------------------------
if [ ! -d "$VENV" ]; then log "creating venv at $VENV"; python3 -m venv "$VENV"; fi
"$VENV/bin/python" -m pip install --upgrade pip >/dev/null 2>&1 || warn "pip upgrade failed"
log "installing Erebus + all runtime extras (editable)"
( cd "$REPO_ROOT" && "$VENV/bin/python" -m pip install -e ".[all]" ) || die "pip install of Erebus failed"
log "Erebus installed: $("$VENV/bin/erebus" --version 2>/dev/null || echo erebus)"

# ---- 3. external tools the modules call -----------------------------------

install_searchsploit() {
  skip searchsploit && { log "skip searchsploit"; return; }
  command -v searchsploit >/dev/null 2>&1 && { log "searchsploit present"; return; }
  pm_install "exploitdb (searchsploit)" exploitdb && command -v searchsploit >/dev/null 2>&1 && return
  warn "exploitdb package unavailable; cloning Exploit-DB to /opt/exploitdb"
  if [ ! -d /opt/exploitdb ]; then
    $SUDO git clone --depth 1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb >/dev/null 2>&1 || { warn "Exploit-DB clone failed"; return; }
  fi
  [ -x /opt/exploitdb/searchsploit ] && $SUDO ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit && log "searchsploit linked from /opt/exploitdb"
}

install_afl() {
  skip afl && { log "skip afl"; return; }
  command -v afl-fuzz >/dev/null 2>&1 && { log "afl-fuzz present"; return; }
  case "$PM" in
    apt)  pm_install "AFL++" afl++ || pm_install "AFL++" aflplusplus || warn "AFL++ not in this repo (fuzz bench stays disabled)";;
    dnf)  pm_install "AFL++" american-fuzzy-lop++ || warn "AFL++ unavailable";;
    brew) pm_install "AFL++" afl++ || warn "AFL++ unavailable via brew";;
    *)    warn "install AFL++ yourself for the fuzz bench";;
  esac
}

install_nuclei() {
  skip nuclei && { log "skip nuclei"; return; }
  command -v nuclei >/dev/null 2>&1 && { log "nuclei present: $(command -v nuclei)"; nuclei_templates; return; }
  if [ "$PM" = brew ]; then pm_install "nuclei" nuclei && { nuclei_templates; return; }; fi
  if command -v go >/dev/null 2>&1; then
    log "installing nuclei via go install"
    if GOBIN=/usr/local/bin $SUDO env "PATH=$PATH" "$(command -v go)" install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest >/dev/null 2>&1 \
       && command -v nuclei >/dev/null 2>&1; then nuclei_templates; return; fi
    warn "go install nuclei failed; trying the release binary"
  fi
  # release binary (no Go needed)
  local arch os ver tag tmp url
  case "$(uname -m)" in x86_64|amd64) arch=amd64;; aarch64|arm64) arch=arm64;; *) warn "unknown arch $(uname -m); install nuclei manually"; return;; esac
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  tag="$(curl -fsSL https://api.github.com/repos/projectdiscovery/nuclei/releases/latest 2>/dev/null | grep -oE '"tag_name"[[:space:]]*:[[:space:]]*"v[^"]+"' | grep -oE 'v[0-9.]+' | head -1 || true)"
  [ -n "$tag" ] || { warn "could not resolve latest nuclei version; install manually"; return; }
  ver="${tag#v}"
  url="https://github.com/projectdiscovery/nuclei/releases/download/${tag}/nuclei_${ver}_${os}_${arch}.zip"
  tmp="$(mktemp -d)"
  if curl -fsSL "$url" -o "$tmp/nuclei.zip" && unzip -o -q "$tmp/nuclei.zip" -d "$tmp" && [ -f "$tmp/nuclei" ]; then
    $SUDO install -m 0755 "$tmp/nuclei" /usr/local/bin/nuclei && log "nuclei $tag installed to /usr/local/bin"
    nuclei_templates
  else
    warn "nuclei download failed ($url); install it manually"
  fi
  rm -rf "$tmp"
}

nuclei_templates() {
  command -v nuclei >/dev/null 2>&1 || return
  log "fetching nuclei templates (first run)"
  nuclei -update-templates >/dev/null 2>&1 || warn "nuclei template fetch failed; run 'nuclei -update-templates' yourself"
}

install_searchsploit
install_afl
install_nuclei

# ---- 4. summary -----------------------------------------------------------
echo
log "tool check:"
for t in nmap nuclei searchsploit afl-fuzz; do
  if command -v "$t" >/dev/null 2>&1; then printf '  \033[32m ok \033[0m %-12s %s\n' "$t" "$(command -v "$t")"
  else printf '  \033[33mmiss\033[0m %-12s (optional; install later)\n' "$t"; fi
done
echo
log "done. next steps:"
cat <<EOF
  source $VENV/bin/activate
  erebus vault set shodan          # optional: paste a Shodan API key
  erebus console --serve --scope scopes/caporia.co.scope
Then open the printed http://127.0.0.1:8777 URL.
EOF

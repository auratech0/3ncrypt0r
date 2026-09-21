#!/bin/sh
# 3ncrypt0r installer
#
#   curl -fsSL https://raw.githubusercontent.com/auratech0/3ncrypt0r/main/install.sh | sh
#
# Environment:
#   PREFIX        install root (default: /usr/local as root, ~/.local otherwise)
#   N3_BRANCH     branch to pull from (default: main)
#   N3_SHA256     expected SHA-256 of 3ncrypt0r.py; verified when set
#   N3_SKIP_DEPS  set to 1 to skip pre-warming Python dependencies
#
# Flags: --uninstall
 
set -eu
 
REPO="auratech0/3ncrypt0r"
NAME="3ncrypt0r"
SCRIPT="3ncrypt0r.py"
BRANCH="${N3_BRANCH:-main}"
URL="https://raw.githubusercontent.com/${REPO}/${BRANCH}/${SCRIPT}"
MIN_PY="3.9"
 
TMPDIR_=""
cleanup() { [ -n "$TMPDIR_" ] && rm -rf "$TMPDIR_"; }
trap cleanup EXIT INT TERM
 
say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
err()  { printf 'error: %s\n' "$*" >&2; exit 1; }
 
if [ "${PREFIX:-}" ]; then
    :
elif [ "$(id -u)" = "0" ]; then
    PREFIX=/usr/local
else
    PREFIX="$HOME/.local"
fi
BINDIR="$PREFIX/bin"
DEST="$BINDIR/$NAME"
 
case "${1:-}" in
    --uninstall)
        removed=0
        if [ -e "$DEST" ]; then
            rm -f "$DEST"
            say "Removed $DEST"
            removed=1
        fi
        runtime="${XDG_DATA_HOME:-$HOME/.local/share}/$NAME/runtime"
        if [ -d "$runtime" ]; then
            rm -rf "$runtime"
            say "Removed $runtime"
            removed=1
        fi
        [ "$removed" = "0" ] && say "Nothing to remove at $DEST"
        vault="${XDG_DATA_HOME:-$HOME/.local/share}/$NAME"
        if [ -e "$vault/master.key" ]; then
            say ""
            say "Your master key and registry were NOT deleted:"
            say "  $vault"
            say "Without them your .enc files are unreadable. To destroy them"
            say "deliberately, run '$NAME kill-all' before uninstalling."
        fi
        exit 0
        ;;
    "") ;;
    *) err "unknown option: $1" ;;
esac
 
PY=""
for candidate in python3 python; do
    command -v "$candidate" >/dev/null 2>&1 || continue
    if "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>/dev/null; then
        PY="$(command -v "$candidate")"
        break
    fi
done
[ -n "$PY" ] || err "Python $MIN_PY or newer is required but was not found on PATH."
 
if command -v curl >/dev/null 2>&1; then
    fetch() { curl -fsSL --proto '=https' --tlsv1.2 "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
    fetch() { wget -q --https-only -O "$2" "$1"; }
else
    err "curl or wget is required."
fi
 
TMPDIR_="$(mktemp -d)"
raw="$TMPDIR_/$SCRIPT"
 
say "Downloading $SCRIPT from $BRANCH..."
fetch "$URL" "$raw" || err "download failed: $URL"
[ -s "$raw" ] || err "downloaded file is empty."
head -n 1 "$raw" | grep -q 'python' || err "downloaded file is not a Python script."
grep -q '^MAGIC = b"3NCRYPT0"' "$raw" || err "downloaded file does not look like $NAME."
 
if [ -n "${N3_SHA256:-}" ]; then
    if command -v sha256sum >/dev/null 2>&1; then
        actual="$(sha256sum "$raw" | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
        actual="$(shasum -a 256 "$raw" | cut -d' ' -f1)"
    else
        err "N3_SHA256 was set but no sha256sum or shasum is available."
    fi
    [ "$actual" = "$N3_SHA256" ] || err "checksum mismatch: expected $N3_SHA256, got $actual"
    say "Checksum verified."
else
    warn "No N3_SHA256 set, so the download was not verified against a known hash."
fi
 
mkdir -p "$BINDIR" || err "cannot create $BINDIR"
staged="$TMPDIR_/staged"
printf '#!%s\n' "$PY" > "$staged"
tail -n +2 "$raw" >> "$staged"
chmod 755 "$staged"
mv -f "$staged" "$DEST" 2>/dev/null || {
    cp "$staged" "$DEST" && chmod 755 "$DEST"
} || err "cannot write $DEST"
 
say "Installed $NAME to $DEST"
 
if [ "${N3_SKIP_DEPS:-}" != "1" ]; then
    say "Preparing Python dependencies..."
    "$DEST" --version >/dev/null 2>&1 || warn "Dependency setup did not finish. It will retry on first use."
fi
 
case ":$PATH:" in
    *":$BINDIR:"*) ;;
    *)
        warn ""
        warn "$BINDIR is not on your PATH. Add it:"
        warn "  echo 'export PATH=\"$BINDIR:\$PATH\"' >> ~/.profile"
        warn "Then open a new shell, or run: export PATH=\"$BINDIR:\$PATH\""
        ;;
esac
 
say ""
say "Get started:"
say "  $NAME init"
say "  $NAME encrypt secret.txt"
say "  $NAME --help"
 

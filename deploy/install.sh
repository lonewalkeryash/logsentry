#!/usr/bin/env bash
# Install LogSentry as a systemd service on a Linux server.
#
#   git clone https://github.com/lonewalkeryash/logsentry.git
#   cd logsentry && sudo ./deploy/install.sh
#
#   sudo ./deploy/install.sh --uninstall
set -euo pipefail

PREFIX=/opt/logsentry
CONF_DIR=/etc/logsentry
UNIT=/etc/systemd/system/logsentry.service
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo $0" >&2; exit 1; }

if [ "${1:-}" = "--uninstall" ]; then
    systemctl disable --now logsentry 2>/dev/null || true
    rm -f "$UNIT"
    systemctl daemon-reload
    for ipt in iptables ip6tables; do   # remove LogSentry's firewall chain
        if command -v "$ipt" >/dev/null && "$ipt" -n -L LOGSENTRY >/dev/null 2>&1; then
            "$ipt" -D INPUT -j LOGSENTRY 2>/dev/null || true
            "$ipt" -F LOGSENTRY && "$ipt" -X LOGSENTRY
        fi
    done
    rm -rf "$PREFIX" /var/lib/logsentry
    echo "LogSentry removed (config kept in $CONF_DIR)."
    exit 0
fi

command -v python3 >/dev/null || { echo "python3 is required" >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' \
    || { echo "Python 3.10 or newer is required" >&2; exit 1; }
if ! python3 -m venv --help >/dev/null 2>&1 || ! python3 -c 'import ensurepip' 2>/dev/null; then
    if command -v apt-get >/dev/null; then
        apt-get update -qq && apt-get install -y -qq python3-venv
    else
        echo "install the Python venv module for your distro first" >&2; exit 1
    fi
fi
command -v iptables >/dev/null || echo "warning: iptables not found; detection works, blocking will not" >&2

echo "[1/4] creating virtualenv in $PREFIX"
python3 -m venv "$PREFIX"
"$PREFIX/bin/pip" install --quiet --upgrade pip
echo "[2/4] installing LogSentry and its dependencies"
"$PREFIX/bin/pip" install --quiet "$REPO"

echo "[3/4] installing config and service"
install -d -m 755 "$CONF_DIR"
if [ ! -f "$CONF_DIR/logsentry.env" ]; then
    install -m 644 "$REPO/deploy/logsentry.env" "$CONF_DIR/logsentry.env"
else
    echo "      keeping existing $CONF_DIR/logsentry.env"
fi
install -m 644 "$REPO/deploy/logsentry.service" "$UNIT"
ln -sf "$PREFIX/bin/logsentry" /usr/local/bin/logsentry

echo "[4/4] starting service"
systemctl daemon-reload
systemctl enable --now logsentry
systemctl restart logsentry

cat <<MSG

LogSentry is running in PREVIEW mode (it logs what it would block).
  live alerts:   journalctl -u logsentry -f
  settings:      $CONF_DIR/logsentry.env   (add --apply to enforce blocks)
  active blocks: sudo logsentry blocks --state /var/lib/logsentry/blocks.json
MSG

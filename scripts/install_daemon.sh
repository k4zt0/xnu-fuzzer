#!/bin/bash
# install_daemon.sh — install xfuzz as a reboot-surviving root LaunchDaemon.
#
# The daemon runs as root (unlocking most Apple driver IOKit user clients),
# keeps its corpus/state under /var/root/xfuzz (survives reboots, unlike /tmp),
# and RunAtLoad + KeepAlive auto-resume it after a kernel panic reboots the box.
#
# Usage:  sudo scripts/install_daemon.sh [--surfaces LIST] [--procs N] [--unsafe]
set -euo pipefail

LABEL="com.xfuzz.fuzzer"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"
INSTALL_DIR="/usr/local/libexec/xfuzz"
WORKDIR="/var/root/xfuzz"

if [[ $EUID -ne 0 ]]; then
  echo "must run as root: sudo $0 $*" >&2
  exit 1
fi

SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"
SURFACES="bsd,mach"
PROCS="4"
EXTRA=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --surfaces) SURFACES="$2"; shift 2;;
    --procs)    PROCS="$2"; shift 2;;
    --unsafe)   EXTRA+=("--unsafe"); shift;;
    *)          EXTRA+=("$1"); shift;;
  esac
done

echo "[*] building xfuzz"
( cd "$SRC_DIR" && make >/dev/null )

echo "[*] installing binary to ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR" "$WORKDIR"
install -m 0755 "$SRC_DIR/xfuzz" "$INSTALL_DIR/xfuzz"
chown -R root:wheel "$INSTALL_DIR" "$WORKDIR"

echo "[*] writing ${PLIST}"
cat > "$PLIST" <<PLIST_EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key><string>${LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>${INSTALL_DIR}/xfuzz</string>
        <string>--workdir</string><string>${WORKDIR}</string>
        <string>--surfaces</string><string>${SURFACES}</string>
        <string>--procs</string><string>${PROCS}</string>
$(for e in "${EXTRA[@]:-}"; do [[ -n "$e" ]] && echo "        <string>$e</string>"; done)
    </array>
    <key>RunAtLoad</key><true/>
    <key>KeepAlive</key><true/>
    <key>ProcessType</key><string>Background</string>
    <key>StandardOutPath</key><string>${WORKDIR}/daemon.out</string>
    <key>StandardErrorPath</key><string>${WORKDIR}/daemon.err</string>
</dict>
</plist>
PLIST_EOF

chown root:wheel "$PLIST"
chmod 0644 "$PLIST"

echo "[*] bootstrapping"
launchctl bootout system/"$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST"
launchctl enable system/"$LABEL" 2>/dev/null || true

echo "[+] installed. state in ${WORKDIR}"
echo "    status: sudo launchctl print system/${LABEL}"
echo "    stop:   sudo launchctl bootout system/${LABEL}"
echo "    logs:   tail -f ${WORKDIR}/xfuzz.log"

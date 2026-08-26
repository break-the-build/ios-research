#!/bin/zsh
# smb-rig driver: one mount cycle against the rig, with timeout + provenance.
# Usage: ./runner.sh [rounds]
# Requires: rig in fuzz mode (smb_rig.py fuzz), smbd credentials configured
# (see README), and this script run as the user who owns /tmp/smbmnt.
set -u
ROUNDS=${1:-20}
MNT=/tmp/smbmnt
LOG=/tmp/smb-rig-driver.log
URL="//research:researchpw@127.0.0.1:4450/fuzzshare"

mkdir -p "$MNT"
echo "[$(date -u +%FT%TZ)] driver start, rounds=$ROUNDS" | tee -a "$LOG"

for i in $(seq 1 $ROUNDS); do
  echo "[$(date -u +%FT%TZ)] round $i: mount" | tee -a "$LOG"
  # 25 s ceiling per phase — a wedged mount is a finding too (record which case file was last)
  case_before=$(ls -t cases/*.rsp 2>/dev/null | head -1)
  ( mount_smbfs "$URL" "$MNT" ) & mp=$!
  ( sleep 25; kill $mp 2>/dev/null ) & kt=$!
  wait $mp 2>/dev/null
  kill $kt 2>/dev/null

  if mount | grep -q " $MNT "; then
    echo "[$(date -u +%FT%TZ)] round $i: mounted — exercising" | tee -a "$LOG"
    ls "$MNT" >/dev/null 2>&1
    touch "$MNT/probe-$i" 2>/dev/null
    diskutil unmount force "$MNT" >/dev/null 2>&1
  else
    echo "[$(date -u +%FT%TZ)] round $i: MOUNT FAILED/TIMEOUT (last-case=$case_before)" | tee -a "$LOG"
    mount_smbfs "$URL" "$MNT" </dev/null >/dev/null 2>&1   # retry once for state cleanup
    diskutil unmount force "$MNT" >/dev/null 2>&1
  fi
done
echo "[$(date -u +%FT%TZ)] driver done" | tee -a "$LOG"

# Post-run check: kernel panics from this session land here and survive reboot
echo "Recent kernel panic reports:" >>"$LOG"
ls -t /Library/Logs/DiagnosticReports/Kernel-*.panic 2>/dev/null | head -5 >>"$LOG" || true

#!/bin/zsh
# smb-rig driver: mount cycles against the rig, a bounded file-op workload,
# and panic correlation. Usage: ./runner.sh [rounds]
# Requires: rig in fuzz mode (smb_rig.py fuzz), smbd credentials configured
# (see README), and this script run as the user who owns $MNT.
#
# Nothing here ever wait()s on a process that touches the mount: a kernel
# thread wedged in smbfs is uninterruptible (kill -9 does not reap it), so
# every step is started detached and only polled, with a deadline.
set -u
cd "${0:A:h}"

ROUNDS=${1:-20}
MNT=${SMB_RIG_MNT:-/tmp/smbmnt}
LOG=${SMB_RIG_LOG:-/tmp/smb-rig-driver.log}
# Must be the identity the seeds were recorded with (`smb_rig.py corpus`
# prints it). Seeds recorded against Samba's map-to-guest are GUEST sessions;
# mounting as a named user then fails with "Authentication error".
URL=${SMB_RIG_URL:-"//GUEST:@127.0.0.1:4450/fuzzshare"}
MOUNT_WAIT=25      # s for the mount to appear
OP_WAIT=5          # s per workload command
UNMOUNT_WAIT=10    # s for the forced unmount
MAX_WEDGED=3       # stuck mount_smbfs processes before we stop: kernel is wedged

mkdir -p "$MNT"
MNT=${MNT:A}       # /tmp -> /private/tmp: `mount` prints the resolved path

ts()  { date -u +%FT%TZ }
log() { echo "[$(ts)] $*" | tee -a "$LOG" }

# newest rig case: "case<TAB>utc<TAB>conn" from the newest run's INDEX.tsv
last_case() {
  local runs=(cases/run-*(N/om)) run
  run=${runs[1]:-}
  if [[ -n $run && -f $run/INDEX.tsv ]] && (( $(wc -l < "$run/INDEX.tsv") > 1 )); then
    echo "${run:t}/$(tail -1 "$run/INDEX.tsv" | cut -f1-3 | tr '\t' ' ')"
  else
    echo none
  fi
}

is_mounted() { mount | grep -qF " on $MNT (" }

# bounded SECS CMD...: run detached, poll until exit or deadline; on timeout
# SIGKILL (best effort) and return 1 without waiting for the process to die.
bounded() {
  local secs=$1; shift
  "$@" </dev/null >/dev/null 2>&1 &!
  local pid=$! n=0
  while kill -0 $pid 2>/dev/null; do
    if (( n >= secs * 4 )); then
      kill -9 $pid 2>/dev/null
      log "  TIMEOUT ${secs}s: $* (last-case=$(last_case))"
      return 1
    fi
    sleep 0.25; (( n++ ))
  done
  return 0
}

wait_mounted() {
  local n=0
  while (( n < MOUNT_WAIT * 2 )); do
    is_mounted && return 0
    sleep 0.5; (( n++ ))
  done
  return 1
}

# Client workload: each op drives a different smbfs response parser.
exercise() {
  local m=$MNT i=$1
  bounded $OP_WAIT ls -lae@O "$m"                     # QUERY_DIR + ACL/xattr/flags lookups
  bounded $OP_WAIT stat -x "$m/hello.txt"             # QUERY_INFO file classes
  bounded $OP_WAIT cat "$m/hello.txt"                 # CREATE + READ
  bounded $OP_WAIT xattr -l "$m/hello.txt"            # named streams (FileStreamInformation)
  bounded $OP_WAIT xattr -w com.research.probe "v$i" "$m/hello.txt"
  bounded $OP_WAIT df -k "$m"                         # QUERY_INFO filesystem classes
  bounded $OP_WAIT smbutil statshares -m "$m"         # negotiated session/share attributes
  bounded $OP_WAIT sh -c "echo probe-$i > '$m/probe-$i'"   # CREATE(write) + WRITE
  bounded $OP_WAIT mkdir "$m/dir-$i"
  bounded $OP_WAIT mv "$m/probe-$i" "$m/dir-$i/moved"     # SET_INFO rename
  bounded $OP_WAIT ls -lR "$m/dir-$i"
  bounded $OP_WAIT ln -s hello.txt "$m/link-$i"       # reparse-point create
  bounded $OP_WAIT readlink "$m/link-$i"              # symlink read path
  bounded $OP_WAIT rm -rf "$m/dir-$i" "$m/link-$i"
}

check_wedged() {
  local stuck
  stuck=$(pgrep -x mount_smbfs | wc -l | tr -d ' ')
  if (( stuck >= MAX_WEDGED )); then
    log "KERNEL WEDGED: $stuck mount_smbfs processes stuck (last-case=$(last_case)) — stopping; reboot to clear"
    exit 2
  fi
}

newest_panic() { local p=(/Library/Logs/DiagnosticReports/*.panic(N.om)); echo "${p[1]:-}" }
panic_before=$(newest_panic)
log "driver start, rounds=$ROUNDS mnt=$MNT"

for (( i = 1; i <= ROUNDS; i++ )); do
  check_wedged
  log "round $i: mount (last-case=$(last_case))"
  mount_smbfs "$URL" "$MNT" </dev/null >/dev/null 2>&1 &!

  if wait_mounted; then
    log "round $i: mounted — exercising"
    exercise $i
  else
    log "round $i: MOUNT FAILED/TIMEOUT (last-case=$(last_case))"
  fi
  # umount(2) first: `diskutil unmount` goes through DiskArbitration and was
  # observed hanging 10 s on smbfs before sending any SMB traffic
  bounded $UNMOUNT_WAIT umount -f "$MNT" || bounded $UNMOUNT_WAIT diskutil unmount force "$MNT"
done
log "driver done, last-case=$(last_case)"

# Kernel panics from this session land here and survive reboot
panic_now=$(newest_panic)
if [[ -n $panic_now && $panic_now != "$panic_before" ]]; then
  log "NEW PANIC REPORT: $panic_now"
fi

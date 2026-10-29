# smb-rig — kernel smbfs client fuzzing rig

Authorized local security research on your own machine. Goal: feed mutated
**server responses** to the macOS in-kernel SMB client (`smbfs` kext) and
capture panics/hangs with per-case provenance. Server-response parsing runs in
ring 0, is network-class attack surface, and is far less fuzzed than media
parsers — the highest-EV lane identified in the 2026-08-25 strategy review.

## Architecture

```
macOS kernel (smbfs) ──mount_smbfs──> smb_rig.py :4450
                                        │  mode=proxy : forward+record ──> real smbd :1445
                                        │  mode=fuzz  : answer from recorded corpus, mutated;
                                        │               every outgoing PDU fsync'd to
                                        │               cases/run-*/NNNNNNN.rsp BEFORE send
```

| File | Role |
|---|---|
| `smb_rig.py` | CLI: `proxy`, `fuzz`, `corpus`, `replay`, `stats`; threaded socket loops |
| `smb2.py` | header layout (MS-SMB2 2.2.1.2), compound chains, NBSS framing |
| `corpus.py` | seed loading: re-parses payloads, pairs responses to requests, seed identity |
| `fuzz_session.py` | per-connection response engine with mutation budget (no sockets) |
| `mutators.py` | offset/length, NextEntryOffset-chain, status, pending, oplock-break mutators |
| `cases.py` | crash-durable case storage (fsync + F_FULLFSYNC, one dir per run) + index reader |
| `triage.py` | run depth statistics and byte-exact connection replay |
| `runner.sh` | client driver: mount, bounded workload, wedge + panic detection |

* **proxy mode** builds ground-truth seeds by sitting between the stock client
  and a real Samba server. Frames are stored individually (`seeds/run-*/…smbr`)
  with an INDEX.tsv.
* **fuzz mode** answers every element of every request (including compound
  CREATE+QUERY_INFO+CLOSE chains) from a template recorded for the same
  command *and sub-type* — SESSION_SETUP leg, QUERY_INFO (InfoType, class),
  QUERY_DIRECTORY class, IOCTL CtlCode. It echoes each request's
  MessageId/SessionId/TreeId, keeps recorded statuses on NEGOTIATE/SESSION_SETUP
  so the NTLM `MORE_PROCESSING_REQUIRED` leg survives, and never answers CANCEL.
  Mutations (see `mutators.py`) favour the fields client parsers index with:
  Offset/Length pairs, NextEntryOffset chains (create contexts incl. Apple's
  `AAPL`, directory entries, stream/EA info, change-notify records), compound
  `NextCommand`, error replies that carry data (`STATUS_STOPPED_ON_SYMLINK`
  symlink error response, `STATUS_BUFFER_OVERFLOW`), `STATUS_PENDING` interim
  + async final (sometimes completed twice), unsolicited oplock breaks
  against live FileIds, and absurd credit grants. ECHO ends a cycle (and
  exercises reconnect).
  Mutation is **budgeted**: `--budget N` events (default 2) per mount,
  refilled at each TREE_CONNECT because smbfs reuses one TCP session across
  mounts. A client drops a session after its first malformed reply, so
  mutating every reply would mostly fuzz the abort path; a small budget keeps
  sessions deep and pins any crash on one reply. NEGOTIATE, SESSION_SETUP and
  TREE_CONNECT replies stay clean unless `--mutate-handshake`. Credits are
  granted from the client's CreditRequest (capped at 512). Connections are
  served concurrently — the kernel keeps idle sessions open while new mounts
  connect.
  `--clean` disables mutation entirely: a conformance check that the client
  mounts and reaches the file-op parsers before you fuzz.
* **replay mode** (`--run cases/run-… --conn N`) re-serves a recorded
  connection byte-for-byte, re-patching only MessageIds to match the live
  client, and answers anything past the recording cleanly. This is the
  reproducer for a panic suspect.
* **stats mode** prints per-run depth (how many connections reached CREATE /
  QUERY_DIR / READ …), mounts, the share of sessions that ended on a mutated
  reply, and the newest mutated cases.
* **corpus mode** reports which seed runs are usable and the template keys they
  yield; `--quarantine` moves unusable runs to `seeds/_quarantine/`. Record
  labels are ignored — payloads are re-parsed — so runs captured before the
  header-offset fix are still valid seeds.

## One-time setup

1. Real reference server (for seed recording only):
   ```sh
   brew install samba
   # /opt/homebrew/etc/smb.conf:  [global] smb ports = 1445
   #                              [fuzzshare] path=/tmp/smbshare public=yes
   mkdir -p /tmp/smbshare && echo hello > /tmp/smbshare/hello.txt
   /opt/homebrew/sbin/smbd --no-process-group -s /opt/homebrew/etc/smb.conf -D
   ```
2. Client identity. **The fuzzing client must mount as the same identity the
   seeds were recorded with** — a replayed session is only valid for that
   identity (a recorded guest grant after a named-user login makes
   `mount_smbfs` fail with "Authentication error"). Guest is the simplest:
   unsigned, no session keys to replay. `smb_rig.py corpus` prints the
   identity found in the seeds; `runner.sh` defaults to `//GUEST:@…`.
3. Mount target dir: `mkdir -p /tmp/smbmnt`

## Recording session

```sh
python3 smb_rig.py proxy                       # terminal A
# terminal B: the runner's workload makes good seeds (xattrs, symlinks, ...)
SMB_RIG_URL=//GUEST:@127.0.0.1:4450/fuzzshare ./runner.sh 1
# Ctrl-C the proxy → seeds/run-*/ now holds the full exchange
```

## Fuzzing session

```sh
python3 smb_rig.py corpus                      # sanity: usable runs, templates, identity
python3 smb_rig.py fuzz --clean                # conformance first: expect 100% mounts
./runner.sh 3 && python3 smb_rig.py stats      # depth should reach CREATE/QUERY_DIR
python3 smb_rig.py fuzz                        # then fuzz (seed = time; in meta.json)
./runner.sh 500
python3 smb_rig.py stats                       # tune --budget if sessions die early
```

Measured on macOS 26.5.2 against the 2026-10-29 seeds with `--clean`: 6/6
mounts (13 tree connects, 349 replies in 28 s), ~4.6 s per mount + 14-op
workload + unmount, every file-op command with a template reached. Replies
are matched to the recorded request chain (incl. CREATE file name); before
that, random template picks gave the share-root CREATE a file's reply and
stalled `mount_smbfs` in about half the rounds.

`runner.sh` never waits on a process that touches the mount (a thread wedged
in smbfs is unkillable); every mount/op/unmount is detached and polled with a
deadline. It stops with `KERNEL WEDGED` once 3 `mount_smbfs` processes are
stuck — that state is itself worth recording (reboot to clear). Overrides:
`SMB_RIG_MNT`, `SMB_RIG_LOG`, `SMB_RIG_URL`.

## After a panic

1. `python3 smb_rig.py stats` — lists the newest **mutated** cases. Those
   are the suspects, not merely the last case sent: clean replies can follow a
   corrupting one. Every case and index line was fsync'd before its send, so
   they survived the panic. INDEX.tsv columns: case, UTC ms, conn, req, mut,
   command chain, bytes, mutation description.
2. Match the suspects' UTC against the panic report
   (`/Library/Logs/DiagnosticReports/*.panic`; the driver log prints
   `NEW PANIC REPORT` when one appears).
3. Reproduce byte-exactly: `python3 smb_rig.py replay --run cases/run-… --conn N`
   and `./runner.sh 1`. (`fuzz --seed S --first-conn N` regenerates the same
   mutation stream too, but only if the client's requests repeat exactly.)
4. Minimize the suspect case's mutation, then escalate via the standard
   pipeline (reproduce → minimize → analyze).

Restarting the rig always creates a new run directory; earlier cases are
never overwritten.

## Safety / provenance notes

* Kernel panics WILL reboot this Mac — close work first. Prefer a macOS VM
  (Virtualization.framework) booted on a KDK **KASAN** kernel as the client,
  with the rig on the host: KASAN turns silent out-of-bounds reads into
  reports, and a panic costs a VM restore instead of a host reboot.
* Everything binds 127.0.0.1 by default. Never expose :4450 beyond loopback
  (when the client is a VM, bind the host-only bridge address, not 0.0.0.0).
* `--mutate-handshake` also mutates NEGOTIATE/SESSION_SETUP/TREE_CONNECT; it
  reaches the negotiate-context and SPNEGO parsers but can wedge `mount()`
  unkillably.
* Seed breadth bounds coverage. Record with the runner's workload against a
  share holding a large file and a nested directory (it reads `data.bin` and
  lists `sub/` recursively); that reached READ/WRITE/SET_INFO/LOCK in clean
  replay on 2026-10-29. Still unrecorded: LOCK replies (macOS sent no LOCK
  through Samba), change-notify (Finder window open on the mount), xattr
  streams (needs Samba `vfs objects = fruit streams_xattr`), two-client lease
  breaks, and DFS referrals.
* CREATE replies echo the client's LeaseKey (and v2 ParentLeaseKey) into the
  recorded `RqLs` context: a lease granted for the recording's key is ignored
  by the live client, which then never issues READ.
* Scope: this is the **macOS** kernel client. iOS's Files-app SMB client is a
  userspace implementation and needs a separate harness.

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
| `smb_rig.py` | CLI: `proxy`, `fuzz`, `corpus`; socket loops |
| `smb2.py` | header layout (MS-SMB2 2.2.1.2), compound chains, NBSS framing |
| `corpus.py` | seed loading: re-parses payloads, pairs responses to requests |
| `fuzz_session.py` | per-connection response engine (no sockets; unit-tested) |
| `mutators.py` | offset/length, NextEntryOffset-chain, status, pending, oplock-break mutators |
| `cases.py` | crash-durable case storage (fsync + F_FULLFSYNC, one dir per run) |
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
  + async final (sometimes completed twice), and unsolicited oplock breaks
  against live FileIds. ECHO ends a cycle (and exercises reconnect).
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
2. Credentials the client will use against BOTH smbd and the rig:
   ```sh
   sudo dscl . -create /Users/research ResearchPassword researchpw   # or use an existing acct
   ```
3. Mount target dir: `mkdir -p /tmp/smbmnt`

## Recording session

```sh
python3 smb_rig.py proxy                       # terminal A
printf 'researchpw\n' | mount_smbfs //research@127.0.0.1:4450/fuzzshare /tmp/smbmnt
ls /tmp/smbmnt; cat /tmp/smbshare/hello.txt    # exercise reads/writes
diskutil unmount /tmp/smbmnt
# Ctrl-C the proxy → seeds/run-*/ now holds the full exchange
```

## Fuzzing session

```sh
python3 smb_rig.py corpus                      # sanity: usable runs + template keys
python3 smb_rig.py fuzz                        # terminal A (seed = time; logged in meta.json)
./runner.sh 50                                 # terminal B
```

`runner.sh` never waits on a process that touches the mount (a thread wedged
in smbfs is unkillable); every mount/op/unmount is detached and polled with a
deadline. It stops with `KERNEL WEDGED` once 3 `mount_smbfs` processes are
stuck — that state is itself worth recording (reboot to clear). Overrides:
`SMB_RIG_MNT`, `SMB_RIG_LOG`, `SMB_RIG_URL`.

## After a panic

1. `cases/run-<UTC>-seed<S>/INDEX.tsv` — last line is the last PDU sent
   (case, UTC ms, connection, command chain, mutation description). It was
   fsync'd before the send, so it survived the panic.
2. Match its UTC against the panic report
   (`/Library/Logs/DiagnosticReports/*.panic`; the driver log prints
   `NEW PANIC REPORT` when one appears).
3. Reproduce: `python3 smb_rig.py fuzz --seed S --first-conn N` replays
   connection N's mutation stream exactly (per-connection RNG).
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
* `--mutate-handshake` also mutates NEGOTIATE/SESSION_SETUP; it reaches the
  negotiate-context and SPNEGO parsers but can wedge `mount()` unkillably.
* Seed breadth bounds coverage: record sessions that exercise xattrs, ACLs
  (`ls -le`), symlinks, change-notify (Finder window open on the mount),
  leases/oplocks (two clients on one file) and DFS referrals.
* Scope: this is the **macOS** kernel client. iOS's Files-app SMB client is a
  userspace implementation and needs a separate harness.

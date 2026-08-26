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
                                        │  mode=fuzz  : replay recorded responses,
                                        │               mutated; every outgoing buffer
                                        │               saved to cases/NNNNNNNN.rsp BEFORE send
```

* **proxy mode** builds ground-truth seeds by sitting between the stock client
  and a real Samba server. Frames are stored individually (`seeds/run-*/…smbr`)
  with an INDEX.tsv.
* **fuzz mode** replays the latest recorded response for each command with
  field-aware mutations (u16/u32 stomps + bitflips), patches MessageId/SessionId
  so the client keeps talking, and saves each case pre-send. After a panic and
  reboot: `ls -t cases/ | head` = suspect case; panic report lands in
  `/Library/Logs/DiagnosticReports/Kernel-*.panic`.

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
python3 smb_rig.py fuzz --seed 1337            # terminal A
./runner.sh 50                                 # terminal B (25 s/mount timeout built in)
```

After any host panic+reboot: `ls -t cases/*.rsp | head -1` = last sent buffer;
keep it, re-run rig with `--seed` frozen, confirm reproducibility, then
minimize by byte-deletion under the same loop.

## Safety / provenance notes

* Kernel panics WILL reboot this Mac — close work first; driver log + cases +
  DiagnosticReports all survive.
* Everything binds 127.0.0.1. Never expose :4450/:4450 beyond loopback.
* All cases saved pre-send; driver log timestamps each round — correlation of
  panic time ↔ last case index is automatic.
* Known limitation (honest): deep-tree coverage needs the client to progress
  past SESSION_SETUP/TREE_CONNECT; canned fallback replies are minimal, so
  early crashes may cluster in negotiate/session paths before file ops are
  reached. Iterate by enriching templates from multiple recording sessions
  (dir listings, oplocks, leases, DFS referrals via `smbutil view`).

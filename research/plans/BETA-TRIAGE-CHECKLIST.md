# BETA-TRIAGE-CHECKLIST — per-beta-cycle kernel/userspace regression review

Run this on every new macOS/iOS beta drop. Produced by the 2026-08-25 macOS 27 b7
static triage (full record: `/Users/danny/dev/betas/campaign-0825/kernel/TRIAGE.md`
Addenda A1.1–A1.12; local findings dir is gitignored by policy). Baseline facts for
b7: xnu-13432.1.9~3 T8122 · 32,449 new syms vs 26.5.2 · 8 new syscalls · MIG #2891
new · kexts AFKHIDTBDevice / DeviceInterface-IOUSBHostFamily / security.Image4 new.

## Session record (2026-08-25)

- [x] NVMe/Image4/gPTP/#2891/AFK static audits: **all hardened, no findings** (#280)
- [x] Audio mock-target PoCs vs real frameworks: **negative** (harness divergence;
      never report externally) (#281)
- [x] Tooling added: `tools/smb-rig` (#282/#283); Ghidra mac_arm_64 decompiler
      natives installed at `/Users/danny/tools/ghidra`

## Kernel diff re-run (each beta)

- [ ] Decompress new kernelcache (mac15g slice = T8122-comparable):
      `ipsw kernel dec <IM4P> -o ...`; note `ipsw kernel version` build string
- [ ] Symtab set-diff vs prior beta AND vs release baseline (`nm -arch arm64e`,
      flow in `/Users/danny/dev/betas/campaign-0825/kernel/symdiff.sh`)
- [ ] Structured dumps diff: syscalls / mach traps / MIG numbers
      (`dumpdiff.sh`) — flag any NEW unnamed `is_iokit_subsystem` num beyond 2891
- [ ] **Image4UserClient::evaluate**: still a stub? If it gained a real body →
      top-priority audit (parser reachable via IOConnect; table slot pre-wired).
      b7 ref: 16-byte `kIOReturnUnsupported` @0xfffffe000b4a8404
- [ ] **IOgPTPPlugin guard constants** vs recorded values (TRIAGE A1.9):
      entitlements `com.apple.private.timesync.direct-userclient` (Manager+NetworkPort
      creation), `.reversesync` {sel41,42}, `.getsyncinfo` {52}, `.timeofdayptpinstance`
      {sel6}; add/removeUnicast min structureInput sizes 1/5/7/17
- [ ] **AFKSharedMemoryResource**: does its IOResources-personality start() now
      succeed? (ungated shared-memory UC becomes any-process-reachable if so —
      latent design risk, TRIAGE A1.12)
- [ ] **#2891 reply-string provenance** once xnu-13432+ source drops (residual
      strlen-of-reply-buffer question, TRIAGE A1.11)

## Userspace retests (once beta dylibs obtainable — spare volume or full IPSW)

- [ ] FINDING-04 AudioToolbox ID3 hang PoC vs beta framework
- [ ] FINDING-05 CoreGraphics PDF-text hang PoC vs beta framework
- [ ] FINDING-06 CoreText sfnt hang PoC vs beta framework (note iOS divergence)
- [ ] Three audio PoC families (CAF/ID3/ADTS) vs beta audiotoolbox_fuzzer
- [ ] Resume userspace campaign harnesses against beta dyld shared cache

## New-lane work

- [ ] smb-rig first recording session (see `tools/smb-rig/README.md` setup), then
      fuzz campaign per strategy review; correlate panics ↔ last case file

# AudioProbe — on-device confirmation probe

Turns a Mac-discovered finding into **hardware-confirmed evidence** on a
personal iPhone (FINDING-04 workflow; issue #217). No SRD required: a
dev-signed app with free provisioning is enough.

## What it does

On launch the app:

1. Opens `Documents/input.bin` from its container if the confirm bridge
   pushed one (`tools/campaign/confirm_on_device.py`), else self-tests with
   the bundled `benign.aiff` + `hang.mp3`.
2. Sniffs the magic bytes and dispatches to the matching framework API,
   mirroring the mac campaign targets:
   - `imageio` → CGImageSource (PNG / GIF / JPEG / HEIC-AVIF `ftyp`)
   - `coregraphics` → CGPDFDocument
   - `coretext` → CTFontManagerCreateFontDescriptorsFromData
   - `audio` → AudioFileOpenURL
3. Logs `PROBE ...` verdicts (captured via `devicectl --console`) and exits
   with `PROBE DONE no-hang` — or spins forever inside the framework if the
   input hangs it (the FINDING-04 signature).

## One-time setup

1. `open AudioProbe.xcodeproj` → Signing & Capabilities → select your
   Personal Team (the checked-in project has none hardcoded)
2. ⌘R once with the iPhone connected (registers device, mints profile)
3. Settings → General → VPN & Device Management → trust the developer cert
4. Enable Developer Mode on the phone (Settings → Privacy & Security)

## Confirm a finding

```bash
# from a file:
.venv/bin/python tools/campaign/confirm_on_device.py --input crash-input.bin

# straight from the workspace crash store:
.venv/bin/python tools/campaign/confirm_on_device.py --crash crash_e38fe9ca18ac
```

Verdicts: `OPEN_OK` / `OPEN_FAIL` / `HANG` / `ERROR`, printed as the standard
JSON envelope. `HANG` on a memory-safety-classified crash is the
bounty-candidate signal; see `docs/` and issue #217 for the campaign loop.

Note: the checked-in project records a Personal Team id (`APCDDQL9RC`) —
team ids are public (they ship in every signed app); change it to your own
via the Signing pane.

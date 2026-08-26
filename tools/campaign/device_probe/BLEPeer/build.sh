#!/bin/bash
# build.sh — compile + bundle the BLEPeer macOS app (TCC requires a signed
# bundle whose Info.plist declares NSBluetoothAlwaysUsageDescription; a bare
# binary or `swift main.swift` aborts in __TCC_CRASHING_DUE_TO_PRIVACY_VIOLATION).
set -eu
cd "$(dirname "$0")"
swiftc main.swift -O -o /tmp/blepeer-bin
mkdir -p BLEPeer.app/Contents/MacOS
cp /tmp/blepeer-bin BLEPeer.app/Contents/MacOS/BLEPeer
[ -f BLEPeer.app/Contents/Info.plist ] || {
  cat > BLEPeer.app/Contents/Info.plist <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleIdentifier</key><string>research.iosr.BLEPeer</string>
<key>CFBundleName</key><string>BLEPeer</string>
<key>CFBundleExecutable</key><string>BLEPeer</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSUIElement</key><true/>
<key>NSBluetoothAlwaysUsageDescription</key><string>Advertises the IOSR-BT research peer so your own iPhone can parse its GATT data during authorized testing.</string>
</dict></plist>
PLIST
}
codesign --force --deep -s - BLEPeer.app
echo "built: BLEPeer.app — launch via 'open' (TCC attributes BT access to the bundle)"

# staticscan — Ghidra integration guide

The scout's call-graph capability uses Ghidra headless analysis to export
functions, call edges, and strings-with-references, then feeds them to
`staticscan callgraph --focus` for directed-fuzzing target selection.

## One-time setup

1. **Java 21** (Ghidra 12 requirement):
   ```bash
   brew install openjdk@21
   ```
2. **Ghidra** (no brew cask; GitHub release):
   ```bash
   mkdir -p ~/tools && cd ~/tools
   curl -sL -o ghidra.zip https://github.com/NationalSecurityAgency/ghidra/releases/latest/download/ghidra_<VER>_PUBLIC_<DATE>.zip
   unzip -q ghidra.zip && mv ghidra_<VER>_PUBLIC ghidra && rm ghidra.zip
   ```
3. Export for every shell (or add to profile):
   ```bash
   export JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
   ```

## Export a binary's call graph

```bash
mkdir -p /tmp/ghidra-proj   # project dir must exist
~/tools/ghidra/support/analyzeHeadless /tmp/ghidra-proj proj \
    -import "$PWD/tools/harness/build/coretext_fuzzer" \
    -postScript ghidra_export.java -scriptPath "$PWD/tools/staticscan"
# -> writes <binary>.ghidra_export.json next to the binary
```

The **Java** postscript is the default (Ghidra 12 removed Jython; Python
scripts need PyGhidra). `ghidra_export.py` is retained for PyGhidra users.

## Turn the export into directed-fuzzing targets

```bash
ios-research staticscan callgraph <binary>.ghidra_export.json \
    --focus --out callgraph.json
# -> callgraph.json is directly consumable by ios_research.directed
#    focus functions = functions referencing format constants
```

Then point a directed campaign at the focus functions (see
`src/ios_research/directed.py`).

## dyld shared cache caveat

System frameworks live inside the shared cache, not as loose files —
`staticscan locate <framework>` reports this. Strings-based
fingerprinting works on the cache directly, but **call-graph analysis
requires extracting the dylib first** (e.g. with `dyld_shared_cache_util
-extract` from dyld sources, or the `ipsw` tool: `brew install ipsw`,
then `ipsw dsc extract`). Loose Mach-Os (custom targets, third-party
apps, our harness binaries) need no extraction.

## Focus-token quality

Focus functions are identified by format-constant references. Overly
generic tokens (e.g. `"data"`) produce false positives in unrelated
runtime code — signature tokens are curated in
`src/ios_research/staticscan.py::FORMAT_SIGNATURES`; when a focus list
looks noisy, tighten the token set first.

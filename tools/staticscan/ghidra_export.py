# Ghidra headless post-script: export functions, call edges, and defined
# strings (with referencing functions) as JSON for ios-research staticscan.
#
# Usage (headless):
#   analyzeHeadless <project_dir> <proj> -import <binary> \
#       -postScript ghidra_export.py -scriptPath tools/staticscan \
#       -deleteProject
#
# The script writes its JSON next to the analyzed binary: <binary>.ghidra.json
# Jython 2.7 (Ghidra's scripting engine): no f-strings, keep it simple.
# @category ios-research
import json
import os

from ghidra.program.model.symbol import RefType

FM = currentProgram.getFunctionManager()
LB = currentProgram.getListing()

functions = []
name_by_entry = {}
for f in FM.getFunctions(True):
    name = f.getName()
    functions.append({"name": name,
                      "entry": str(f.getEntryPoint())})
    name_by_entry[str(f.getEntryPoint())] = name

edges = []
for f in FM.getFunctions(True):
    called = f.getCalledFunctions(None)
    if called is None:
        continue
    for t in called:
        edges.append({"from": f.getName(), "to": t.getName()})

strings = []
for si in LB.getDefinedData(True):
    try:
        if si.hasStringValue():
            data = si.getValue()
            if not isinstance(data, (str, unicode)):
                continue
            refs = []
            it = si.getReferenceIteratorTo()
            for r in it:
                fn = FM.getFunctionContaining(r.getFromAddress())
                if fn is not None:
                    refs.append(fn.getName())
            strings.append({"data": data[:512],
                            "references": sorted(set(refs))})
    except Exception:
        pass

out = {"functions": functions, "edges": edges, "strings": strings}
base = currentProgram.getExecutablePath() or "program"
dest = os.path.join(os.path.dirname(base) or ".", "ghidra_export.json")
with open(dest, "w") as fh:
    json.dump(out, fh)
print("staticscan: wrote %s (%d functions, %d edges, %d strings)" %
      (dest, len(functions), len(edges), len(strings)))

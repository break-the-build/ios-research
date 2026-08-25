/* Ghidra headless post-script: export functions, call edges, and defined
 * strings (with referencing functions) as JSON for ios-research staticscan.
 *
 * Java port of ghidra_export.py — Ghidra 12 removed Jython, and .java
 * scripts are compiled on the fly by headless runs, so this variant has no
 * Python dependency.
 *
 * Usage (headless):
 *   analyzeHeadless <project_dir> <proj> -import <binary> \
 *       -postScript ghidra_export.java -scriptPath tools/staticscan
 *
 * Writes JSON next to the analyzed binary: <binary>.ghidra_export.json
 * @category ios-research
 */
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.util.*;

public class ghidra_export extends GhidraScript {

    private String jesc(String s) {
        StringBuilder b = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.toString();
    }

    private String jstr(String v) { return "\"" + jesc(v) + "\""; }

    private String jlist(List<String> items) {
        StringBuilder b = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) b.append(",");
            b.append(items.get(i));
        }
        return b.append("]").toString();
    }

    @Override
    public void run() throws Exception {
        FunctionManager fm = currentProgram.getFunctionManager();

        List<String> fnJson = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            fnJson.add("{\"name\":" + jstr(f.getName())
                + ",\"entry\":" + jstr(f.getEntryPoint().toString()) + "}");
        }

        List<String> edgeJson = new ArrayList<>();
        for (Function f : fm.getFunctions(true)) {
            Set<Function> called;
            try {
                called = f.getCalledFunctions(monitor);
            } catch (Exception e) { continue; }
            if (called == null) continue;
            for (Function t : called) {
                edgeJson.add("{\"from\":" + jstr(f.getName())
                    + ",\"to\":" + jstr(t.getName()) + "}");
            }
        }

        List<String> strJson = new ArrayList<>();
        DataIterator di = currentProgram.getListing().getDefinedData(true);
        int scanned = 0;
        while (di.hasNext() && scanned < 2_000_000) {
            Data d = di.next();
            scanned++;
            if (d == null || !d.hasStringValue()) continue;
            Object v = d.getValue();
            if (!(v instanceof String)) continue;
            String val = (String) v;
            if (val.length() > 512) val = val.substring(0, 512);
            Set<String> refs = new TreeSet<>();
            try {
                ReferenceIterator it = currentProgram.getReferenceManager()
                    .getReferencesTo(d.getAddress());
                while (it.hasNext()) {
                    Reference r = it.next();
                    Function fn = getFunctionContaining(r.getFromAddress());
                    if (fn != null) refs.add(fn.getName());
                }
            } catch (Exception e) { /* best effort */ }
            List<String> refItems = new ArrayList<>();
            for (String r : refs) refItems.add(jstr(r));
            strJson.add("{\"data\":" + jstr(val)
                + ",\"references\":" + jlist(refItems) + "}");
        }

        String json = "{\"functions\":[" + String.join(",", fnJson)
            + "],\"edges\":[" + String.join(",", edgeJson)
            + "],\"strings\":[" + String.join(",", strJson) + "]}";

        String path = currentProgram.getExecutablePath();
        File bin = new File(path);
        File dest = new File(bin.getParentFile(), bin.getName()
            + ".ghidra_export.json");
        Writer w = new OutputStreamWriter(new FileOutputStream(dest),
            "UTF-8");
        w.write(json);
        w.close();
        println("staticscan: wrote " + dest.getPath() + " ("
            + fnJson.size() + " functions, " + edgeJson.size()
            + " edges, " + strJson.size() + " strings)");
    }
}

#!/usr/bin/env python3
"""smb-rig: malicious SMB2 server / recording proxy targeting the macOS kernel smbfs client.

Authorized local security research only (own machine). See README.md.

Modes:
  proxy  listen on --listen (default 4450), forward to a real SMB server on
         --upstream (default 1445), log every frame both directions into
         seeds/*.bin  -> builds the replay corpus.
  fuzz   replay recorded server-side responses (mutated) to whatever the
         client sends; unknown commands get mutated garbage sized like the
         recorded template. Every outgoing buffer is saved BEFORE sending,
         so the last-saved case after a kernel panic is the suspect.

Frame format on disk (seed files): NBSS already stripped; each record =
  u32 magic 'SMBR' | u8 direction(0=req,1=resp) | u8 cmd | u32 msgid | u32 len | bytes
"""
import argparse, os, socket, struct, sys, time, random

MAGIC = b"SMBR"
SMB2_SIG = b"\xfeSMB"
HDR = 64


def nbss_split(buf):
    """Yield complete NBSS PDUs (type, payload) from a buffer; return rest."""
    out, off = [], 0
    while len(buf) - off >= 4:
        n = int.from_bytes(buf[off + 1:off + 4], "big")
        if len(buf) - off < 4 + n:
            break
        out.append((buf[off], buf[off + 4:off + 4 + n]))
        off += 4 + n
    return out, buf[off:]


def parse_smb2(payload):
    """Return (cmd, status, flags, msgid, body) or None."""
    if len(payload) < HDR or payload[:4] != SMB2_SIG:
        return None
    cmd = struct.unpack_from("<H", payload, 14)[0]
    msgid = struct.unpack_from("<Q", payload, 28)[0]
    body = payload[HDR:]
    return cmd, msgid, body


CMD_NAMES = {0: "NEGOTIATE", 1: "SESSION_SETUP", 2: "LOGOFF", 3: "TREE_CONNECT",
             4: "TREE_DISCONNECT", 5: "CREATE", 6: "CLOSE", 7: "FLUSH",
             8: "READ", 9: "WRITE", 16: "ECHO", 18: "QUERY_DIR",
             19: "CHANGE_NOTIFY", 20: "INFO"}


class Recorder:
    def __init__(self, dirpath):
        self.dir = dirpath
        os.makedirs(dirpath, exist_ok=True)
        self.n = 0
        self.idx = os.path.join(dirpath, "INDEX.tsv")

    def save(self, direction, cmd, msgid, data):
        fn = f"{self.n:06d}_{ 'req' if direction==0 else 'rsp'}_{CMD_NAMES.get(cmd,cmd):>14}_{msgid:#x}.smbr"
        with open(os.path.join(self.dir, fn), "wb") as f:
            f.write(MAGIC + struct.pack("<BBII", direction, cmd & 0xFF, msgid & 0xFFFFFFFF, len(data)) + data)
        with open(self.idx, "a") as f:
            f.write(f"{fn}\t{direction}\t{cmd}\t{msgid}\t{len(data)}\n")
        self.n += 1


def pump(src, dst, recorder, direction, state):
    """Read from src, log + forward each NBSS PDU to dst."""
    try:
        src.settimeout(0.25)
        while True:
            try:
                chunk = src.recv(65536)
            except socket.timeout:
                return True
            except OSError:
                return False
            if not chunk:
                return False
            state["buf"] += chunk
            pdus, state["buf"] = nbss_split(state["buf"])
            for _t, payload in pdus:
                p = parse_smb2(payload)
                cmd, msgid = (p[0], p[1]) if p else (-1, 0)
                recorder.save(direction, cmd, msgid, payload)
                if direction == 1:
                    state["last_rsp"] = (cmd, payload)
                try:
                    dst.sendall(payload)
                except OSError:
                    return False
    finally:
        pass


def do_proxy(args):
    rec = Recorder(os.path.join(args.seeds, time.strftime("run-%Y%m%d-%H%M%S")))
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.listen))
    srv.listen(1)
    print(f"[proxy] listening {args.bind}:{args.listen} -> {args.upstream}  (Ctrl-C to stop)")
    while True:
        cli, addr = srv.accept()
        print(f"[proxy] client {addr}")
        up = None
        try:
            up = socket.create_connection((args.upstream_host, args.upstream), timeout=10)
        except OSError as e:
            print(f"[proxy] upstream connect failed: {e}")
            cli.close()
            continue
        st_c, st_s = {"buf": b""}, {"buf": b""}
        while True:
            progressed = False
            if pump(cli, up, rec, 0, st_c):
                progressed = True
            if pump(up, cli, rec, 1, st_s):
                progressed = True
            if not progressed:
                # idle heartbeat; drop connection if both sides closed
                try:
                    cli.setblocking(False); cli.close()
                except OSError:
                    pass
                try:
                    up.close()
                except OSError:
                    pass
                break
        print("[proxy] session ended")


# ---------------- fuzz mode ----------------

def load_templates(seed_dirs):
    """Latest response per command becomes the template."""
    best = {}
    import glob
    files = []
    for d in seed_dirs:
        files += glob.glob(os.path.join(d, "*.smbr"))
    for fp in sorted(files):
        raw = open(fp, "rb").read()
        if raw[:4] != MAGIC:
            continue
        direction, cmd, msgid, ln = struct.unpack_from("<BBII", raw, 4)
        if direction == 1 and ln >= HDR:
            best[cmd] = raw[16:16 + ln]
    return best


def mutate(body, rng):
    """Field-stomp + bitflip mutation on a response body copy."""
    b = bytearray(body)
    if not b:
        return bytes(b)
    for _ in range(rng.randint(1, 4)):
        op = rng.random()
        if op < 0.45 and len(b) >= 2:                       # u16 field stomp
            o = rng.randrange(0, len(b) - 1)
            v = rng.choice([0x0000, 0x0001, 0xFFFF, 0x7FFF, 0x0100])
            struct.pack_into("<H", b, o, v)
        elif op < 0.75 and len(b) >= 4:                     # u32 field stomp
            o = rng.randrange(0, len(b) - 3)
            v = rng.choice([0, 1, 0xFFFFFFFF, 0x7FFFFFFF, 0xFFFFFF00, rng.getrandbits(32)])
            struct.pack_into("<I", b, o, v)
        else:                                               # byte flips
            for _ in range(rng.randint(1, 8)):
                o = rng.randrange(len(b))
                b[o] ^= 1 << rng.randrange(8)
    return bytes(b)


CANNED_NEGOTIATE = (
    struct.pack("<HHI", 65, 0, 0)           # StructSize=65, SecurityMode=0, Capabilities=0
    + b"\x00" * 16                          # GUID
    + struct.pack("<HIHI", 0x02FF, 0, 1, 0)  # MaxDialect.. actually rough; client re-negotiates
    + struct.pack("<H", 0x0202)             # dialect 2.0.2 fallback
)
# NOTE: canned fallbacks are intentionally minimal; real seeds from proxy mode
# are what drive deep parsing.


def do_fuzz(args):
    tmpl = load_templates(args.seeds)
    if not tmpl:
        sys.exit("no seed templates found — run proxy mode first")
    print(f"[fuzz] templates for commands: {[CMD_NAMES.get(k,k) for k in sorted(tmpl)]}")
    rng = random.Random(args.seed)
    os.makedirs(args.cases, exist_ok=True)
    caseno = 0

    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((args.bind, args.listen))
    srv.listen(1)
    print(f"[fuzz] listening {args.bind}:{args.listen}; run mount_smbfs against this port")

    while True:
        cli, addr = srv.accept()
        print(f"[fuzz] client {addr} case#{caseno}")
        buf = b""
        sess = 0
        try:
            cli.settimeout(15)
            while True:
                # read one request PDU
                while len(buf) < 4:
                    c = cli.recv(65536)
                    if not c:
                        raise ConnectionReset
                    buf += c
                n = int.from_bytes(buf[1:4], "big")
                while len(buf) < 4 + n:
                    c = cli.recv(65536)
                    if not c:
                        raise ConnectionReset
                    buf += c
                payload, buf = buf[4:4 + n], buf[4 + n:]
                p = parse_smb2(payload)
                if p is None:
                    continue
                cmd, msgid, body = p

                base = tmpl.get(cmd)
                if base is None:
                    # synthesize minimal error/success reply so client keeps talking
                    hdr = SMB2_SIG + struct.pack("<HHIQIHHQQ", 64, 0, 0xC0000001,
                                                 cmd, 1, 0x1, 0, msgid) + b"\x00" * 24
                    resp = hdr[:HDR]
                else:
                    resp = bytearray(base)
                    struct.pack_into("<Q", resp, 28, msgid)          # match msgid
                    struct.pack_into("<I", resp, 8, 0)               # STATUS_SUCCESS
                    if sess:
                        struct.pack_into("<Q", resp, 40, sess)
                    body_mut = mutate(bytes(resp[HDR:]), rng)
                    resp = bytes(resp[:HDR]) + body_mut

                caseno += 1
                casefile = os.path.join(args.cases, f"{caseno:07d}.rsp")
                open(casefile, "wb").write(resp)                     # PROVENANCE: saved pre-send
                try:
                    cli.sendall(b"\x00" + len(resp).to_bytes(3, "big") + resp)
                except OSError:
                    raise ConnectionReset

                if cmd == 1:  # SESSION_SETUP: capture granted session id from our own template
                    try:
                        sess = struct.unpack_from("<Q", resp, 40)[0]
                    except Exception:
                        sess = 0
                if cmd == 16:  # ECHO → healthy liveness exit for the driver script
                    print("[fuzz] ECHO seen; session cycle done")
                    break
        except (ConnectionReset, socket.timeout, OSError):
            pass
        finally:
            try:
                cli.close()
            except OSError:
                pass
        print(f"[fuzz] cycle complete, cases={caseno}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["proxy", "fuzz"])
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--listen", type=int, default=4450)
    ap.add_argument("--upstream", type=int, default=1445, help="real smbd port")
    ap.add_argument("--upstream-host", default="127.0.0.1")
    ap.add_argument("--seeds", default="seeds")
    ap.add_argument("--cases", default="cases")
    ap.add_argument("--seed", type=int, default=1337)
    a = ap.parse_args()

    if a.mode == "proxy":
        do_proxy(a)
    else:
        do_fuzz(a)


if __name__ == "__main__":
    main()

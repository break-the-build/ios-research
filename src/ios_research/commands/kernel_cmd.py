"""`ios-research kernel` — kernel-boundary harness tooling (XNU mach_msg)."""

from __future__ import annotations

from ..errors import ValidationError
from ..output import Result


def register(subparsers, parent) -> None:
    p = subparsers.add_parser("kernel", parents=[parent],
                              help="kernel-boundary research surfaces")
    sub = p.add_subparsers(dest="subcommand", metavar="<action>")

    p_surface = sub.add_parser("surface", parents=[parent],
                               help="describe simulated boundary surfaces")
    p_surface.set_defaults(func=cmd_surface)

    p_build = sub.add_parser("msg-build", parents=[parent],
                             help="pack a Mach message from fields")
    p_build.add_argument("--bits", type=lambda v: int(v, 0), default=0x80000000)
    p_build.add_argument("--remote", type=lambda v: int(v, 0), default=1)
    p_build.add_argument("--local", type=lambda v: int(v, 0), default=0)
    p_build.add_argument("--voucher", type=lambda v: int(v, 0), default=0)
    p_build.add_argument("--id", dest="msg_id",
                         type=lambda v: int(v, 0), default=0x1000)
    p_build.add_argument("--port", action="append", default=[],
                         help="port right name (repeatable)")
    p_build.add_argument("--ool-size", action="append", default=[],
                         type=lambda v: int(v, 0),
                         help="OOL region size (repeatable)")
    p_build.add_argument("--payload", default="dead4141414141",
                         help="hex payload bytes")
    p_build.add_argument("--out", required=True,
                         help="write the packed message here")
    p_build.set_defaults(func=cmd_msg_build)

    p_unpack = sub.add_parser("msg-unpack", parents=[parent],
                              help="parse and validate a packed message")
    p_unpack.add_argument("input")
    p_unpack.set_defaults(func=cmd_msg_unpack)

    p.set_defaults(func=cmd_surface)


SURFACES = [
    {"id": "mach-msg-complex", "kind": "ipc",
     "description": "complex Mach messages with port + OOL descriptors"},
    {"id": "mach-send-rights", "kind": "ipc",
     "description": "send-right accounting across descriptor arrays"},
    {"id": "driverkit-userclient", "kind": "driverkit",
     "description": "user-client method dispatch surface model "
                    "(reserved for future targets)"},
]


def cmd_surface(ctx, args) -> Result:
    return Result(command="kernel surface",
                  data={"surfaces": SURFACES, "count": len(SURFACES)},
                  human=lambda d: "\n".join(
                      f"{s['id']:24} {s['description']}"
                      for s in d["surfaces"]))


def _int_list(values):
    out = []
    for v in values:
        try:
            out.append(int(v, 0) if isinstance(v, str) else int(v))
        except ValueError as exc:
            raise ValidationError(f"invalid integer value '{v}'") from exc
    return out


def cmd_msg_build(ctx, args) -> Result:
    from ..machmsg import MachMessage, MachMessageError, OOLDescriptor, \
        PortDescriptor, pack
    ports = [PortDescriptor(name=n) for n in _int_list(args.port)]
    ools = [OOLDescriptor(address=0x4000 + i * 0x100, size=s)
            for i, s in enumerate(_int_list(args.ool_size))]
    try:
        payload = bytes.fromhex(args.payload)
    except ValueError as exc:
        raise ValidationError(f"--payload must be hex: {exc}") from exc
    msg = MachMessage(bits=args.bits, remote=args.remote, local=args.local,
                      voucher=args.voucher, msg_id=args.msg_id,
                      ports=ports, ool_regions=ools, payload=payload)
    try:
        blob = pack(msg)
    except MachMessageError as exc:
        raise ValidationError(str(exc)) from exc

    from ..machmsg import parse
    status, detail, parsed = parse(blob)

    import os
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "wb") as fh:
        fh.write(blob)

    return Result(command="kernel msg-build",
                  data={"out": args.out, "size": len(blob),
                        "fields": msg.to_dict(),
                        "self_check": {"status": status, "detail": detail}},
                  messages=[f"wrote {len(blob)} bytes to {args.out} "
                            f"(self-check: {status})"])


def cmd_msg_unpack(ctx, args) -> Result:
    from ..machmsg import parse
    try:
        data = open(args.input, "rb").read()
    except OSError as exc:
        raise ValidationError(f"cannot read input: {exc}") from exc
    status, detail, msg = parse(data)
    return Result(command="kernel msg-unpack",
                  data={"input": args.input, "status": status,
                        "detail": detail,
                        "fields": msg.to_dict() if msg else None})

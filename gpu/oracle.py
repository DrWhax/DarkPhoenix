#!/usr/bin/env python3
"""External white-box oracle for darkphoenix-metal.

Stdout is the binary protocol. Stray prints are moved to stderr.

Serve your own WhiteBoxedAES::

    from oracle import serve
    serve(MyWhiteBoxedAES(...))

Or::

    python3 -u gpu/oracle.py encoded --key HEX --seed 1
    python3 -u gpu/oracle.py class pkg.mod:ClassName --json '{"...": "..."}'

The class must implement apply(data) and applyFault(data, [(round, byte, xor)]).
applyReverse(data) is used only when hasReverse() is true.
Fault byte indexes are stable labels for 16 distinct bytes in that round, the
same contract as darkphoenixAES.WhiteBoxedAES.
"""

import importlib
import json
import os
import struct
import sys
import types

OP_HELLO = 1
OP_QUIT = 2
OP_EVAL = 3
OP_REVERSE = 4
OP_CHANGE = 5
OP_REMOVE = 6
OP_RANDOM = 7
OP_THREAD = 8
OP_PREPARE = 9
OP_CLEAR = 10


def _stub_tqdm():
    try:
        import tqdm  # noqa: F401
    except ImportError:
        mod = types.ModuleType("tqdm")

        class _T:
            def __init__(self, *a, **k):
                pass

            def update(self, *a, **k):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        mod.tqdm = _T
        sys.modules["tqdm"] = mod


def _read_exact(n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sys.stdin.buffer.read(n - len(buf))
        if not chunk:
            raise EOFError
        buf += chunk
    return bytes(buf)


def serve(wb):
    """Speak the oracle protocol. Does not return until the client quits or stdin closes."""
    proto = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    try:
        sys.stdout = sys.stderr
    except Exception:
        pass

    def ok(payload=b""):
        proto.write(b"\x00" + payload)
        proto.flush()

    def fail(message):
        raw = str(message).encode("utf-8", "replace")
        proto.write(b"\x01" + struct.pack("<I", len(raw)) + raw)
        proto.flush()

    _stub_tqdm()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    from darkphoenixAES.WhiteBoxedAES import WhiteBoxedAES, WhiteBoxedAESAuto, WhiteBoxedAESDynamic

    nr = int(wb.getRoundNumber())
    encrypt = 1 if wb.isEncrypt() else 0
    reverse = 1 if wb.hasReverse() else 0
    last = getattr(wb, "lastRoundHasMC", None)
    last_b = 0 if last is None else (2 if last else 1)
    auto = 1 if isinstance(wb, WhiteBoxedAESAuto) else 0
    dynamic = 1 if isinstance(wb, WhiteBoxedAESDynamic) else 0
    has_random = 1 if callable(getattr(wb, "getRandomInput", None)) else 0
    evaluated = 0
    if callable(getattr(wb, "newThread", None)):
        wb.newThread()

    def callback(tag, data):
        proto.write(bytes([tag]) + bytes(data))
        proto.flush()
        return _read_exact(16)

    try:
        while True:
            op = _read_exact(1)[0]
            if op == OP_QUIT:
                ok()
                return
            if op == OP_HELLO:
                ok(struct.pack("<BBBBBBB", nr, encrypt, reverse, last_b, auto, dynamic, has_random))
                continue
            if op == OP_CHANGE:
                rnd, byte = struct.unpack("<BB", _read_exact(2))
                wb.changeFaultPosition(rnd, byte)
                ok()
                continue
            if op == OP_REMOVE:
                rnd, byte = struct.unpack("<BB", _read_exact(2))
                if hasattr(wb, "removeFaultPosition"):
                    wb.removeFaultPosition(rnd, byte)
                ok()
                continue
            if op == OP_RANDOM:
                n = struct.unpack("<I", _read_exact(4))[0]
                got = bytes(wb.getRandomInput(n))
                if len(got) != 16:
                    raise RuntimeError("getRandomInput must return 16 bytes")
                ok(got)
                continue
            if op == OP_THREAD:
                if callable(getattr(wb, "newThread", None)):
                    wb.newThread()
                ok()
                continue
            if op == OP_PREPARE:
                rnd, has2 = struct.unpack("<BB", _read_exact(2))
                rev1 = lambda data: callback(2, data)
                rev2 = (lambda data: callback(3, data)) if has2 else None
                if dynamic and hasattr(wb, "prepareFaultPosition"):
                    wb.prepareFaultPosition(rnd, rev1, rev2)
                ok()
                continue
            if op == OP_CLEAR:
                rnd, byte = struct.unpack("<BB", _read_exact(2))
                if hasattr(wb, "removeFaultPosition"):
                    rounds = range(nr) if rnd == 0xFF else [rnd]
                    for r in rounds:
                        bytes_ = range(16) if byte == 0xFF else [byte]
                        for b in bytes_:
                            wb.removeFaultPosition(r, b)
                ok()
                continue
            count = struct.unpack("<I", _read_exact(4))[0]
            if op == OP_REVERSE:
                blocks = _read_exact(count * 16)
                out = bytearray()
                for i in range(count):
                    data = blocks[i * 16:(i + 1) * 16]
                    got = wb.applyReverse(data)
                    if len(got) != 16:
                        raise RuntimeError("applyReverse must return 16 bytes")
                    out += bytes(got)
                ok(out)
                continue
            if op == OP_EVAL:
                raw = _read_exact(count * 20)
                out = bytearray()
                for i in range(count):
                    rec = raw[i * 20:(i + 1) * 20]
                    data = rec[:16]
                    rnd, byte, xor = struct.unpack_from("<HBB", rec, 16)
                    if rnd == 0xFFFF:
                        got = wb.apply(data)
                    else:
                        got = wb.applyFault(data, [(rnd, byte, xor)])
                    if len(got) != 16:
                        raise RuntimeError("apply/applyFault must return 16 bytes")
                    out += bytes(got)
                    evaluated += 1
                    if evaluated % 100000 == 0:
                        print(f"oracle evaluations {evaluated}", file=sys.stderr, flush=True)
                ok(out)
                continue
            fail(f"unknown op {op}")
            return
    except EOFError:
        return
    except Exception as exc:
        fail(f"{type(exc).__name__}: {exc}")
        raise


def _encoded_wb(argv):
    _stub_tqdm()
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if root not in sys.path:
        sys.path.insert(0, root)
    from darkphoenixAES.test.AESEncoded import AESEncoded
    from darkphoenixAES.test.WhiteBoxedAESTest import WhiteBoxedAESTest

    key = None
    seed = 1
    decrypt = False
    no_reverse = False
    auto = False
    dynamic = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--key":
            key = bytes.fromhex(argv[i + 1])
            i += 2
        elif a == "--seed":
            seed = int(argv[i + 1])
            i += 2
        elif a == "--decrypt":
            decrypt = True
            i += 1
        elif a == "--no-reverse":
            no_reverse = True
            i += 1
        elif a == "--auto":
            auto = True
            i += 1
        elif a == "--dynamic":
            dynamic = True
            i += 1
        else:
            raise SystemExit(f"unknown encoded arg {a}")
    if key is None:
        raise SystemExit("encoded oracle requires --key HEX")
    from darkphoenixAES.WhiteBoxedAES import WhiteBoxedAESDynamic
    aes = AESEncoded(key, encodingSeed=seed)
    if auto:
        from darkphoenixAES.test.WhiteBoxedAESAutoTest import WhiteBoxedAESAutoTest
        return WhiteBoxedAESAutoTest(aes, enc=not decrypt, useReverse=not no_reverse, fast=True, multiFault=False)
    if dynamic:
        class Dyn(WhiteBoxedAESTest, WhiteBoxedAESDynamic):
            def prepareFaultPosition(self, fround, reverseRoundMethod, reverseRoundMethod2=None):
                out = self.applyFault(bytes(16), [(fround, 0, 1)])
                reverseRoundMethod(out)
                if reverseRoundMethod2 is not None:
                    reverseRoundMethod2(out)
        return Dyn(aes, enc=not decrypt, useReverse=not no_reverse, fast=True)
    return WhiteBoxedAESTest(aes, enc=not decrypt, useReverse=not no_reverse, fast=True)


def _class_wb(argv):
    if not argv:
        raise SystemExit("class oracle requires module:ClassName")
    spec = argv[0]
    rest = argv[1:]
    payload = None
    if rest[:1] == ["--json"]:
        payload = json.loads(rest[1])
    modname, _, clsname = spec.partition(":")
    if not clsname:
        raise SystemExit("class spec must be module:ClassName")
    mod = importlib.import_module(modname)
    cls = getattr(mod, clsname)
    if payload is None:
        return cls()
    if isinstance(payload, dict):
        return cls(**payload)
    if isinstance(payload, list):
        return cls(*payload)
    raise SystemExit("--json must be an object or array")


def main():
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help"):
        print(__doc__, file=sys.stderr)
        return 0
    mode, argv = argv[0], argv[1:]
    if mode == "encoded":
        wb = _encoded_wb(argv)
    elif mode == "class":
        wb = _class_wb(argv)
    else:
        raise SystemExit(f"unknown mode {mode}")
    serve(wb)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BrokenPipeError:
        raise SystemExit(0)

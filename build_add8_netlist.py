#!/usr/bin/env python3
"""Build official-canvas-equivalent ADD8 netlist + calldata for LeoLabs Processor."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent


class Netlist:
    NAND = 0

    def __init__(self, n_in: int):
        self.n_in = n_in
        self.elements: list[tuple] = []
        self.next = 2 + n_in

    @property
    def ZERO(self) -> int:
        return 0

    @property
    def ONE(self) -> int:
        return 1

    def input(self, i: int) -> int:
        if not 0 <= i < self.n_in:
            raise RangeError(f"input {i}")
        return 2 + i

    def nand(self, a: int, b: int) -> int:
        out = self.next
        self.next += 1
        self.elements.append((self.NAND, a, b, out))
        return out

    def encode(self) -> bytes:
        buf = bytearray()
        for op, *rest in self.elements:
            if op != self.NAND:
                raise ValueError(op)
            buf.append(self.NAND)
            a, b, _out = rest
            for x in (a, b):
                buf.extend([(x >> 16) & 255, (x >> 8) & 255, x & 255])
        return bytes(buf)


class RangeError(ValueError):
    pass


def ge(o: Netlist, a: int) -> int:
    return o.nand(a, a)


def ts(o: Netlist, a: int, b: int) -> int:
    return o.nand(ge(o, a), ge(o, b))


def half_add(o: Netlist, a: int, b: int) -> dict[str, int]:
    f = o.nand(a, b)
    h = o.nand(a, f)
    d = o.nand(b, f)
    s = o.nand(h, d)
    c = o.nand(f, f)
    return {"sum": s, "carry": c}


def full_add(o: Netlist, a: int, b: int, cin: int) -> dict[str, int]:
    h = half_add(o, a, b)
    d = half_add(o, h["sum"], cin)
    return {"sum": d["sum"], "carry": ts(o, h["carry"], d["carry"])}


def build_adder(width: int) -> tuple[Netlist, int, int, list[int]]:
    """Ripple-carry adder a[width]+b[width]+cin → sum[width]+cout (canvas mt)."""
    nl = Netlist(2 * width + 1)
    a = [nl.input(i) for i in range(width)]
    b = [nl.input(width + i) for i in range(width)]
    cin = nl.input(2 * width)
    sums: list[int] = []
    carry = cin
    for i in range(width):
        r = full_add(nl, a[i], b[i], carry)
        sums.append(r["sum"])
        carry = r["carry"]
    # Double-NOT buffer on each output (canvas burn pattern)
    outs = [ge(nl, ge(nl, x)) for x in [*sums, carry]]
    return nl, 2 * width + 1, width + 1, outs


def u256(n: int) -> bytes:
    return int(n).to_bytes(32, "big")


def encode_mint(token_id: int, amount: int) -> str:
    sel = bytes.fromhex("1b2ef1ca")  # mint(uint256,uint256)
    return "0x" + (sel + u256(token_id) + u256(amount)).hex()


def encode_tapeout(netlist: bytes, n_in: int, n_out: int) -> str:
    sel = bytes.fromhex("7bd3ac1d")  # tapeout(bytes,uint32,uint32)
    # head: offset(0x60), nIn, nOut, then bytes blob
    head = u256(0x60) + u256(n_in) + u256(n_out)
    blob = u256(len(netlist)) + netlist
    pad = (32 - (len(netlist) % 32)) % 32
    blob += b"\x00" * pad
    return "0x" + (sel + head + blob).hex()


def eval_adder_bits(width: int, a_val: int, b_val: int, cin: int = 0) -> dict:
    """Local NAND-netlist eval (levelized) for demo vectors."""
    nl, n_in, n_out, outs = build_adder(width)
    # signal values
    vals = {0: 0, 1: 1}
    for i in range(width):
        vals[2 + i] = (a_val >> i) & 1
        vals[2 + width + i] = (b_val >> i) & 1
    vals[2 + 2 * width] = cin & 1
    for _op, a, b, out in nl.elements:
        vals[out] = 1 - (vals[a] & vals[b])
    bits = [vals[o] for o in outs]
    got = 0
    for i, bit in enumerate(bits):
        got |= bit << i
    expect = (a_val + b_val + cin) & ((1 << (width + 1)) - 1)
    return {
        "a": a_val,
        "b": b_val,
        "cin": cin,
        "expect": expect,
        "got": got,
        "ok": got == expect,
        "sum_bits": bits,
    }


def main() -> None:
    width = 8
    nl, n_in, n_out, outs = build_adder(width)
    raw = nl.encode()
    n_nand = len(nl.elements)

    mint_price = 66_000_000_000_000  # 0.000066 OKB wei
    protocol_fee = 660_000_000_000_000  # 0.00066 OKB
    tapeout_fee = 1_300_000_000_000_000  # 0.0013 OKB
    mint_value = n_nand * mint_price + protocol_fee
    total_value = mint_value + tapeout_fee

    vectors = [
        eval_adder_bits(width, 100, 50, 0),  # canvas demo vt(8,100,50)
        eval_adder_bits(width, 255, 1, 0),
        eval_adder_bits(width, 0xA5, 0x5A, 1),
        eval_adder_bits(width, 0, 0, 0),
        eval_adder_bits(width, 128, 128, 0),
    ]
    assert all(v["ok"] for v in vectors), vectors

    mint_data = encode_mint(0, n_nand)  # NAND id=0
    tape_data = encode_tapeout(raw, n_in, n_out)

    receipt = {
        "schema": "tapeout_add8_weapon_pack/v1",
        "as_of": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "circuit": {
            "name": "ADD8",
            "op": "+",
            "N": width,
            "nIn": n_in,
            "nOut": n_out,
            "nNand": n_nand,
            "nLatch": 0,
            "netlist_hex": "0x" + raw.hex(),
            "netlist_bytes": len(raw),
            "netlist_sha256": hashlib.sha256(raw).hexdigest(),
            "outputs_signal_ids": outs,
            "labels": {
                "in": [*(f"a{i}" for i in range(width)), *(f"b{i}" for i in range(width)), "cin"],
                "out": [*(f"s{i}" for i in range(width)), "cout"],
            },
            "demo_vector": {"a": 100, "b": 50, "cin": 0, "expect": 150},
        },
        "processor": {
            "cpu": "0xa196ab8ef5ae052c13819e73f3cc3f4263faf744",
            "transistors": "0x37b97b180919bb40d8060f3497c9c243b9c1caf5",
            "factory": "0x1f09daefa827f02cbb40967cc91b259763760761",
            "chain_id": 196,
            "name": "LeoLabs Builder Desk",
            "symbol": "LEOLABS",
        },
        "fees_wei": {
            "mintPrice": mint_price,
            "protocolFee": protocol_fee,
            "TAPEOUT_FEE": tapeout_fee,
            "mint_tx_value": mint_value,
            "tapeout_tx_value": tapeout_fee,
            "total_value": total_value,
            "total_okb": total_value / 1e18,
            "approx_usd_at_122": round(total_value / 1e18 * 122, 4),
        },
        "calldata": {
            "mint_nand": {
                "to": "0x37b97b180919bb40d8060f3497c9c243b9c1caf5",
                "value_wei": str(mint_value),
                "data": mint_data,
            },
            "tapeout": {
                "to": "0xa196ab8ef5ae052c13819e73f3cc3f4263faf744",
                "value_wei": str(tapeout_fee),
                "data": tape_data,
            },
        },
        "eval_vectors": vectors,
        "why_competitive": [
            "Not a bare NAND — 8-bit ripple-carry adder (122 NAND), canvas-equivalent mt(Ue,8)",
            "Local eval suite passes 5 vectors including official demo 100+50=150",
            "Pairs with LeoLabs Builder Desk Processor already live on X Layer",
            "Cost ~0.010 OKB (~$1.2) — Cap $10 headroom after create remains >$8",
        ],
    }

    out_json = OUT / "add8-weapon-pack.json"
    out_hex = OUT / "add8-netlist.hex"
    out_json.write_text(json.dumps(receipt, indent=2) + "\n")
    out_hex.write_text("0x" + raw.hex() + "\n")
    print(json.dumps({
        "wrote": str(out_json),
        "nNand": n_nand,
        "nIn": n_in,
        "nOut": n_out,
        "bytes": len(raw),
        "total_okb": receipt["fees_wei"]["total_okb"],
        "eval_ok": all(v["ok"] for v in vectors),
    }, indent=2))


if __name__ == "__main__":
    main()

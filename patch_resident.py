#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Patch the GameLock program to read `update.PGL` from the memory card.

The stock loader looks for `update.PGL` on USB mass storage. It finds the device through
the `FCD USB-OHCI` driver of GameLock, which PCSX2 does not emulate. This script changes
where the file comes from, to `mc0:`, and changes nothing else. The AES decrypt, the ELF
parsing, the segment copy and the `ExecPS2` call all stay as the original vendor code.

The input is the decompressed program, based at 0x100000, not the compressed `BOOT.ELF`
from the memory card. The output is an ELF that you can pass to `pcsx2 -elf`.
"""

from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

BASE = 0x100000

# The sprintf format that builds the update path: "%s:\%s" with (device, "update.PGL").
# mc0 needs forward slashes. The replacement is the same length, so one byte changes.
FMT_ADDR = 0x126858
FMT_OLD = b"%s:\\%s"
FMT_NEW = b"%s:/%s"

# The screen that GameLock starts on. 0 is game_details. 7 is auto_update, the screen
# that runs the update code every frame. This change is a convenience, so that the update
# runs at startup and you do not navigate the menu.
SCREEN_ADDR = 0x12D10C
SCREEN_AUTO_UPDATE = 7

# FUN_00100c50(a0=&count, a1=namebuf, a2=max) normally sends a "UFS9999" devctl to list
# USB mass storage devices. This stub reports one device instead, named "mc0", so that
# the original path code builds "mc0:/update.PGL".
ENUM_ADDR = 0x100C50
ENUM_STUB = [
    0x3C020030,  # lui v0, 0x0030
    0x3442636D,  # ori v0, v0, 0x636d   -> 0x0030636d = 'm','c','0',0 little-endian
    0xACA20000,  # sw  v0, 0(a1)        -> namebuf[0] = "mc0"
    0x24020001,  # li  v0, 1
    0xAC820000,  # sw  v0, 0(a0)        -> *count = 1
    0x03E00008,  # jr  ra
    0x24020001,  # li  v0, 1            (delay slot) -> return 1
]

ENTRY = 0x1000E0


def patch(image: bytes, *, auto_update: bool = True) -> bytes:
    buf = bytearray(image)

    def w32(vaddr: int, value: int) -> None:
        struct.pack_into("<I", buf, vaddr - BASE, value)

    off = FMT_ADDR - BASE
    if buf[off:off + len(FMT_OLD)] != FMT_OLD:
        raise SystemExit(
            f"unexpected bytes at {FMT_ADDR:#x}: {bytes(buf[off:off + len(FMT_OLD)])!r} "
            f"(expected {FMT_OLD!r}). Is this the decompressed program, based at {BASE:#x}?"
        )
    buf[off:off + len(FMT_NEW)] = FMT_NEW

    if auto_update:
        current = struct.unpack_from("<I", buf, SCREEN_ADDR - BASE)[0]
        if current != 0:
            raise SystemExit(f"initial screen index at {SCREEN_ADDR:#x} is {current}, expected 0")
        w32(SCREEN_ADDR, SCREEN_AUTO_UPDATE)

    for i, insn in enumerate(ENUM_STUB):
        w32(ENUM_ADDR + i * 4, insn)

    return bytes(buf)


def wrap_elf(body: bytes, base: int = BASE, entry: int = ENTRY, bss: int = 0x200000) -> bytes:
    """Wrap a raw memory image in a small ELF32 little-endian MIPS executable."""
    eh = (
        b"\x7fELF"
        + bytes([1, 1, 1, 0])
        + bytes(8)
        + struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, entry, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    )
    ph = struct.pack("<8I", 1, 0x1000, base, base, len(body), len(body) + bss, 7, 0x1000)
    return eh + ph + bytes(0x1000 - len(eh) - len(ph)) + body


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("program", help="decompressed GameLock program, raw, based at 0x100000")
    ap.add_argument("output", help="the patched ELF to write")
    ap.add_argument(
        "--no-auto-update",
        action="store_true",
        help="keep the normal start screen. Navigate to the Update screen yourself.",
    )
    ap.add_argument("--raw", action="store_true", help="write a raw image instead of an ELF")
    args = ap.parse_args(argv)

    image = Path(args.program).read_bytes()
    patched = patch(image, auto_update=not args.no_auto_update)
    out = Path(args.output)
    out.write_bytes(patched if args.raw else wrap_elf(patched))
    print(f"{args.program} -> {out} ({out.stat().st_size} bytes)")
    print("place update.PGL in the memory card root, then: pcsx2 -elf", out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

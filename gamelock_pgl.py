#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["cryptography>=3.0"]
# ///
"""Build and inspect `update.PGL` payloads for Xploder Parental GameLock (PS2).

The GameLock update channel is a loader that checks no signature. The program on the
memory card reads `update.PGL` and decrypts it with AES-128-ECB. If the result starts
with `\\x7fELF`, the loader reads the program headers and jumps to the entry point with
`ExecPS2`.

The AES key is the MD5 hash of the GameLock password. GameLock stores the same 16 bytes
at offset 0x10 of `Config.PGL` on the memory card. Nothing signs the payload, so the
password alone is enough to run any program.

README.md describes the format.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- limits that the device imposes ---------------------------------------------------
# The keyboard buffer holds 16 bytes. GameLock rejects entries shorter than 5 characters
# with the message "Password too short".

PASSWORD_MIN = 5
PASSWORD_MAX = 16

# The loader rejects a size of 0, and any size over 0x500000.
MAX_PAYLOAD = 0x500000
BLOCK = 16

# --- memory map of the GameLock program (BOOT.ELF, decompressed, loaded at 0x100000) --
RESIDENT_BASE = 0x100000
RESIDENT_IMAGE_END = 0x15EA0C  # end of its code and data
RESIDENT_BSS_END = 0x272AE8  # end of the memory its startup code clears
LOADER_ADDR = 0x1193F8  # the ELF loader itself

# The loader copies PT_LOAD segments while it runs. Everything it still needs after the
# copy must survive: the loader, the memory-copy helpers, the IOP shutdown calls,
# FlushCache (0x121EB0) and _ExecPS2 (0x121E00). An overlap with this window is fatal.
#
# An overlap with the rest of the program is not fatal. A test loaded the GameLock program
# itself, a full 0x100000-0x35EA0C segment, over the running copy. It replaced live code,
# including the stub at 0x100C50, and still reached ExecPS2 and booted.
CRITICAL_START = 0x119000
CRITICAL_END = 0x124000

PT_LOAD = 1


class GameLockError(Exception):
    """Raised for bad input, or for a payload that the device rejects."""


# --- crypto ---------------------------------------------------------------------------

def derive_key(password: str) -> bytes:
    """Return the AES-128 key for `password`, which is the MD5 hash of its ASCII bytes.

    GameLock stores the same 16 bytes at Config.PGL+0x10. It compares them with memcmp
    when you type the password.
    """
    validate_password(password)
    return hashlib.md5(password.encode("ascii")).digest()


def validate_password(password: str) -> None:
    try:
        raw = password.encode("ascii")
    except UnicodeEncodeError as exc:
        raise GameLockError("password must be ASCII. The on-screen keyboard cannot type anything else.") from exc
    if not (PASSWORD_MIN <= len(raw) <= PASSWORD_MAX):
        raise GameLockError(
            f"password must be {PASSWORD_MIN}-{PASSWORD_MAX} characters (got {len(raw)})"
        )
    bad = sorted({c for c in password if not (0x20 <= ord(c) <= 0x7E)})
    if bad:
        raise GameLockError(f"password contains characters the keyboard cannot type: {bad!r}")


def _cipher(key: bytes) -> Cipher:
    return Cipher(algorithms.AES(key), modes.ECB())


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt with AES-128-ECB, padded with zeros to a block boundary.

    The loader rounds the file size up to 16 bytes and decrypts that many bytes. It reads
    only the real file length from the card. A short final block therefore decrypts
    uninitialized memory.
    """
    padded = plaintext + b"\0" * (-len(plaintext) % BLOCK)
    return _cipher(key).encryptor().update(padded)


def decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(ciphertext) % BLOCK:
        raise GameLockError(f"ciphertext is not a multiple of {BLOCK} bytes")
    return _cipher(key).decryptor().update(ciphertext)


# --- ELF inspection -------------------------------------------------------------------

@dataclass
class Segment:
    type: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int

    @property
    def end(self) -> int:
        return self.vaddr + self.memsz


@dataclass
class ElfInfo:
    entry: int
    segments: list[Segment] = field(default_factory=list)

    @property
    def loads(self) -> list[Segment]:
        return [s for s in self.segments if s.type == PT_LOAD]


def parse_elf(data: bytes) -> ElfInfo:
    """Read the parts of an ELF32 little-endian header that a PS2 payload needs."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise GameLockError("not an ELF file (bad magic)")
    if data[4] != 1:
        raise GameLockError("not ELF32. The PS2 loader handles 32-bit files only.")
    if data[5] != 1:
        raise GameLockError("not little-endian")
    e_machine, = struct.unpack_from("<H", data, 18)
    if e_machine != 8:  # EM_MIPS
        raise GameLockError(f"not a MIPS ELF (e_machine={e_machine})")
    entry, phoff = struct.unpack_from("<II", data, 24)
    phentsize, phnum = struct.unpack_from("<HH", data, 42)
    if phentsize != 32:
        raise GameLockError(f"unexpected program header size {phentsize}")
    segs = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + 32 > len(data):
            raise GameLockError("program header table runs past end of file")
        p_type, p_offset, p_vaddr, _p_paddr, p_filesz, p_memsz = struct.unpack_from("<6I", data, off)
        segs.append(Segment(p_type, p_offset, p_vaddr, p_filesz, p_memsz))
    return ElfInfo(entry=entry, segments=segs)


def _overlaps(a0: int, a1: int, b0: int, b1: int) -> bool:
    return a0 < b1 and b0 < a1


def check_payload(data: bytes) -> list[tuple[str, str]]:
    """Return a list of (level, message), where level is 'error' or 'warning'."""
    out: list[tuple[str, str]] = []
    info = parse_elf(data)

    padded = len(data) + (-len(data) % BLOCK)
    if padded == 0:
        out.append(("error", "payload is empty"))
    if padded > MAX_PAYLOAD:
        out.append(("error", f"payload is {padded:#x} bytes. The loader rejects anything over {MAX_PAYLOAD:#x}."))

    loads = info.loads
    if not loads:
        out.append(("error", "no PT_LOAD segments, so the loader copies nothing"))
        return out

    # An entry point outside every loaded, file-backed range is the most common mistake.
    # The console then starts running whatever sits at that address.
    if not any(s.vaddr <= info.entry < s.vaddr + s.filesz for s in loads):
        out.append((
            "error",
            f"entry point {info.entry:#x} is not inside any file-backed PT_LOAD range "
            + ", ".join(f"[{s.vaddr:#x},{s.vaddr + s.filesz:#x})" for s in loads),
        ))

    for s in loads:
        if _overlaps(s.vaddr, s.end, CRITICAL_START, CRITICAL_END):
            out.append((
                "error",
                f"segment [{s.vaddr:#x},{s.end:#x}) overlaps [{CRITICAL_START:#x},"
                f"{CRITICAL_END:#x}). That range holds the loader, its memory-copy "
                "helpers and ExecPS2. The copy destroys the code that performs it.",
            ))
        elif _overlaps(s.vaddr, s.end, RESIDENT_BASE, RESIDENT_BSS_END):
            out.append((
                "warning",
                f"segment [{s.vaddr:#x},{s.end:#x}) overlaps the GameLock program "
                f"[{RESIDENT_BASE:#x},{RESIDENT_BSS_END:#x}) outside the critical window. "
                "This works in testing, but it overwrites a running program.",
            ))
    return out


# --- commands -------------------------------------------------------------------------

def _report(problems: list[tuple[str, str]]) -> int:
    sys.stdout.flush()  # keep diagnostics below the summary they refer to
    for level, msg in problems:
        print(f"  {level}: {msg}", file=sys.stderr)
    return sum(1 for level, _ in problems if level == "error")


def cmd_pack(args: argparse.Namespace) -> int:
    payload = Path(args.elf).read_bytes()
    problems = check_payload(payload)
    if problems:
        print(f"{args.elf}:", file=sys.stderr)
        errors = _report(problems)
        if errors and not args.force:
            print("refusing to pack; re-run with --force to override", file=sys.stderr)
            return 1
    key = derive_key(args.password)
    out = Path(args.output)
    out.write_bytes(encrypt(payload, key))
    print(f"{args.elf} -> {out}  ({out.stat().st_size} bytes, key {key.hex()})")
    print("copy it to the memory card as update.PGL")
    return 0


def cmd_unpack(args: argparse.Namespace) -> int:
    key = derive_key(args.password)
    plain = decrypt(Path(args.pgl).read_bytes(), key)
    if plain[:4] != b"\x7fELF":
        print(
            f"warning: plaintext does not start with \\x7fELF (got {plain[:4]!r}). "
            "Wrong password, or this is a database update rather than an ELF.",
            file=sys.stderr,
        )
    Path(args.output).write_bytes(plain)
    print(f"{args.pgl} -> {args.output}  ({len(plain)} bytes, key {key.hex()})")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    data = Path(args.elf).read_bytes()
    info = parse_elf(data)
    print(f"{args.elf}: {len(data)} bytes, entry {info.entry:#x}")
    for s in info.segments:
        kind = "LOAD" if s.type == PT_LOAD else f"type{s.type}"
        print(f"  {kind:6} vaddr {s.vaddr:#010x} filesz {s.filesz:#x} memsz {s.memsz:#x}")
    problems = check_payload(data)
    if not problems:
        print("  looks loadable")
        return 0
    return 1 if _report(problems) else 0


def cmd_key(args: argparse.Namespace) -> int:
    print(derive_key(args.password).hex())
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("pack", help="encrypt an ELF into update.PGL")
    p.add_argument("elf")
    p.add_argument("output")
    p.add_argument("-p", "--password", required=True)
    p.add_argument("--force", action="store_true", help="pack even if validation fails")
    p.set_defaults(func=cmd_pack)

    p = sub.add_parser("unpack", help="decrypt an update.PGL back to an ELF")
    p.add_argument("pgl")
    p.add_argument("output")
    p.add_argument("-p", "--password", required=True)
    p.set_defaults(func=cmd_unpack)

    p = sub.add_parser("info", help="check whether an ELF is loadable by GameLock")
    p.add_argument("elf")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("key", help="print the AES key (MD5) for a password")
    p.add_argument("password")
    p.set_defaults(func=cmd_key)

    args = ap.parse_args(argv)
    try:
        return args.func(args)
    except GameLockError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"error: {exc.filename or ''}: {exc.strerror or exc}".strip(": "), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

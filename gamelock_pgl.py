#!/usr/bin/env python3
"""Build and inspect `update.PGL` payloads for Xploder Parental GameLock (PS2).

Parental GameLock's firmware-update channel is an unsigned ELF loader. The resident
program reads `update.PGL`, decrypts it with AES-128-ECB, and if the plaintext starts
with `\\x7fELF` it loads the program headers and jumps to the entry point via `ExecPS2`.

The AES key is the MD5 of the installation's own password — the same 16 bytes stored at
offset 0x10 of `Config.PGL` on the memory card. There is no signature on the payload, so
knowing the password is sufficient to run arbitrary code.

See README.md for the reverse-engineering details.
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# --- device-imposed limits ------------------------------------------------------------
# The on-screen keyboard buffer is 16 bytes, with a NUL written at index 16, and entries
# shorter than 5 characters are rejected with "Password too short".
PASSWORD_MIN = 5
PASSWORD_MAX = 16

# The loader refuses sizes of 0 or > 0x500000 before allocating.
MAX_PAYLOAD = 0x500000
BLOCK = 16

# --- resident memory map (unpacked BOOT.ELF, loaded at 0x100000) ----------------------
RESIDENT_BASE = 0x100000
RESIDENT_IMAGE_END = 0x15EA0C  # code + data of the unpacked resident
RESIDENT_BSS_END = 0x272AE8  # cleared by the resident's own startup
LOADER_ADDR = 0x1193F8  # FUN_001193f8, the ELF loader itself

# The loader copies PT_LOAD segments while executing, so anything it still needs after the
# copy must survive it: the loader, the memcpy/memset helpers, the IOP teardown calls,
# FlushCache (0x121EB0) and _ExecPS2 (0x121E00). Overlapping *this* window is fatal.
#
# Overlapping the rest of the resident is not. Demonstrated: loading GameLock's own
# unpacked resident (a full 0x100000-0x35EA0C segment) over the running patched copy
# replaced live code mid-run — including the patched device-enumeration stub at
# 0x100C50 — and still reached ExecPS2 and booted the payload. Only a narrow window
# genuinely matters.
CRITICAL_START = 0x119000
CRITICAL_END = 0x124000

PT_LOAD = 1


class GameLockError(Exception):
    """Raised for malformed input or a payload the device would reject."""


# --- crypto ---------------------------------------------------------------------------

def derive_key(password: str) -> bytes:
    """Return the AES-128 key for `password`: the raw MD5 of its ASCII bytes.

    This is byte-identical to the digest the device stores at Config.PGL+0x10 and
    compares against with memcmp when you type the password in.
    """
    validate_password(password)
    return hashlib.md5(password.encode("ascii")).digest()


def validate_password(password: str) -> None:
    try:
        raw = password.encode("ascii")
    except UnicodeEncodeError as exc:
        raise GameLockError("password must be ASCII; the on-screen keyboard cannot type anything else") from exc
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
    """AES-128-ECB encrypt, zero-padded up to a block boundary.

    Padding matters: the loader rounds the file size up to 16 and decrypts that many
    bytes, but only reads the real file length off the card. A short final block would
    decrypt uninitialised heap.
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
    """Parse just enough ELF32-LE to validate a PS2 payload."""
    if len(data) < 52 or data[:4] != b"\x7fELF":
        raise GameLockError("not an ELF file (bad magic)")
    if data[4] != 1:
        raise GameLockError("not ELF32 — the PS2 EE loader only handles 32-bit")
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
    """Return [(level, message)] where level is 'error' or 'warning'.

    These are the conditions that actually bite in practice, each learned the hard way.
    """
    out: list[tuple[str, str]] = []
    info = parse_elf(data)

    padded = len(data) + (-len(data) % BLOCK)
    if padded == 0:
        out.append(("error", "payload is empty"))
    if padded > MAX_PAYLOAD:
        out.append(("error", f"payload is {padded:#x} bytes; loader rejects anything over {MAX_PAYLOAD:#x}"))

    loads = info.loads
    if not loads:
        out.append(("error", "no PT_LOAD segments — nothing would be copied"))
        return out

    # The single most common self-inflicted failure: an entry point that is not inside
    # any loaded, file-backed range. Execution starts on whatever happens to be there.
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
                f"{CRITICAL_END:#x}), which holds the loader, its memcpy/memset helpers "
                "and ExecPS2; overwriting those mid-copy is fatal",
            ))
        elif _overlaps(s.vaddr, s.end, RESIDENT_BASE, RESIDENT_BSS_END):
            out.append((
                "warning",
                f"segment [{s.vaddr:#x},{s.end:#x}) overlaps the resident "
                f"[{RESIDENT_BASE:#x},{RESIDENT_BSS_END:#x}) outside the critical window; "
                "observed to work, but you are overwriting a running program",
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

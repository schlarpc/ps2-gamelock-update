"""Tests for the update.PGL packer.

The key vector is pinned against a value confirmed on the real cipher: the resident's own
AES routine was driven under emulation and matched a reference implementation byte-exactly.
"""

import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import gamelock_pgl as g


def make_elf(entry=0x400000, vaddr=0x400000, body=b"\x00" * 32, memsz_extra=0):
    eh = (
        b"\x7fELF"
        + bytes([1, 1, 1, 0])
        + bytes(8)
        + struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, entry, 52, 0, 0, 52, 32, 1, 0, 0, 0)
    )
    ph = struct.pack("<8I", g.PT_LOAD, 0x80, vaddr, vaddr, len(body), len(body) + memsz_extra, 7, 0x10)
    return eh + ph + bytes(0x80 - len(eh) - len(ph)) + body


def errors(data):
    return [m for lvl, m in g.check_payload(data) if lvl == "error"]


# --- crypto ---------------------------------------------------------------------------

def test_key_matches_confirmed_vector():
    assert g.derive_key("letmein").hex() == "0d107d09f5bbe40cade3de5c71e9e9b7"


def test_roundtrip():
    key = g.derive_key("letmein")
    elf = make_elf()
    assert g.decrypt(g.encrypt(elf, key), key)[: len(elf)] == elf


def test_payload_is_block_aligned():
    key = g.derive_key("hunter2")
    assert len(g.encrypt(b"x" * 17, key)) == 32


def test_wrong_password_does_not_recover_elf():
    elf = make_elf()
    blob = g.encrypt(elf, g.derive_key("letmein"))
    assert g.decrypt(blob, g.derive_key("letmeout"))[:4] != b"\x7fELF"


# --- password rules -------------------------------------------------------------------

@pytest.mark.parametrize("pw", ["abcd", "a" * 17, "nul\0byte", "café!"])
def test_rejects_bad_passwords(pw):
    with pytest.raises(g.GameLockError):
        g.derive_key(pw)


@pytest.mark.parametrize("pw", ["abcde", "a" * 16, "p@ss w0rd!"])
def test_accepts_valid_passwords(pw):
    assert len(g.derive_key(pw)) == 16


# --- ELF validation -------------------------------------------------------------------

def test_accepts_well_formed_payload():
    assert g.check_payload(make_elf()) == []


def test_rejects_entry_outside_load():
    # The exact mistake that produced a black screen and a TLB miss at 0x400080.
    problems = errors(make_elf(entry=0x400080, vaddr=0x400000, body=b"\x00" * 16))
    assert any("entry point" in m for m in problems)


def test_rejects_overlap_with_the_critical_window():
    problems = errors(make_elf(entry=g.LOADER_ADDR, vaddr=g.LOADER_ADDR))
    assert any("fatal" in m for m in problems)


def test_resident_overlap_outside_critical_window_is_only_a_warning():
    # Demonstrated on hardware-equivalent emulation: loading GameLock's own resident over
    # itself replaced live code (including the stub at 0x100C50) and still booted.
    low = make_elf(entry=0x100100, vaddr=0x100000, body=b"\x00" * 0x1000)
    assert errors(low) == []
    assert any(lvl == "warning" for lvl, _ in g.check_payload(low))


def test_warns_on_bss_overlap():
    assert any(lvl == "warning" for lvl, _ in g.check_payload(make_elf(entry=0x200000, vaddr=0x200000)))
    assert not errors(make_elf(entry=0x200000, vaddr=0x200000))


def test_rejects_oversized_payload():
    big = make_elf(body=b"\x00" * (g.MAX_PAYLOAD + 1))
    assert any("over" in m for m in errors(big))


def test_rejects_non_elf():
    with pytest.raises(g.GameLockError):
        g.parse_elf(b"not an elf at all, really")


def test_rejects_wrong_architecture():
    elf = bytearray(make_elf())
    struct.pack_into("<H", elf, 18, 62)  # EM_X86_64
    with pytest.raises(g.GameLockError):
        g.parse_elf(bytes(elf))


def test_uLaunchELF_style_high_load_is_clean():
    # uLaunchELF links at 0x01CB8190, clear of the resident; this must pass unflagged.
    assert g.check_payload(make_elf(entry=0x01D0001C, vaddr=0x01CB8190, body=b"\x00" * 0x4A984)) == []

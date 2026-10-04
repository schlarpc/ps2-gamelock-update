# ps2-gamelock-update

Tooling for the firmware-update channel in **Xploder Parental GameLock** (PlayStation 2,
Fire International / Blaze, 2007).

GameLock's updater is an **unsigned ELF loader**. The resident program reads a file called
`update.PGL`, decrypts it with AES-128-ECB, and if the plaintext begins with `\x7fELF` it
loads the program headers and jumps to the entry point via `ExecPS2`. The AES key is the
MD5 of the installation's own password. There is no signature on the payload, so anyone who
knows the password can run arbitrary code on the console.

This repo packs payloads for that channel, and includes a small patch that makes the update
path reachable under PCSX2.

## The format

`update.PGL` is just `AES-128-ECB(payload, key = MD5(password))`. No header, no IV, no MAC.

The same 16-byte digest is stored at offset `0x10` of `Config.PGL` on the memory card, where
it doubles as the password verifier — the device hashes what you type and `memcmp`s it. So
the key material for the update channel is exactly the password check, reused.

The loader accepts two payload shapes:

| plaintext starts with | size | treated as |
|---|---|---|
| `\x7fELF` | any | ELF executable — loaded and run |
| `E\xCC` | exactly `0xEE50` | packed database update (the `.PGL` game/rating tables) |

## Usage

```sh
# what key does a password produce?
./gamelock_pgl.py key letmein
# 0d107d09f5bbe40cade3de5c71e9e9b7

# will this ELF actually load? (checks entry point, load addresses, size)
./gamelock_pgl.py info BOOT.ELF

# build the payload
./gamelock_pgl.py pack BOOT.ELF update.PGL -p letmein

# decrypt one back, e.g. a genuine vendor update if one ever surfaces
./gamelock_pgl.py unpack update.PGL recovered.elf -p letmein
```

Copy `update.PGL` to the memory card (root, or the USB stick root on real hardware) and
trigger the update from GameLock's menu.

### Constraints the tool checks for you

- **Password**: 5–16 printable ASCII characters. The on-screen keyboard is a standard US
  layout in both cases; the buffer is 16 bytes with a NUL written at index 16, and anything
  shorter than 5 is rejected with *"Password too short"*.
- **Size**: the loader refuses an empty payload or anything over `0x500000` (5 MB), measured
  after rounding up to a 16-byte block.
- **Entry point** must lie inside a file-backed `PT_LOAD` range. Getting this wrong is the
  easiest way to waste an afternoon: the loader faithfully jumps to whatever you declared,
  and you get a black screen with a TLB miss at your own entry address.
- **Load address** must avoid `0x119000`–`0x124000`. The loader copies segments *while it is
  executing*, so the loader itself, its memcpy/memset helpers, `FlushCache` and `ExecPS2`
  all have to survive the copy. Overlapping that window is fatal; overlapping the rest of
  the resident is only a warning, and is demonstrably survivable — see below.

  In practice this almost never bites, because released PS2 homebrew ships ps2-packer'd and
  therefore links high (OPL `0x01BDD650`, PS2Ident `0x01C90F00`, uLaunchELF `0x01CB8190`).
  If you build your own, either link above the resident or pack it.

Payloads are zero-padded to a 16-byte boundary. This matters: the loader rounds the file
size up to a block and decrypts that far, but only reads the real length off the card, so a
short final block would decrypt uninitialised heap.

### Footgun: nothing consumes `update.PGL`

The loader does not delete the file, mark it consumed, or version-check it. It reads,
decrypts, loads and jumps — and that is all. So a payload that itself re-enters the update
path boots forever: load, exec, repeat, with no way out but removing the memory card.

Packing the *patched* resident from `patch_resident.py` does exactly this, since it starts
on the Update screen and reads from `mc0:`. Packing the *unpatched* resident is harmless and
simply boots GameLock normally — it starts on the main screen and looks for USB.

`argv[0]` is passed to your payload as the literal string `"update.PGL"`, not a full path.
Programs that derive config paths from `argv[0]` (uLaunchELF does) will look in odd places.

## Running it under PCSX2

The stock loader enumerates USB mass storage through GameLock's own `FCD USB-OHCI` driver,
which PCSX2 does not emulate, so the update path is unreachable as shipped.
`patch_resident.py` redirects the file source to `mc0:` and nothing else:

| addr | change | why |
|---|---|---|
| `0x12685B` | `\` → `/` (1 byte) | `"%s:\%s"` → `"%s:/%s"`; mc0 wants forward slashes |
| `0x100C50` | 7-instruction stub | device enumeration reports one device named `"mc0"` |
| `0x12D10C` | `0` → `7` (4 bytes) | boot straight to the Update screen (convenience only) |

```sh
./patch_resident.py boot_unpacked.bin gamelock_patched.elf
pcsx2 -elf gamelock_patched.elf
```

The decrypt, ELF parse, segment copy and `ExecPS2` handover are **untouched vendor code** —
only the path the file comes from changes.

`boot_unpacked.bin` is the resident `BOOT.ELF` after ps2-packer decompression, based at
`0x100000`. The copy on the memory card is packed; unpack it first (emulating the stub is
easier than reimplementing the decompressor).

You also need a memory card image with a GameLock installation on it — at minimum
`BAEXEC-SYSTEM/Config.PGL`, whose MD5 field must match the password you packed with.
[`mymcplus`](https://github.com/thestr4ng3r/mymcplus) builds one.

## Verified

End to end under PCSX2 2.6.3: uLaunchELF (305 KB) packed with this tool, placed on the
memory card, booted by GameLock's own loader — module loads, pad init, `PS2KBD - USB
Keyboard Library`. The AES implementation was confirmed byte-exact against the resident's
own cipher routine, driven under emulation.

## Notes

- This is for a discontinued 2007 accessory on a console that left production in 2013. The
  "parental control" it enforces is a game-rating lock whose config and enforcement binary
  both live on a removable memory card.
- The `osdmain.elf` system update GameLock installs *is* signed (a KELF, signed with
  console-derived MagicGate key material). The `update.PGL` channel documented here is not.
  They are different mechanisms; only the latter is an open door.

## License

MIT.

## Tested payloads

All packed with this tool and booted by GameLock's own loader under PCSX2 2.6.3.

| payload | load addr | verdict | result |
|---|---|---|---|
| uLaunchELF `BOOT-DS34-NO_NETWORK` | `0x01CB8190` | loadable | boots |
| Open PS2 Loader v1.1.0 | `0x01BDD650` | loadable | boots |
| PS2Ident | `0x01C90F00` | loadable | not booted yet |
| uLaunchELF `BOOT-EXFAT-DS34-MMCE` | `0x01CA33D0` | loadable | not booted yet |
| GameLock's own unpacked resident | `0x00100000` | warning | boots (see below) |

The last row is the interesting one. It overlaps the resident across its whole range and
still works: the copy replaced live code mid-run — including the patched enumeration stub at
`0x100C50` — reached `ExecPS2`, and re-executed. Confirmed from the log rather than by eye,
since GameLock's entire startup (`FCD USB-OHCI`, `Config.PGL`, `G.PGL`, `NTSC version`)
appears once before the soft reboot and once after, while `mc0:/update.PGL` is opened twice
before and **zero** times after — the payload is the unpatched build, which looks for USB.

That is why the critical window is `0x119000`–`0x124000` and not the whole resident.

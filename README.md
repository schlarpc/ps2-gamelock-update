# ps2-gamelock-update

Tools for the update channel in Xploder Parental GameLock, a PlayStation 2 parental-control
accessory from 2007.

GameLock updates itself through a loader that checks no signature. The program on the memory
card reads a file named `update.PGL` and decrypts it with AES-128-ECB. If the result starts
with `\x7fELF`, the loader runs it as a program. (ELF is the executable file format of the
PlayStation 2.) The AES key is the MD5 hash of the password you set in GameLock. Nothing
signs the payload, so anyone who knows the password can run any program on the console.

This repository packs payloads for that channel. It also includes a patch that makes the
update path work under PCSX2, a PlayStation 2 emulator.

## The format

`update.PGL` is `AES-128-ECB(payload, key = MD5(password))`. It has no header, no IV, and no
MAC.

GameLock stores the same 16 bytes at offset `0x10` of `Config.PGL` on the memory card. It
hashes the password you type and compares the two values with `memcmp`. The update key and
the password check are therefore the same value.

The loader accepts two kinds of payload:

| The plaintext starts with | Size | The loader treats it as |
|---|---|---|
| `\x7fELF` | Any | A program, which it loads and runs |
| `E\xCC` | Exactly `0xEE50` | A database update for the game and rating tables |

## Usage

```sh
# Print the AES key for a password.
./gamelock_pgl.py key letmein
# 0d107d09f5bbe40cade3de5c71e9e9b7

# Make sure that an ELF can load: entry point, load addresses, size.
./gamelock_pgl.py info BOOT.ELF

# Build the payload.
./gamelock_pgl.py pack BOOT.ELF update.PGL -p letmein

# Decrypt a payload back into an ELF.
./gamelock_pgl.py unpack update.PGL recovered.elf -p letmein
```

The scripts carry PEP 723 metadata, so `uv run gamelock_pgl.py ...` installs
`cryptography` for you. To install it yourself instead, run `pip install cryptography`.

Copy `update.PGL` to the root of the memory card. On real hardware, copy it to the root of
the USB stick. Then start the update from the GameLock menu.

### What the tool makes sure of

- **Password**: 5 to 16 printable ASCII characters. GameLock rejects anything shorter than 5
  characters with the message "Password too short".
- **Size**: the loader rejects an empty payload, and any payload over `0x500000` (5 MB).
- **Entry point**: it must sit inside a `PT_LOAD` range that the file backs. If it does not,
  the loader jumps to the address you declared and the console shows a black screen.
- **Load address**: it must avoid `0x119000` to `0x124000`. The loader copies segments while
  it runs, so the loader, its memory-copy helpers, `FlushCache` and `ExecPS2` must survive
  the copy. An overlap with the rest of the program is only a warning.

Released PlayStation 2 homebrew is compressed with ps2-packer and loads high, so the load
address rarely matters. OPL loads at `0x01BDD650`, PS2Ident at `0x01C90F00`, and uLaunchELF
at `0x01CB8190`. If you build your own program, link it above `0x400000` or compress it.

GameLock passes `argv[0]` to your program as the text `update.PGL`, not as a full path. A
program that builds a configuration path from `argv[0]` looks in the wrong place. uLaunchELF
does this.

## Running it under PCSX2

The stock loader reads `update.PGL` from USB through the `FCD USB-OHCI` driver of GameLock.
PCSX2 does not emulate that driver, so the update path does not work. `patch_resident.py`
changes where the file comes from, and changes nothing else.

| Address | Change | Reason |
|---|---|---|
| `0x12685B` | `\` becomes `/`, 1 byte | `"%s:\%s"` becomes `"%s:/%s"`. `mc0` needs forward slashes. |
| `0x100C50` | 7-instruction stub | The device list reports one device, named `mc0`. |
| `0x12D10C` | `0` becomes `7`, 4 bytes | GameLock starts on the Update screen. |

```sh
./patch_resident.py boot_unpacked.bin gamelock_patched.elf
pcsx2 -elf gamelock_patched.elf
```

The decrypt, the ELF parsing, the segment copy and the `ExecPS2` call all stay as the
original vendor code.

`boot_unpacked.bin` is the `BOOT.ELF` from the memory card after you decompress it. The copy
on the card is compressed with ps2-packer.

You also need a memory card image that holds a GameLock installation. It must contain at
least `BAEXEC-SYSTEM/Config.PGL`, and the MD5 field in that file must match the password you
pack with. [`mymcplus`](https://github.com/thestr4ng3r/mymcplus) builds the image.

## Tested payloads

The GameLock loader booted these under PCSX2 2.6.3. The AES code in this tool matches the
cipher inside GameLock byte for byte, tested under emulation.

| Payload | Load address | Result |
|---|---|---|
| uLaunchELF `BOOT-DS34-NO_NETWORK` | `0x01CB8190` | Boots |
| Open PS2 Loader v1.1.0 | `0x01BDD650` | Boots |
| The GameLock program itself, decompressed | `0x00100000` | Boots |
| PS2Ident | `0x01C90F00` | Not tested |
| uLaunchELF `BOOT-EXFAT-DS34-MMCE` | `0x01CA33D0` | Not tested |

The third row overlaps the running program across its whole range and still works. The copy
replaced live code and still reached `ExecPS2`. This is the reason the critical window is
`0x119000` to `0x124000` and not the whole program.

## Notes

GameLock is a discontinued accessory for a console that left production in 2013. It blocks
games by age rating. Both its configuration and the program that enforces the lock sit on a
removable memory card.

The `osdmain.elf` system update that GameLock installs is signed. It is a KELF, signed with
key material from the console. The `update.PGL` channel in this document is not signed. The
two are separate mechanisms.

## License

MIT.

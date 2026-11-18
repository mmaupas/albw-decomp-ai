"""Build the synthetic decrypted USA ALBW .3ds that Zakuro runs for coverage.

  python tools/synth_rom.py [--eu-rom PATH] [--code PATH] [--out PATH]

Why this exists: Zakuro needs a full decrypted .3ds (NCSD -> NCCH -> ExeFS +
RomFS). This machine has no USA ROM dump — only `code.bin` (the USA ExeFS
.code, user-supplied, gitignored) and the wrong-region EU cart in logs/rom/.
The EU cart is already decrypted and carries the same game build: its ExeFS
`.code` entry is exactly 0x628000 bytes, the size of code.bin, and its
NCCH/ExHeader describe the same segment layout (text 0x00100000, rodata
0x00693000, data 0x006FF000).

So the synthetic ROM is the EU cart copied, with:
  - ExeFS .code        <- code.bin            (the USA code under test)
  - NCCH/ACI program_id, partition_id, jump_id <- USA title id 0004000000C30E00
  - product_code       <- CTR-P-BZLE          (region USA per zakuro's cfg)
  - everything else (ExHeader, RomFS, banner, icon) unchanged

The RomFS therefore stays the EU one (same file layout; only localized text
differs), which is fine for *code* coverage: which functions execute is
driven by the USA .code, not by asset bytes. The result is scratch
(gitignored): it is an emulator input, never committed — same rule as
code.bin itself. Never extract code.bin from rom/; this script does the
opposite (puts the USA code.bin into a container).

Output default: ~/zakuro-work/albw-usa-synth.3ds
"""
import argparse
import hashlib
import os
import shutil
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import ROOT

USA_TITLE_ID = 0x0004000000C30E00  # 00040000-00C30E00 (EU cart in logs/rom is ...-000EC400)
USA_PRODUCT_CODE = b"CTR-P-BZLE"
MEDIA_UNIT = 0x200


def find_eu_rom(args_rom):
    if args_rom:
        return args_rom
    import glob
    hits = sorted(glob.glob(os.path.join(ROOT, "logs", "rom", "*.3ds")))
    if hits:
        return hits[0]
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--eu-rom")
    ap.add_argument("--code", default=os.path.join(ROOT, "code.bin"))
    ap.add_argument("--out", default=os.path.expanduser("~/zakuro-work/albw-usa-synth.3ds"))
    ap.add_argument("--keep-ids", action="store_true",
                    help="leave the EU program_id/product_code in place (only swap .code)")
    args = ap.parse_args()

    eu = find_eu_rom(args.eu_rom)
    if not eu or not os.path.exists(eu):
        print("no EU container ROM found; pass --eu-rom PATH", file=sys.stderr)
        return 2
    if not os.path.exists(args.code):
        print("no code.bin at %s" % args.code, file=sys.stderr)
        return 2

    code = open(args.code, "rb").read()
    print("code.bin: %s (%d bytes, sha1 %s)" % (args.code, len(code),
          hashlib.sha1(code).hexdigest()[:12]))

    with open(eu, "rb") as f:
        ncsd_head = f.read(0x200)
        if ncsd_head[0x100:0x104] != b"NCSD":
            print("%s is not an NCSD image" % eu, file=sys.stderr)
            return 2
        part0_off = struct.unpack_from("<I", ncsd_head, 0x120)[0] * MEDIA_UNIT
        f.seek(part0_off)
        ncch = bytearray(f.read(0x200))
        if ncch[0x100:0x104] != b"NCCH":
            print("partition 0 of %s is not NCCH" % eu, file=sys.stderr)
            return 2
        exefs_off = struct.unpack_from("<I", ncch, 0x1A0)[0] * MEDIA_UNIT
        f.seek(part0_off + exefs_off)
        exefs = f.read(0x200)

    # locate the .code entry in the ExeFS header
    code_entry = None
    for i in range(10):
        name = exefs[i * 0x10:i * 0x10 + 8].split(b"\0")[0]
        off, size = struct.unpack_from("<II", exefs, i * 0x10 + 8)
        if name == b".code":
            code_entry = (off, size)
    if code_entry is None:
        print("no .code in the ExeFS", file=sys.stderr)
        return 2
    code_off, code_size = code_entry
    if code_size != len(code):
        print("ExeFS .code size 0x%X != code.bin size 0x%X — layout differs, refusing"
              % (code_size, len(code)), file=sys.stderr)
        return 2

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    if os.path.exists(args.out):
        os.remove(args.out)
    print("copying %s -> %s" % (eu, args.out))
    shutil.copyfile(eu, args.out)

    with open(args.out, "r+b") as f:
        base = part0_off
        if not args.keep_ids:
            # NCCH header: program_id, partition_id, product_code
            f.seek(base + 0x108); f.write(struct.pack("<Q", USA_TITLE_ID))
            f.seek(base + 0x118); f.write(struct.pack("<Q", USA_TITLE_ID))
            f.seek(base + 0x150); f.write(USA_PRODUCT_CODE.ljust(0x10, b"\0"))
            # ExHeader: ACI program_id, SCI jump_id
            f.seek(base + 0x400); f.write(struct.pack("<Q", USA_TITLE_ID))
            f.seek(base + 0x200 + 0x1C8); f.write(struct.pack("<Q", USA_TITLE_ID))
        # ExeFS .code <- USA code.bin
        f.seek(base + exefs_off + 0x200 + code_off)
        f.write(code)

    # verify what we wrote
    with open(args.out, "rb") as f:
        if not args.keep_ids:
            f.seek(base + 0x118)
            assert struct.unpack("<Q", f.read(8))[0] == USA_TITLE_ID
        f.seek(base + exefs_off + 0x200 + code_off)
        written = f.read(len(code))
        assert hashlib.sha1(written).hexdigest() == hashlib.sha1(code).hexdigest()
    print("synthetic ROM ready: %s (%d bytes)" % (args.out, os.path.getsize(args.out)))
    print("  .code region sha1 matches code.bin; ids %s"
          % ("USA %016X / %s" % (USA_TITLE_ID, USA_PRODUCT_CODE.decode()) if not args.keep_ids else "kept EU"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Run Zakuro's interpreter headless over the USA ALBW ROM and write a
coverage log for tools/coverage_rank.py.

  python tools/coverage_run.py [--rom PATH] [--frames N] [--out PATH] [--covtool PATH]

The heavy lifting is done by `covtool`, a tiny Rust binary that links
zakuro-core (github.com/fearkov/zakuro) and steps the interpreter
instruction by instruction, counting every PC. covtool is NOT committed
(it lives outside the repo, next to a zakuro checkout); this wrapper just
locates it, runs it, and drops the JSONL where coverage_rank.py expects it.

ROM discovery (first match wins):
  --rom, else $ALBW_ROM, else a *.3ds under $ALBW_ROMS_DIR or ~/Download
The ROM must be DECRYPTED (Zakuro requires it; the USA ALBW dump we have
is already fixed-crypto/plaintext in its ExeFS).

Output: logs/coverage/executed.jsonl, one {"addr": "XXXXXXXX", "hits": N}
per executed PC (logs/ is gitignored).
"""
import argparse
import glob
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import ROOT

DEFAULT_OUT = os.path.join(ROOT, "logs", "coverage", "executed.jsonl")
DEFAULT_COVTOOL = os.path.expanduser(
    "~/zakuro-work/covtool/target/release/covtool")


def find_rom(args_rom):
    if args_rom:
        return args_rom
    if os.environ.get("ALBW_ROM"):
        return os.environ["ALBW_ROM"]
    for d in [os.environ.get("ALBW_ROMS_DIR", ""), os.path.expanduser("~/Download"),
              "/storage/emulated/0/Download"]:
        if not d:
            continue
        hits = sorted(glob.glob(os.path.join(d, "*Link*Between*Worlds*USA*.3ds")))
        if hits:
            return hits[0]
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rom")
    ap.add_argument("--frames", type=int, default=600,
                    help="frames to run (600 ~= 10 s of game time)")
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--covtool", default=DEFAULT_COVTOOL)
    ap.add_argument("--data", default=os.path.expanduser("~/zakuro-work/cov-data"),
                    help="zakuro data dir (saves etc.)")
    args = ap.parse_args()

    rom = find_rom(args.rom)
    if not rom or not os.path.exists(rom):
        print("no decrypted USA ROM found; pass --rom PATH", file=sys.stderr)
        return 2
    if not os.path.exists(args.covtool):
        print("covtool binary not found at %s\n" % args.covtool +
              "build it from a zakuro checkout (see docs/RECOMP_IDEAS.md section 2)",
              file=sys.stderr)
        return 2
    out_dir = os.path.dirname(os.path.abspath(args.out))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    os.makedirs(args.data, exist_ok=True)
    print("rom: %s\nframes: %d\nout: %s" % (rom, args.frames, args.out))
    cmd = [args.covtool, rom, str(args.frames), args.out, args.data]
    rc = subprocess.run(cmd).returncode
    if rc == 0 and os.path.exists(args.out):
        n = sum(1 for _ in open(args.out))
        print("coverage: %d distinct PCs -> %s" % (n, args.out))
    return rc


if __name__ == "__main__":
    sys.exit(main())

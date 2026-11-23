#!/usr/bin/env python3
"""One-time setup for the objdiff-cli wrapper: download the PINNED release into
tools/bin/ (gitignored) and verify its SHA-256 before the binary is ever used.

  python3 tools/setup_objdiff.py                          # auto-detect host platform
  python3 tools/setup_objdiff.py --target linux-aarch64   # e.g. the phone (Termux)
  python3 tools/setup_objdiff.py --check                  # verify an installed binary

The repository never commits a binary and never downloads one at build time:
this script is run manually, once, and writes only the untracked
tools/bin/objdiff-cli (+ a small .json sidecar recording version/target/hash).

Pinned release: objdiff-cli v3.8.3,
https://github.com/encounter/objdiff/releases/tag/v3.8.3
Per-asset SHA-256 below (computed from the release assets at pin time).
"""
import argparse
import hashlib
import json
import os
import platform
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BIN_DIR = os.path.join(ROOT, "tools", "bin")
BIN_NAME = "objdiff-cli"

OBJDIFF_VERSION = "v3.8.3"
RELEASE_URL = "https://github.com/encounter/objdiff/releases/download/%s/%s"
# target -> (release asset, pinned SHA-256 of that asset)
ASSETS = {
    "linux-x86_64": ("objdiff-cli-linux-x86_64",
                     "e823ae932a56c68dcd86b68d12f2268c953e0c027402162c8a6dfa6a00d65008"),
    "linux-aarch64": ("objdiff-cli-linux-aarch64",
                      "0e630457e2f33a43da3723e195ecd0b39b683a6a83122955fdc68c5b17183cbc"),
    "macos-arm64": ("objdiff-cli-macos-arm64",
                    "27dbd79196394c246dde77ef0a6ac855ff6c568069171dd7db0093f39c03ee8d"),
    "macos-x86_64": ("objdiff-cli-macos-x86_64",
                     "4a0f5079600cb9ddf2369414e712f96838bc0ae05cd1a98c92f6131078ec4b0e"),
    "windows-x86_64": ("objdiff-cli-windows-x86_64.exe",
                       "dd12dfb5e9e94a7f6c949a37e1815963cf2cffe4c87b4999b7ebc8c15b398a1f"),
}


def detect_target(system=None, machine=None):
    """Host platform -> pinned asset target (explicit --target overrides)."""
    system = system if system is not None else sys.platform
    machine = (machine if machine is not None else platform.machine()).lower()
    if system.startswith("linux"):
        return {"x86_64": "linux-x86_64", "amd64": "linux-x86_64",
                "aarch64": "linux-aarch64", "arm64": "linux-aarch64"}.get(
                    machine, "linux-x86_64")
    if system == "darwin":
        return "macos-arm64" if machine in ("arm64", "aarch64") else "macos-x86_64"
    if system in ("win32", "cygwin"):
        return "windows-x86_64"
    raise SystemExit("unsupported platform %s/%s: pass --target explicitly "
                     "(one of: %s)" % (system, machine, ", ".join(sorted(ASSETS))))


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(url, dest, opener=None):
    """Stream url -> dest. `opener` (test hook) replaces urllib.request.urlopen."""
    request = urllib.request.Request(url, headers={"User-Agent": "albw-decomp-ai setup_objdiff"})
    open_url = opener or urllib.request.urlopen
    with open_url(request, timeout=120) as response, open(dest, "wb") as out:
        while True:
            chunk = response.read(1 << 20)
            if not chunk:
                break
            out.write(chunk)


def install(target, dest_dir=None, opener=None):
    """Download the pinned asset for `target`, verify SHA-256, install atomically.

    Returns (binary_path, sha256). Any hash mismatch aborts before the binary
    is put in place; nothing is left behind on failure.
    """
    if target not in ASSETS:
        raise SystemExit("unknown target %r (one of: %s)" % (target, ", ".join(sorted(ASSETS))))
    asset, expected = ASSETS[target]
    url = RELEASE_URL % (OBJDIFF_VERSION, asset)
    dest_dir = dest_dir or BIN_DIR
    os.makedirs(dest_dir, exist_ok=True)
    suffix = ".exe" if target.startswith("windows") else ""
    fd, tmp = tempfile.mkstemp(prefix="." + BIN_NAME + ".", dir=dest_dir)
    os.close(fd)
    try:
        fetch(url, tmp, opener=opener)
        got = sha256_file(tmp)
        if got != expected:
            raise SystemExit("SHA-256 mismatch for %s: got %s, expected %s - refusing to install"
                             % (url, got, expected))
        dest = os.path.join(dest_dir, BIN_NAME + suffix)
        os.replace(tmp, dest)
        os.chmod(dest, 0o755)
        with open(dest + ".json", "w", encoding="utf-8") as stream:
            json.dump({"version": OBJDIFF_VERSION, "target": target,
                       "asset": asset, "sha256": got, "url": url}, stream, indent=1)
            stream.write("\n")
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    return dest, got


def check(dest_dir=None):
    """Verify an already-installed binary against its pinned sidecar hash."""
    dest_dir = dest_dir or BIN_DIR
    suffix = ".exe" if os.name == "nt" else ""
    dest = os.path.join(dest_dir, BIN_NAME + suffix)
    if not os.path.isfile(dest):
        return None
    sidecar = dest + ".json"
    if not os.path.isfile(sidecar):
        return {"path": dest, "sha256": sha256_file(dest), "pinned": None, "ok": False,
                "note": "no sidecar: hash not pinned, re-run setup to pin it"}
    with open(sidecar, encoding="utf-8") as stream:
        meta = json.load(stream)
    got = sha256_file(dest)
    ok = got == meta.get("sha256")
    return {"path": dest, "sha256": got, "pinned": meta.get("sha256"),
            "version": meta.get("version"), "target": meta.get("target"), "ok": ok}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", choices=sorted(ASSETS), default=None,
                    help="release asset to install (default: auto-detect host)")
    ap.add_argument("--dest", default=None, help="install directory (default: tools/bin/)")
    ap.add_argument("--check", action="store_true", help="verify the installed binary and exit")
    args = ap.parse_args()
    if args.check:
        result = check(args.dest)
        if result is None:
            print("not installed: %s" % os.path.join(args.dest or BIN_DIR, BIN_NAME))
            return 2
        print(json.dumps(result, indent=1))
        return 0 if result["ok"] else 1
    target = args.target or detect_target()
    dest, got = install(target, dest_dir=args.dest)
    print("installed objdiff-cli %s (%s) -> %s" % (OBJDIFF_VERSION, target, dest))
    print("sha256 %s (verified against the pinned release asset)" % got)
    print("NEXT  python3 tools/objdiff.py units <object-file> --json")
    return 0


if __name__ == "__main__":
    sys.exit(main())

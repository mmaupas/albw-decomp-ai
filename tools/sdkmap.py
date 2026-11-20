#!/usr/bin/env python
"""SDK fingerprinting pipeline (roadmap H1, AUTOMATION_PLAN phase 8).

  python tools/sdkmap.py inventory --nnsdk-dir PATH [--out shared/nnsdk_inventory.json] [--json]
  python tools/sdkmap.py plan [--filter excluded_library,unmatched] [--limit N] [--json]
  python tools/sdkmap.py fingerprint [--addr 0xA ...] [--budget B] [--image PATH] [--force] [--json]
  python tools/sdkmap.py try-compile <addr> --nnsdk-dir PATH [--sym SUBSTR] [--run] [--json]
  python tools/sdkmap.py status [--json]
  python tools/sdkmap.py report [--json]

Hypothesis: part of the unmatched tail and the excluded_library entries is
ordinary Nitro/nn SDK code compiled from the SDK's own sources with the same
compiler and flags. The public reconstruction 3dsdecomp/nnsdk
(https://github.com/3dsdecomp/nnsdk) is cloned at session time into an
UNTRACKED working directory; its source is never committed (it ships no
LICENSE file at the pinned revision, and this repo never vendors SDK
material - see AGENTS.md and docs/AUTOMATION_PLAN.md phase 8). The only
committed artifact is a generated metadata inventory:
shared/nnsdk_inventory.json (names, mangled-name patterns, namespaces,
source paths inside nnsdk, kind, per-file structure hash). No game-derived
raw data is ever written by this tool.

`inventory` parses the nnsdk tree with a small stdlib C++ scope/signature
scanner: namespaces, class/struct scopes, free functions, class members,
static members, constructors/destructors/operators, templates and __asm
functions (whose exact mangled name is harvested from the
`__attribute__((section("i._ZN...")))` marker). Mangled names are otherwise
best-effort full-expansion Itanium patterns (unknown types encode as `?`),
usable as `fn.py check --sym` substrings. Output is deterministic
(sort_keys) and resumable through a per-file cache under logs/sdkmap/.

`plan` is fully offline (no code.bin, no nnsdk clone): it reads the committed
inventory + funcs.json + functions.json + shared/symbols.jsonl and ranks
candidate game functions likely to be SDK code, starting from the
excluded_library and unmatched pools. Signals: symbol-name hits against the
inventory, size-class agreement with the SDK-typical size distribution of
the excluded_library pool, library-region clustering around excluded_library
addresses, and call-graph neighborhood of already-matched SDK-looking
functions (exact caller edges come from logs/sdkmap/fingerprints.json once
`fingerprint` has run on the phone; until then the funcs.json bl target set
and address clustering are the offline proxy). Each row carries the address,
reasons, suggested nnsdk source paths, and an expected difficulty. State:
logs/sdkmap/plan.json.

`fingerprint` needs code.bin (SHA-1-verified, read-only) + capstone: it
disassembles each candidate and stores its normalized token stream
(shapemine vocabulary: cond stripped, r/#/POOL/CALL) plus the CFG shape
(block count, pool size, call list) in logs/sdkmap/fingerprints.json for
phone-side comparison against compiled nnsdk sources. Without code.bin it
prints the phone command and exits 2.

`try-compile` is the phone-only orchestrator: it builds a self-contained
unit under logs/sdkmap/build/<ADDR>/ from the mapped nnsdk source(s) (the
Include tree is copied beside the unit and angle includes rewritten to
quoted ones so fn.py check's fixed -I resolves them), compiles with the
entry's cc/flags (defaults otherwise) through the repository compiler lock
(via permuter.check_one -> fn.py check), and on RESULT: MATCH runs the
standard `worklist register` flow and records a `sdk:nnsdk <path>@<rev>`
note in the entry (same note-field convention as source_lost). --run is
required to execute; the default is a dry run that prints the exact
commands. Without code.bin/armcc/nnsdk it exits 2 with the phone commands.
Nothing is ever auto-registered from a sandbox.

`status` / `report` are offline views over the resumable state.

State (gitignored, regenerable): logs/sdkmap/{inventory_cache.json,
plan.json, fingerprints.json, attempts.jsonl, build/}.
"""
import argparse
import bisect
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (ROOT, TEXT_START, TEXT_SIZE, atomic_write, file_lock,  # noqa: E402
                    load_binary, read_json, write_json)

try:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM
except ImportError:
    Cs = None

STATE = os.path.join(ROOT, "logs", "sdkmap")
CACHE_FILE = os.path.join(STATE, "inventory_cache.json")
PLAN_FILE = os.path.join(STATE, "plan.json")
FINGER_FILE = os.path.join(STATE, "fingerprints.json")
ATTEMPTS_FILE = os.path.join(STATE, "attempts.jsonl")
BUILD_DIR = os.path.join(STATE, "build")
INVENTORY = os.path.join(ROOT, "shared", "nnsdk_inventory.json")
FUNCS = os.path.join(ROOT, "funcs.json")
FUNCTIONS = os.path.join(ROOT, "functions.json")
SYMBOLS = os.path.join(ROOT, "shared", "symbols.jsonl")
CODE_BIN = os.path.join(ROOT, "code.bin")
DEFAULT_CC = "4.1/b1049"
DEFAULT_FLAGS = "--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections"
NNSDK_URL = "https://github.com/3dsdecomp/nnsdk"
SRC_EXTS = (".c", ".cc", ".cpp", ".h", ".hpp")
SKIP_DIRS = {".git", ".github", "logs", "build", "__pycache__", ".venv"}
DEFAULT_BUDGET = 20
DEFAULT_LIMIT = 50
SIZE_CLASSES = ((16, "tiny"), (64, "small"), (256, "medium"), (None, "large"))
REGION_RADIUS = 0x4000


def armcc_exe(cc):
    return os.path.join(ROOT, "tools", "armcc", *cc.split("/"), "bin", "armcc.exe")


def key_of(addr):
    return "%08X" % addr


# ------------------------------------------------------- inventory: parsing

_STRIP_RE = re.compile(
    r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.DOTALL)


def strip_source(text):
    """Blank comments, string/char literals and preprocessor lines, keeping
    newlines and offsets (and therefore line numbers) intact."""
    def blank(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    text = _STRIP_RE.sub(blank, text)
    out = []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            out.append(re.sub(r"[^\n]", " ", line))
        else:
            out.append(line)
    return "\n".join(out) + ("\n" if text.endswith("\n") else "")


_TOKEN_RE = re.compile(r"[A-Za-z_]\w*|::|<<|>>|->|\+\+|--|&&|\|\||==|!=|<=|>=|"
                       r"[()\[\]{};,<>:*&=+\-/%!~^|?.]")


def tokenize(text):
    """(token, offset) pairs; offsets drive line numbers."""
    return [(m.group(0), m.start()) for m in _TOKEN_RE.finditer(text)]


def line_of(text, pos):
    return text.count("\n", 0, pos) + 1


MODIFIERS = {"static", "inline", "virtual", "constexpr", "explicit", "extern",
             "friend", "typedef", "__asm", "__forceinline", "__inline"}
TERMINATORS = {"if", "for", "while", "switch", "return", "sizeof", "catch",
               "else", "do", "case", "default", "new", "delete", "throw",
               "goto", "break", "continue", "namespace", "class", "struct",
               "union", "enum", "template", "operator", "public", "private",
               "protected", "using", "const", "noexcept", "override", "final",
               "try", "asm"}
ATTR_WORDS = ("__attribute__", "__declspec", "__aligned", "__packed")
BUILTIN_TYPES = {"void", "bool", "char", "short", "int", "long", "float",
                 "double", "wchar_t", "signed", "unsigned", "size_t"}
IDENT_RE = re.compile(r"[A-Za-z_]\w*\Z")


def split_top_level(text, sep=","):
    parts, depth, cur = [], 0, []
    for ch in text:
        if ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth -= 1
        if ch == sep and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    parts.append("".join(cur))
    return [p.strip() for p in parts if p.strip()]


def param_type(param):
    """Best-effort type of one parameter (drops name and default value)."""
    param = param.split("=")[0].strip()
    toks = param.replace("*", " * ").replace("&", " & ").split()
    if len(toks) >= 2 and toks[-1].isidentifier() and toks[-1] not in BUILTIN_TYPES:
        toks = toks[:-1]
    return " ".join(toks).replace(" *", "*").replace(" &", "&").strip()


def parse_params(text):
    if not text.strip() or text.strip() == "void":
        return []
    return [param_type(p) for p in split_top_level(text)]


def _raw_text(toks, source):
    if not toks:
        return ""
    start = toks[0][1]
    end = toks[-1][1] + len(toks[-1][0])
    return source[start:end]


def _scope_match(head_text):
    """Does this head open a scope? Returns (kind, name) or None.
    A leading template<...> is stripped first."""
    t = head_text.strip()
    if re.match(r"template\s*<", t):
        depth = 0
        for i, ch in enumerate(t):
            if ch == "<":
                depth += 1
            elif ch == ">":
                depth -= 1
                if depth == 0:
                    t = t[i + 1:].strip()
                    break
    m = re.match(r"enum\s+(?:class\s+|struct\s+)?([A-Za-z_]\w*)", t)
    if m:
        return "enum", m.group(1) or ""
    m = re.match(r"(namespace|class|struct|union)\s+([A-Za-z_]\w*)?", t)
    if not m:
        return None
    if m.group(1) == "namespace" and "=" in t:
        return None
    return m.group(1), m.group(2) or ""


def parse_file(raw, rel, extra_types=None):
    """Scan one nnsdk source file -> (functions, types). Pure.

    `raw` is the original text (attribute string literals are blanked in the
    stripped copy used for scanning, so section("i._ZN...") names are read
    from `raw` via the preserved offsets). `extra_types` seeds the file-local
    type table with types declared in other files of the same tree."""
    stripped = strip_source(raw)
    toks = tokenize(stripped)
    funcs, types = [], dict(extra_types or {})
    scope = []
    i, n = 0, len(toks)
    head, attrs = [], []
    pending = False  # a function was just recorded at '('; body/init may follow
    was_fn = False

    def skip_balanced(idx, open_t, close_t):
        depth = 0
        while idx < n:
            t = toks[idx][0]
            if t == open_t:
                depth += 1
            elif t == close_t:
                depth -= 1
                if depth == 0:
                    return idx + 1
            idx += 1
        return idx

    def clear():
        nonlocal head, attrs
        head, attrs = [], []

    while i < n:
        tok, pos = toks[i]
        if tok == "}":
            if scope:
                scope.pop()
            clear()
            i += 1
            continue
        if tok == ";":
            clear()
            i += 1
            continue
        if tok == ":":
            if pending:
                while i < n and toks[i][0] not in ("{", ";"):
                    i += 1
                pending = False
                continue
            if head and head[-1][0] in ("public", "private", "protected"):
                clear()
            elif not _scope_match(" ".join(t for t, _p in head)):
                clear()
            i += 1
            continue
        if tok in ATTR_WORDS and i + 1 < n and toks[i + 1][0] == "(":
            close = skip_balanced(i + 1, "(", ")")
            attrs.append(raw[pos:toks[close - 1][1] + len(toks[close - 1][0])])
            i = close
            continue
        if tok == "{":
            head_text = " ".join(t for t, _p in head)
            sm = _scope_match(head_text)
            if sm:
                scope.append(sm)
                if sm[0] in ("class", "struct", "union") and sm[1]:
                    types[sm[1]] = [nm for k, nm in scope[:-1] if k == "namespace"]
                clear()
                i += 1
                continue
            fn = _function_from_head(head, stripped, raw, rel, scope, types, attrs)
            if fn:
                fn["line"] = line_of(stripped, head[0][1]) if head else 0
                fn["params_text"] = ""
                fn["params"] = []
                fn["mangled_pattern"] = mangle(fn["namespaces"], fn["class"],
                                               fn["name"], [], fn["kind"], types)
                funcs.append(fn)
            clear()
            i = skip_balanced(i, "{", "}")
            continue
        if tok == "(":
            fn = _function_from_head(head, stripped, raw, rel, scope, types, attrs)
            close = skip_balanced(i, "(", ")")
            if fn:
                fn["line"] = line_of(stripped, head[0][1]) if head else line_of(stripped, pos)
                fn["params_text"] = _raw_text(toks[i + 1:close - 1], stripped)
                fn["params"] = parse_params(fn["params_text"])
                fn["mangled_pattern"] = mangle(fn["namespaces"], fn["class"],
                                               fn["name"], fn["params"], fn["kind"], types)
                funcs.append(fn)
                was_fn = True
            clear()
            pending = was_fn
            i = close
            continue
        head.append((tok, pos))
        i += 1
    return funcs, types


def _function_from_head(head, stripped, raw, rel, scope, types, attrs):
    """If the accumulated head + a following '(' form a function declarator,
    return its record; else None."""
    if not head:
        return None
    toks = [t for t, _p in head]
    idents = [t for t in toks if IDENT_RE.match(t)]
    if not idents:
        return None
    if "operator" in idents and toks[-1] != "operator":
        if IDENT_RE.match(toks[-1]) and toks.index("operator") == len(toks) - 2:
            name = "operator " + toks[-1]  # conversion operator
        else:
            name = "operator" + toks[-1]
        ret_toks = toks[:toks.index("operator")]
    else:
        last = idents[-1]
        if last in TERMINATORS or last in MODIFIERS:
            return None
        if not (IDENT_RE.match(toks[-1]) or
                (toks[-1] and toks[-1][0] == "~" and len(toks) >= 2)):
            return None
        if len(toks) >= 2 and toks[-2] == "~":
            name = "~" + toks[-1]
            ret_toks = toks[:-2]
        else:
            name = toks[-1]
            ret_toks = toks[:-1]
    raw_head = _raw_text(head, stripped)
    mods = {t for t in idents if t in MODIFIERS}
    ret = " ".join(ret_toks).strip(" :,")
    ret = re.sub(r"\s+", " ", ret).strip()
    cls = next((nm for k, nm in reversed(scope)
                if k in ("class", "struct", "union")), None)
    if name.startswith("~"):
        kind = "destructor"
    elif cls and name == cls:
        kind = "constructor"
    elif cls:
        if "static" in mods:
            kind = "static_member"
        elif "virtual" in mods:
            kind = "virtual_member"
        else:
            kind = "member"
    elif "static" in mods:
        kind = "static_function"
    else:
        kind = "free_function"
    if name.startswith("operator"):
        kind = ("operator" if cls is None else kind + "_operator")
    ns = [nm for k, nm in scope if k == "namespace"]
    attr_text = " ".join(attrs)
    m = re.search(r'section\s*\(\s*"i\.([^"]+)"', attr_text) or \
        re.search(r'section\s*\(\s*"i\.([^"]+)"', raw_head)
    rec = {
        "name": name,
        "qualified": "::".join(ns + ([cls] if cls else []) + [name]),
        "namespaces": ns,
        "class": cls,
        "kind": kind,
        "return": ret,
        "source": rel,
        "asm": "__asm" in mods or "asm" in attr_text,
        "inline": bool(mods & {"inline", "__forceinline", "__inline"}),
        "template": "template" in idents,
        "mangled_pattern": "",
    }
    if m:
        rec["mangled_exact"] = m.group(1)
    return rec


# ---------------------------------------------------- inventory: mangling

BUILTIN = {
    "void": "v", "bool": "b", "char": "c", "signed char": "a",
    "unsigned char": "h", "short": "s", "unsigned short": "t",
    "short int": "s", "unsigned short int": "t", "int": "i", "signed": "i",
    "signed int": "i", "unsigned": "j", "unsigned int": "j", "long": "l",
    "unsigned long": "m", "long int": "l", "unsigned long int": "m",
    "long long": "x", "unsigned long long": "y", "long long int": "x",
    "unsigned long long int": "y", "float": "f", "double": "d",
    "long double": "e", "wchar_t": "w", "char16_t": "Ds", "char32_t": "Di",
    # nn::Types.h typedefs (transparent in Itanium mangling)
    "u8": "h", "u16": "t", "u32": "j", "u64": "y", "s8": "a", "s16": "s",
    "s32": "i", "s64": "x", "uintptr_t": "m", "intptr_t": "l",
}

OPERATOR_CODES = {
    "new": "nw", "delete": "dl", "new[]": "na", "delete[]": "da",
    "+": "pl", "-": "mi", "*": "ml", "/": "dv", "%": "rm", "^": "eo",
    "&": "an", "|": "or", "~": "co", "!": "nt", "=": "aS", "<": "lt",
    ">": "gt", "+=": "pL", "-=": "mI", "*=": "mL", "/=": "dV", "%=": "rM",
    "^=": "eO", "&=": "aN", "|=": "oR", "<<": "ls", ">>": "rs",
    "<<=": "lS", ">>=": "rS", "==": "eq", "!=": "ne", "<=": "le", ">=": "ge",
    "&&": "an", "||": "oo", "++": "pp", "--": "mm", ",": "cm", "->*": "pm",
    "->": "pt", "()": "cl", "[]": "ix",
}


def encode_type(t, ns_scope, types=None):
    """Best-effort Itanium encoding of one C++ type; unknown forms -> '?'.
    Bare class names declared in this file qualify with their own namespace."""
    t = re.sub(r"\s+", " ", t.strip())
    t = re.sub(r"^(struct|class|union|enum)\s+", "", t)
    prefix = ""
    while True:
        if t.endswith("*"):
            prefix += "P"
            t = t[:-1].strip()
        elif t.endswith("&&"):
            prefix += "O"
            t = t[:-2].strip()
        elif t.endswith("&"):
            prefix += "R"
            t = t[:-1].strip()
        elif t.startswith("const "):
            prefix += "K"
            t = t[6:].strip()
        elif t.endswith(" const"):
            prefix += "K"
            t = t[:-6].strip()
        else:
            break
    m = re.fullmatch(r"(.*)\[(\d+)\]", t)
    if m:
        return prefix + "A%s_%s" % (m.group(2), encode_type(m.group(1), ns_scope, types))
    if t in BUILTIN:
        return prefix + BUILTIN[t]
    if t == "...":
        return "z"
    if "<" in t and t.endswith(">"):
        base, args = t.split("<", 1)
        inner = "".join(encode_type(a, ns_scope, types) for a in split_top_level(args[:-1]))
        return prefix + _encode_name(base.strip(), ns_scope)[:-1] + "I" + inner + "E"
    return prefix + _encode_name(t, ns_scope, types)


def _encode_name(name, ns_scope, types=None):
    if "::" in name:
        comps = [c for c in name.split("::") if c]
        return "N" + "".join("%d%s" % (len(c), c) for c in comps) + "E"
    scope = (types or {}).get(name) or ns_scope
    if scope:
        return "N" + "".join("%d%s" % (len(c), c) for c in scope) + \
               "%d%sE" % (len(name), name)
    return "%d%s" % (len(name), name)


def mangle(ns_scope, cls, name, params, kind, types=None):
    """Best-effort full-expansion Itanium mangled-name pattern."""
    comps = list(ns_scope) + ([cls] if cls else [])
    if name.startswith("~"):
        bare = "D1"
    elif kind == "constructor":
        bare = "C1"
    elif name.startswith("operator "):
        bare = encode_type(name[len("operator "):], ns_scope, types)
    elif name.startswith("operator"):
        op = name[len("operator"):].strip()
        bare = OPERATOR_CODES.get(op, "?")
    else:
        bare = "%d%s" % (len(name), name)
    if comps:
        head = "_ZN" + "".join("%d%s" % (len(c), c) for c in comps) + bare + "E"
    else:
        head = "_Z" + bare
    if params is None:
        params = []
    return head + ("".join(encode_type(p, ns_scope, types) for p in params) or "v")


# ------------------------------------------------------ inventory: driver

PHONE_CLONE = """clone the public nnsdk reconstruction into an UNTRACKED directory
(outside the repo, or under the gitignored logs/):
  git clone https://github.com/3dsdecomp/nnsdk {dir}
  (cd {dir} && git checkout d50a4b89d13c929d2438abf92e5a48f039efffbf)
then:
  uv run python tools/sdkmap.py inventory --nnsdk-dir {dir}
  uv run python tools/sdkmap.py plan --limit 50 --json"""


def nnsdk_revision(nnsdk_dir):
    try:
        out = subprocess.run(["git", "-C", nnsdk_dir, "rev-parse", "HEAD"],
                             capture_output=True, text=True, timeout=30)
        if out.returncode == 0:
            return out.stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    return "unknown"


def list_source_files(nnsdk_dir):
    out = []
    for base, dirs, files in os.walk(nnsdk_dir):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for f in sorted(files):
            if os.path.splitext(f)[1] in SRC_EXTS:
                out.append(os.path.relpath(os.path.join(base, f), nnsdk_dir))
    return sorted(out)


def structure_hash(funcs):
    """Hash of the parsed declaration structure (comment/whitespace-proof)."""
    canon = json.dumps([{k: v for k, v in f.items() if k != "line"} for f in funcs],
                       sort_keys=True)
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()


def scan_nnsdk(nnsdk_dir, cache=None):
    """Parse the whole tree -> (inventory dict, cache). Resumable: cache maps
    relpath -> {"sha256", "record"} and is reused when the content hash
    matches, so only changed files are re-parsed."""
    cache = cache if cache is not None else {}
    rels = list_source_files(nnsdk_dir)
    texts = {}
    for rel in rels:
        with open(os.path.join(nnsdk_dir, rel), encoding="utf-8", errors="replace") as fh:
            texts[rel] = fh.read()
    # pre-pass: collect declared type names across the whole tree so bare
    # class references mangle with their declaring namespace
    global_types = {}
    for rel in rels:
        _funcs, types = parse_file(texts[rel], rel)
        global_types.update(types)
    files = []
    for rel in rels:
        full = os.path.join(nnsdk_dir, rel)
        with open(full, "rb") as fh:
            raw = fh.read()
        sha = hashlib.sha256(raw).hexdigest()
        ent = cache.get(rel)
        if ent and ent.get("sha256") == sha and ent["record"].get("global_types") == global_types:
            record = ent["record"]
        else:
            text = texts[rel]
            funcs, types = parse_file(text, rel, global_types)
            funcs.sort(key=lambda f: (f.get("line", 0), f["name"]))
            record = {"path": rel, "content_sha256": sha,
                      "structure_hash": structure_hash(funcs),
                      "global_types": global_types,
                      "types": [{"name": nm, "namespaces": ns, "kind": "class"}
                                for nm, ns in sorted(types.items())],
                      "functions": funcs}
            cache[rel] = {"sha256": sha, "record": record}
        files.append({k: v for k, v in record.items() if k != "global_types"})
    files.sort(key=lambda r: r["path"])
    rev = nnsdk_revision(nnsdk_dir)
    inv = {
        "generator": "tools/sdkmap.py inventory",
        "nnsdk": {
            "url": NNSDK_URL,
            "revision": rev,
            "license": ("no LICENSE file at the pinned revision (GitHub API "
                        "reports license: null); metadata-only inventory, no "
                        "nnsdk source is vendored into this repo"),
            "attribution": "3dsdecomp/nnsdk, %s, revision %s" % (NNSDK_URL, rev),
        },
        "counts": {"files": len(files),
                   "functions": sum(len(f["functions"]) for f in files)},
        "files": files,
    }
    return inv, cache


def load_cache():
    if os.path.exists(CACHE_FILE):
        try:
            return read_json(CACHE_FILE)
        except (OSError, ValueError):
            return {}
    return {}


def cmd_inventory(nnsdk_dir, out_path, as_json):
    if not os.path.isdir(nnsdk_dir):
        hint = PHONE_CLONE.format(dir=nnsdk_dir)
        out = {"error": "missing nnsdk clone", "missing": [nnsdk_dir],
               "phone_commands": hint}
        print(json.dumps(out) if as_json else "no nnsdk clone at %s\n%s" % (nnsdk_dir, hint))
        return 2
    inv, cache = scan_nnsdk(nnsdk_dir, load_cache())
    write_json(CACHE_FILE, cache)
    atomic_write(out_path, json.dumps(inv, indent=1, sort_keys=True) + "\n")
    summary = {"out": os.path.relpath(out_path, ROOT), "files": inv["counts"]["files"],
               "functions": inv["counts"]["functions"], "revision": inv["nnsdk"]["revision"]}
    if as_json:
        print(json.dumps(summary))
    else:
        print("inventory: %d files, %d functions -> %s (nnsdk rev %s)" % (
            summary["files"], summary["functions"], summary["out"], summary["revision"]))
        print("NEXT  git add %s && python tools/sdkmap.py plan --json" % summary["out"])
    return 0


# ------------------------------------------------------------------- plan

def load_inventory(path=None):
    if path is None:
        path = INVENTORY
    if not os.path.exists(path):
        return None
    try:
        return read_json(path)
    except (OSError, ValueError):
        return None


def load_symbols(path=None):
    if path is None:
        path = SYMBOLS
    out = {}
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            try:
                d = json.loads(line)
                if d.get("name") and d.get("addr"):
                    out[int(d["addr"], 16)] = d["name"]
            except (ValueError, KeyError, TypeError):
                pass
    return out


def name_index(inv):
    """List of (compiled regex, entry) used to match a symbols.jsonl name
    against the inventory: full namespace paths, namespace components (only
    with an adjacent ::), and class/function names as whole words."""
    idx = []
    for f in inv.get("files", []):
        for fn in f["functions"]:
            entry = {"qualified": fn["qualified"], "source": f["path"],
                     "kind": fn["kind"]}
            ns = fn["namespaces"]
            for k in range(2, len(ns) + 1):
                prefix = "::".join(ns[:k])
                idx.append((re.compile(r"(?:^|[^\w:])%s(?::|\b)" % re.escape(prefix)),
                            entry))
            for nm in {fn["name"].lstrip("~"), fn["class"]} - {None, ""}:
                if nm and len(nm) >= 3:
                    idx.append((re.compile(r"\b%s\b" % re.escape(nm)), entry))
    return idx


def name_hits(symbol_name, idx):
    if not symbol_name:
        return []
    hits, seen = [], set()
    for pat, e in idx:
        if pat.search(symbol_name) and e["qualified"] not in seen:
            seen.add(e["qualified"])
            hits.append(e)
    hits.sort(key=lambda e: e["qualified"])
    return hits


def size_class(size):
    for bound, name in SIZE_CLASSES:
        if bound is None or size <= bound:
            return name
    return "large"


def func_size(starts, i):
    end = starts[i + 1] if i + 1 < len(starts) else TEXT_START + TEXT_SIZE
    return end - starts[i]


def plan_rows(inv, funcs, functions, symbols, filters, limit, fingerprints=None):
    """Ranked SDK candidates. Pure: no I/O, no state writes."""
    starts = sorted(funcs["starts"])
    bl_targets = set(funcs.get("bl", []))
    idx = name_index(inv)
    pools = set(filters) or {"excluded_library", "unmatched"}
    if "all" in pools:
        pools = {"excluded_library", "unmatched", "source_lost"}
    excluded = sorted(int(k, 16) for k, v in functions.items()
                      if v.get("status") == "excluded_library")
    excl_sizes = {}
    for a in excluded:
        i = bisect.bisect_left(starts, a)
        if i < len(starts) and starts[i] == a:
            excl_sizes[a] = func_size(starts, i)
    class_hist = {}
    for s in excl_sizes.values():
        class_hist[size_class(s)] = class_hist.get(size_class(s), 0) + 1
    n_excl = max(len(excl_sizes), 1)
    matched_keys = {k for k, v in functions.items()
                    if v.get("status") in ("honest", "hack")}
    matched_ints = {int(k, 16) for k in matched_keys}
    matched_sdk = sorted(a for a, nm in symbols.items()
                         if a in matched_ints and nm and name_hits(nm, idx))
    edges = {}
    if fingerprints:
        for addr, rec in fingerprints.items():
            try:
                edges[int(addr, 16)] = [int(c, 16) for c in rec.get("calls", [])]
            except (ValueError, TypeError):
                pass
    excl_set = set(excluded)
    sdk_set = set(matched_sdk)
    rows = []
    for i, addr in enumerate(starts):
        key = key_of(addr)
        ent = functions.get(key)
        status = ent.get("status") if ent else None
        if status in ("honest", "hack", "lifted", "semantic_match", "interior_address"):
            continue
        if status == "excluded_library":
            pool = "excluded_library"
        elif status == "no_source" or (ent and ent.get("label") == "source_lost"):
            pool = "source_lost"
        else:
            pool = "unmatched"
        if pool not in pools:
            continue
        size = func_size(starts, i)
        sc = size_class(size)
        reasons, score = [], 0.0
        if pool == "excluded_library":
            score += 100.0
            reasons.append("excluded_library (closest prior: known embedded library code)")
        elif pool == "source_lost":
            score += 20.0
            reasons.append("source_lost (earlier match whose source was purged)")
        sym = symbols.get(addr)
        hits = name_hits(sym, idx) if sym else []
        if hits:
            score += min(50.0, 10.0 * len(hits))
            reasons.append("name hit vs nnsdk inventory: " + ", ".join(
                h["qualified"] for h in hits[:4]))
        prior = class_hist.get(sc, 0) / n_excl
        if excluded and prior > 0:
            score += 20.0 * prior
            reasons.append("size class %s is SDK-typical (%d/%d excluded_library entries in class)"
                           % (sc, class_hist.get(sc, 0), n_excl))
        near_excl = [a for a in excluded if abs(a - addr) <= REGION_RADIUS]
        if near_excl:
            score += 30.0
            reasons.append("library region: %d excluded_library entries within 0x%X"
                           % (len(near_excl), REGION_RADIUS))
        near_sdk = [a for a in matched_sdk if abs(a - addr) <= 2 * REGION_RADIUS]
        if near_sdk:
            score += 15.0
            reasons.append("near matched SDK-named function %s" % key_of(
                min(near_sdk, key=lambda a: abs(a - addr))))
        calls = edges.get(addr, [])
        sdk_callees = [c for c in calls if c in sdk_set or c in excl_set]
        if sdk_callees:
            score += 25.0
            reasons.append("calls SDK-looking/library function(s): " + ", ".join(
                key_of(c) for c in sdk_callees[:4]))
        if addr in bl_targets:
            reasons.append("is a call target in funcs.json")
        suggested = sorted({h["source"] for h in hits})
        if size > 256:
            difficulty = "high"
        elif hits or pool == "excluded_library":
            difficulty = "low" if size <= 64 else "medium"
        else:
            difficulty = "medium" if size <= 64 else "high"
        rows.append({"addr": key, "size": size, "size_class": sc, "pool": pool,
                     "score": round(score, 2), "reasons": reasons,
                     "name_hits": [h["qualified"] for h in hits],
                     "suggested": suggested, "difficulty": difficulty,
                     "symbol": sym})
    rows.sort(key=lambda r: (-r["score"], int(r["addr"], 16)))
    return rows[:limit] if limit else rows


def load_plan_state():
    if os.path.exists(PLAN_FILE):
        try:
            return read_json(PLAN_FILE)
        except (OSError, ValueError):
            return {}
    return {}


def cmd_plan(filters, limit, as_json):
    inv = load_inventory()
    if inv is None:
        hint = ("no committed inventory %s; run: python tools/sdkmap.py inventory "
                "--nnsdk-dir <nnsdk-clone>" % os.path.relpath(INVENTORY, ROOT))
        out = {"error": "missing committed inventory", "missing": [INVENTORY],
               "phone_commands": hint}
        print(json.dumps(out) if as_json else hint)
        return 2
    funcs = read_json(FUNCS)
    functions = read_json(FUNCTIONS)
    symbols = load_symbols()
    fingerprints = {}
    if os.path.exists(FINGER_FILE):
        try:
            fingerprints = read_json(FINGER_FILE)
        except (OSError, ValueError):
            fingerprints = {}
    rows = plan_rows(inv, funcs, functions, symbols, filters, limit, fingerprints)
    state = {"filters": sorted(set(filters)), "limit": limit,
             "inventory_revision": inv.get("nnsdk", {}).get("revision"),
             "candidates": rows}
    write_json(PLAN_FILE, state)
    out = {"inventory_revision": state["inventory_revision"],
           "n_candidates": len(rows), "candidates": rows}
    if as_json:
        print(json.dumps(out))
    else:
        print("sdkmap plan: %d candidates (inventory rev %s)" % (
            len(rows), state["inventory_revision"]))
        for r in rows[:40]:
            print("  %s  %6d B  %-6s %-6s score %6.1f  %s" % (
                r["addr"], r["size"], r["size_class"], r["difficulty"], r["score"],
                "; ".join(r["reasons"][:2])))
        if len(rows) > 40:
            print("  ... %d more" % (len(rows) - 40))
        print("NEXT  uv run python tools/sdkmap.py fingerprint --budget %d   # phone: needs code.bin"
              % DEFAULT_BUDGET)
    return 0


# ------------------------------------------------------------- fingerprint

class Image:
    """A flat code image with its .text base (fixture-friendly, no SHA check)."""

    def __init__(self, data, text_start=TEXT_START):
        self.data = data
        self.ta = text_start

    def word(self, addr):
        off = addr - self.ta
        if off < 0 or off + 4 > len(self.data):
            raise ValueError("address %08X outside image" % addr)
        return struct.unpack_from("<I", self.data, off)[0]

    def try_word(self, addr):
        off = addr - self.ta
        if off < 0 or off + 4 > len(self.data):
            return None
        return struct.unpack_from("<I", self.data, off)[0]


def load_image(path=None):
    """Default: the SHA-1-verified, read-only code.bin. --image: raw file."""
    if path is None:
        if not os.path.exists(CODE_BIN):
            return None
        return Image(load_binary(CODE_BIN))
    with open(path, "rb") as fh:
        return Image(fh.read())


PHONE_FINGERPRINT = """fingerprinting needs the game binary + capstone; neither is in this sandbox.
On the phone (Termux), with the SHA-1-verified code.bin in the repo root:
  uv run python tools/sdkmap.py plan --limit 50 --json
  uv run python tools/sdkmap.py fingerprint --budget 20
  uv run python tools/sdkmap.py report --json"""


def fingerprint_one(img, starts, addr):
    """Disassemble one function; tokens reuse the shapemine vocabulary and
    the CFG/pool split reuses lift.py's helpers (pure apart from capstone)."""
    import lift
    import shapemine
    starts = sorted(starts)
    i = bisect.bisect_right(starts, addr) - 1
    if i < 0 or starts[i] != addr:
        raise ValueError("fingerprint requires an exact function start: %08X" % addr)
    end = starts[i + 1] if i + 1 < len(starts) else TEXT_START + TEXT_SIZE
    end = min(end, img.ta + len(img.data))
    blocks, ce, pool = lift.build_cfg(img, addr, end, starts)
    tokens = [shapemine.token_of(ins.mnemonic, ins.op_str)
              for blk in blocks for ins in blk["insns"]]
    calls = sorted({t for blk in blocks for kind, t in blk["succs"]
                    if t is not None and kind in ("call", "tail")})
    joined = "\n".join(tokens)
    return {"addr": key_of(addr), "size": end - addr, "n_insns": len(tokens),
            "n_blocks": len(blocks), "pool_size": len(pool), "code_end": ce,
            "token_hash": hashlib.blake2b(joined.encode("utf-8"),
                                          digest_size=16).hexdigest(),
            "tokens": tokens, "calls": [key_of(c) for c in calls]}


def load_fingerprints():
    if os.path.exists(FINGER_FILE):
        try:
            return read_json(FINGER_FILE)
        except (OSError, ValueError):
            return {}
    return {}


def cmd_fingerprint(addrs, budget, image_path, force, as_json):
    missing = []
    if image_path is None and not os.path.exists(CODE_BIN):
        missing.append("code.bin (SHA-1 e6ab7d66ee62e879248b0660aaf38d22202e604b, 6,455,296 bytes)")
    if Cs is None:
        missing.append("capstone (uv sync)")
    if missing:
        out = {"error": "fingerprint cannot run here", "missing": missing,
               "phone_commands": PHONE_FINGERPRINT}
        print(json.dumps(out) if as_json else PHONE_FINGERPRINT)
        return 2
    img = load_image(image_path)
    if img is None:
        out = {"error": "image not readable", "missing": ["code.bin"],
               "phone_commands": PHONE_FINGERPRINT}
        print(json.dumps(out) if as_json else PHONE_FINGERPRINT)
        return 2
    funcs = read_json(FUNCS)
    starts = funcs["starts"]
    if not addrs:
        rows = load_plan_state().get("candidates") or []
        addrs = [int(r["addr"], 16) for r in rows[:budget]]
    fp = load_fingerprints()
    done = 0
    for addr in addrs[:budget]:
        key = key_of(addr)
        if key in fp and not force:
            continue
        try:
            rec = fingerprint_one(img, starts, addr)
        except ValueError as exc:
            rec = {"addr": key, "error": str(exc)}
        fp[key] = rec
        done += 1
        print("fingerprinted %s (%d/%d)" % (key, done, budget), file=sys.stderr)
    write_json(FINGER_FILE, fp)
    out = {"budget": budget, "fingerprinted_this_run": done, "total_fingerprinted": len(fp)}
    if as_json:
        print(json.dumps(out))
    else:
        print("fingerprint: %d this run, %d total (state: logs/sdkmap/fingerprints.json)" % (
            done, len(fp)))
        print("NEXT  uv run python tools/sdkmap.py try-compile %s --nnsdk-dir <nnsdk-clone> --run"
              % (key_of(addrs[0]) if addrs else "<ADDR>"))
    return 0


# ------------------------------------------------------------- try-compile

PHONE_TRY = """try-compile needs code.bin + armcc (Wine) + the nnsdk clone; none are in
this sandbox. On the phone (Termux):
  # 1. game binary (own USA dump): decompressed .code -> code.bin in the repo root
  #    (6,455,296 bytes, SHA-1 e6ab7d66ee62e879248b0660aaf38d22202e604b)
  # 2. ARM Compiler 4.1 build 1049 at tools/armcc/4.1/b1049/bin/armcc.exe
  # 3. untracked nnsdk clone:
  git clone https://github.com/3dsdecomp/nnsdk <dir>
  (cd <dir> && git checkout d50a4b89d13c929d2438abf92e5a48f039efffbf)
  # 4. then, per candidate from `sdkmap plan`:
  uv run python tools/sdkmap.py try-compile 0x{addr} --nnsdk-dir <dir> --run
  python3 tools/audit.py                  # after each registration
  uv run python tools/rebuild_check.py    # image gate must stay EXACT MATCH"""


def prereqs(cc, nnsdk_dir, sources):
    missing = []
    if not os.path.exists(CODE_BIN):
        missing.append("code.bin")
    else:
        try:
            load_binary(CODE_BIN)
        except (OSError, ValueError):
            missing.append("code.bin (wrong size/SHA-1)")
    exe = armcc_exe(cc)
    if not os.path.exists(exe):
        missing.append("armcc at %s" % os.path.relpath(exe, ROOT))
    if not nnsdk_dir or not os.path.isdir(nnsdk_dir):
        missing.append("nnsdk clone dir")
    for rel in sources:
        if nnsdk_dir and not os.path.isfile(os.path.join(nnsdk_dir, rel)):
            missing.append("nnsdk source %s" % rel)
    return missing


def suggestions_for(addr):
    for row in load_plan_state().get("candidates", []):
        if row["addr"] == key_of(addr):
            return row
    return None


def build_unit(addr, nnsdk_dir, sources):
    """Copy the mapped nnsdk source(s) + the Include tree into a
    self-contained build unit under logs/sdkmap/build/<ADDR>/ (never
    committed). Angle includes of nn/ are rewritten to quoted includes so
    fn.py check's fixed -I shared/include still resolves them relative to
    the unit file."""
    unit_dir = os.path.join(BUILD_DIR, key_of(addr))
    if os.path.isdir(unit_dir):
        shutil.rmtree(unit_dir)
    os.makedirs(unit_dir)
    parts = []
    for rel in sources:
        with open(os.path.join(nnsdk_dir, rel), encoding="utf-8", errors="replace") as fh:
            text = fh.read()
        text = re.sub(r'#include\s*<nn/([^>]*)>', r'#include "nn/\1"', text)
        dest = os.path.join(unit_dir, rel.replace("/", "__"))
        with open(dest, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        parts.append('#include "%s"' % os.path.basename(dest))
    inc_src = os.path.join(nnsdk_dir, "Include")
    if os.path.isdir(inc_src):
        shutil.copytree(inc_src, unit_dir, dirs_exist_ok=True)
    unit_path = os.path.join(unit_dir, "unit.cpp")
    with open(unit_path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(parts) + "\n")
    return unit_dir, unit_path


def record_attempt(rec):
    os.makedirs(STATE, exist_ok=True)
    with open(ATTEMPTS_FILE, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec) + "\n")


def add_sdk_note(key, note):
    """Add the sdk:nnsdk note to a just-registered entry (same free-text
    note-field convention as source_lost; audit.py stays CLEAN because the
    note is allowed on matched entries)."""
    with file_lock(os.path.join(ROOT, "logs", "worklist.lock")):
        data = read_json(FUNCTIONS)
        ent = data.get(key)
        if not ent or ent.get("status") not in ("honest", "hack"):
            raise ValueError("refusing to note a non-matched entry: " + key)
        ent["note"] = note
        write_json(FUNCTIONS, data, canonical=True)


def cmd_try_compile(addr, nnsdk_dir, sym, run, as_json, manual_sources=None):
    key = key_of(addr)
    funcs = read_json(FUNCS)
    if addr not in funcs["starts"]:
        out = {"error": "not a function start", "addr": key}
        print(json.dumps(out) if as_json else
              "try-compile requires an exact function start: " + key)
        return 2
    functions = read_json(FUNCTIONS)
    ent = functions.get(key) or {}
    cc = ent.get("cc", DEFAULT_CC)
    flags = ent.get("flags", DEFAULT_FLAGS)
    row = suggestions_for(addr)
    sources = list(manual_sources or (row or {}).get("suggested") or [])
    if not sources:
        hint = ("no suggested nnsdk sources for %s; either the plan row has name hits "
                "(run: uv run python tools/sdkmap.py plan --json) or pass the mapped "
                "nnsdk source explicitly: --source Source/math/math_VEC3.cpp" % key)
        out = {"error": "no suggestions", "addr": key, "phone_commands": hint}
        print(json.dumps(out) if as_json else hint)
        return 2
    missing = prereqs(cc, nnsdk_dir, sources)
    if missing:
        out = {"error": "try-compile cannot run here", "missing": missing,
               "phone_commands": PHONE_TRY.format(addr=key)}
        print(json.dumps(out) if as_json else PHONE_TRY.format(addr=key))
        return 2
    unit_dir, unit_path = build_unit(addr, nnsdk_dir, sources)
    rel_unit = os.path.relpath(unit_path, ROOT)
    check_cmd = ('uv run python tools/fn.py check %s 0x%s --cc %s --flags "%s"'
                 % (rel_unit, key, cc, flags))
    register_cmd = "uv run python tools/worklist.py register 0x%s --src %s" % (key, rel_unit)
    note = "sdk:nnsdk %s@%s" % ("+".join(sources), nnsdk_revision(nnsdk_dir))
    if not run:
        out = {"addr": key, "dry_run": True, "cc": cc, "flags": flags,
               "sources": sources, "unit": rel_unit,
               "commands": [check_cmd, register_cmd], "note": note}
        if as_json:
            print(json.dumps(out))
        else:
            print("try-compile %s (dry run; sources: %s)" % (key, ", ".join(sources)))
            print("  CHECK    %s" % check_cmd)
            print("  REGISTER %s" % register_cmd)
            print("  NOTE     %s   # recorded on the entry after register" % note)
            print("NEXT  on the phone add --run to execute; audit + image gate after each registration")
        record_attempt({"addr": key, "mode": "dry-run", "sources": sources,
                        "cc": cc, "flags": flags})
        return 0
    from permuter import check_one
    result = check_one(unit_dir, unit_path, addr, flags, sym, cc=cc)
    rec = {"addr": key, "mode": "run", "sources": sources, "cc": cc, "flags": flags,
           "match": bool(result["match"]), "words": result.get("words"),
           "total": result.get("total"), "err": result.get("err")}
    record_attempt(rec)
    if not result["match"]:
        out = dict(rec)
        out["phone_commands"] = check_cmd
        if as_json:
            print(json.dumps(out))
        else:
            print("try-compile %s: NO MATCH (%s/%s words)%s" % (
                key, result.get("words"), result.get("total"),
                " err: " + result["err"] if result.get("err") else ""))
            print("NEXT  %s   # inspect the diff, adjust the mapped source, retry" % check_cmd)
        return 1
    if key in functions:
        out = dict(rec, registered=False,
                   hint=("entry already exists (%s); the phone operator replaces that "
                         "entry manually, then runs: %s   (note: %s)"
                         % (ent.get("status"), register_cmd, note)))
        if as_json:
            print(json.dumps(out))
        else:
            print("try-compile %s: RESULT: MATCH, but the index already has an entry (%s)"
                  % (key, ent.get("status")))
            print("  REGISTER %s   # after the operator replaces the %s entry" % (
                register_cmd, ent.get("status")))
            print("  NOTE     %s" % note)
        return 0
    import worklist
    worklist.register(addr, src=unit_path, flags=flags, as_json=as_json)
    add_sdk_note(key, note)
    out = dict(rec, registered=True, note=note)
    if as_json:
        print(json.dumps(out))
    else:
        print("try-compile %s: RESULT: MATCH -> registered with note: %s" % (key, note))
        print("NEXT  python3 tools/audit.py && uv run python tools/rebuild_check.py")
    return 0


# ---------------------------------------------------------- status/report

def _load_attempts():
    attempts = []
    if os.path.exists(ATTEMPTS_FILE):
        with open(ATTEMPTS_FILE, encoding="utf-8") as fh:
            for line in fh:
                try:
                    attempts.append(json.loads(line))
                except ValueError:
                    pass
    return attempts


def cmd_status(as_json):
    inv = load_inventory()
    plan = load_plan_state()
    fp = load_fingerprints()
    attempts = _load_attempts()
    out = {
        "inventory": ({"files": inv["counts"]["files"],
                       "functions": inv["counts"]["functions"],
                       "revision": inv["nnsdk"]["revision"]} if inv else None),
        "plan": {"candidates": len(plan.get("candidates", [])),
                 "filters": plan.get("filters", [])},
        "fingerprints": len(fp),
        "try_compile_attempts": len(attempts),
        "try_compile_matches": sum(1 for a in attempts if a.get("match")),
    }
    if as_json:
        print(json.dumps(out))
    else:
        print("sdkmap status:")
        print("  inventory:    %s" % (out["inventory"] or "missing (run inventory with an nnsdk clone)"))
        print("  plan:         %d candidates %s" % (out["plan"]["candidates"], out["plan"]["filters"]))
        print("  fingerprints: %d" % out["fingerprints"])
        print("  try-compile:  %d attempts, %d matches" % (
            out["try_compile_attempts"], out["try_compile_matches"]))
        print("NEXT  python tools/sdkmap.py report --json")
    return 0


def cmd_report(as_json):
    plan = load_plan_state()
    fp = load_fingerprints()
    attempts = _load_attempts()
    rows = []
    for r in plan.get("candidates", []):
        f = fp.get(r["addr"]) or {}
        rows.append({"addr": r["addr"], "size": r["size"], "pool": r["pool"],
                     "score": r["score"], "difficulty": r["difficulty"],
                     "reasons": r["reasons"], "suggested": r["suggested"],
                     "fingerprinted": r["addr"] in fp,
                     "token_hash": f.get("token_hash"),
                     "n_blocks": f.get("n_blocks"), "pool_size": f.get("pool_size")})
    out = {"candidates": len(rows),
           "fingerprinted": sum(1 for r in rows if r["fingerprinted"]),
           "rows": rows, "attempts": attempts}
    if as_json:
        print(json.dumps(out))
    else:
        print("sdkmap report: %d planned candidates, %d fingerprinted" % (
            out["candidates"], out["fingerprinted"]))
        for r in rows[:30]:
            print("  %s %6dB %-6s %s %s" % (
                r["addr"], r["size"], r["difficulty"],
                ("fp:" + r["token_hash"][:8]) if r["fingerprinted"] else "-",
                "; ".join(r["reasons"][:1])))
        if len(rows) > 30:
            print("  ... %d more" % (len(rows) - 30))
        for a in attempts[-10:]:
            print("  attempt %s %s match=%s" % (a.get("addr"), a.get("mode"), a.get("match")))
        print("NEXT  uv run python tools/sdkmap.py try-compile %s --nnsdk-dir <nnsdk-clone> --run"
              % (rows[0]["addr"] if rows else "<ADDR>"))
    return 0


# --------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("inventory")
    p.add_argument("--nnsdk-dir", required=True)
    p.add_argument("--out", default=os.path.relpath(INVENTORY, ROOT))
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=lambda a: cmd_inventory(a.nnsdk_dir,
                                              os.path.join(ROOT, a.out), a.json))
    p = sub.add_parser("plan")
    p.add_argument("--filter", default="excluded_library,unmatched")
    p.add_argument("--limit", type=int, default=DEFAULT_LIMIT)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=lambda a: cmd_plan(a.filter.split(","), a.limit, a.json))
    p = sub.add_parser("fingerprint")
    p.add_argument("--addr", action="append", default=[])
    p.add_argument("--budget", type=int, default=DEFAULT_BUDGET)
    p.add_argument("--image")
    p.add_argument("--force", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=lambda a: cmd_fingerprint([int(x, 16) for x in a.addr],
                                                 a.budget, a.image, a.force, a.json))
    p = sub.add_parser("try-compile")
    p.add_argument("addr")
    p.add_argument("--nnsdk-dir", required=True)
    p.add_argument("--sym")
    p.add_argument("--source", action="append", default=[],
                   help="nnsdk source path (inside the clone) to map to this address; "
                        "repeatable; overrides the plan suggestions")
    p.add_argument("--run", action="store_true",
                   help="actually compile + register (phone only; default is a dry run)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=lambda a: cmd_try_compile(int(a.addr, 16), a.nnsdk_dir,
                                                 a.sym, a.run, a.json, a.source))
    p = sub.add_parser("status")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=lambda a: cmd_status(a.json))
    p = sub.add_parser("report")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=lambda a: cmd_report(a.json))
    args = ap.parse_args()
    sys.exit(args.fn(args) or 0)


if __name__ == "__main__":
    main()

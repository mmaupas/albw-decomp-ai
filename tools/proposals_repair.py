"""Repair proposal pass (roadmap H3): single-change source variants for near-misses.

Inspired by RetroReversing/decomp-repair (AGPL-3.0-only; ideas ported, no source
committed — see docs/AUTOMATION_PLAN.md phase 9): given an existing near-miss
candidate source, emit ordered variants, each altering ONE thing armcc 4.1 is
sensitive to: a literal's value or type, a local's lifetime, which register
carries an argument, operand order, branch arm order, explicit casts, volatile
placement.

Philosophy: PROPOSES, NEVER JUDGES. Nothing here compiles or checks; only
`fn.py check` (armcc, on the phone) judges, and only `worklist register`
registers on RESULT: MATCH. This module is pure and offline: stdlib only, no
capstone, no code.bin, deterministic given the source.

  from proposals_repair import propose, run_pass
  variants = propose(source, name="func_00100000",
                     diff={"n_op": 2, "diff_words": [{"offset": "0x10", "target": "mov r3, #0x2a"}]},
                     flags="--cpu=MPCore --fpmode=fast --apcs=/interwork -O3 -Otime --split_sections",
                     budget=12)
  # -> [{index, name, family, reason, hash, source}, ...] ordered, budgeted

Pass families (ranked by the repo's known wall classes, see shared/recipes.json
negatives + docs/LESSONS.md):
  literal_value   diff-word-driven literal nudges (fam_sti 3rd pool word class)
  branch_arm      if/else arm swap with negated guard (if-conversion / PERM class)
  bool_cast       explicit (s32) cast on a guard (bool-materialization class)
  arg_register    register hints, signedness-invariant param types, param reorder
  lifetime        local hoist / split (fresh used local) / narrow
  operand_order   commute pure commutative operands
  cast_insert     explicit narrowing cast on store RHS
  literal_type    u-suffix / (u32) cast on integer literals
  volatile_move   relocate an existing volatile qualifier to deref sites

Semantic safety: a pass that cannot prove the rewrite semantics-preserving
emits nothing. When in doubt, do not emit.
"""
import hashlib
import json
import os
import re
import time

DEFAULT_BUDGET = 12
IDENT = r"[A-Za-z_]\w*"
SCALAR = {"u8", "u16", "u32", "s8", "s16", "s32", "int", "unsigned int",
          "signed int", "char", "unsigned char", "short"}
SIGNEDNESS = {"int": "s", "signed int": "s", "s32": "s",
              "unsigned int": "u", "u32": "u"}
COMMUTATIVE = "+*&|^"
FLIP = {"==": "!=", "!=": "==", "<=": ">", ">=": "<", "<": ">=", ">": "<="}
KEYWORDS = {"return", "if", "else", "for", "while", "do", "switch", "case",
            "default", "goto", "break", "continue", "sizeof", "typedef"}
# ranked after the repo's parked wall classes: pool-word literal walls first
# (fam_sti), then branch layout (if-conversion), then bool materialization,
# then register/lifetime carrying, then the cheaper textual nudges
FAMILY_ORDER = ("literal_value", "branch_arm", "bool_cast", "arg_register",
                "lifetime", "operand_order", "cast_insert", "literal_type",
                "volatile_move")
DECL_RE = re.compile(r"^(?:const\s+|volatile\s+|static\s+|register\s+)*"
                     r"(?P<type>[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*?)\s*(?P<ptr>\*+)?\s*"
                     r"(?P<name>[A-Za-z_]\w*)\s*(?P<init>=\s*.+?)?\s*$", re.S)


# --------------------------------------------------------------- C text tools

def _blank(text):
    """Mask comments and string/char literals with spaces (length preserved)."""
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            for k in range(i, j):
                out[k] = " "
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            for k in range(i, j):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n:
                if text[j] == "\\":
                    j += 2
                    continue
                if text[j] == c:
                    j += 1
                    break
                j += 1
            for k in range(i, min(j, n)):
                if text[k] != "\n":
                    out[k] = " "
            i = j
        else:
            i += 1
    return "".join(out)


def _close(text, i, open_ch, close_ch):
    depth = 0
    for j in range(i, len(text)):
        if text[j] == open_ch:
            depth += 1
        elif text[j] == close_ch:
            depth -= 1
            if depth == 0:
                return j
    return None


def _lead(clean, s, e):
    """Leading-whitespace width of the statement span [s, e)."""
    return len(clean[s:e]) - len(clean[s:e].lstrip())


def _split_params(clean, p_open, p_close):
    params, start, depth = [], p_open + 1, 0
    for i in range(p_open + 1, p_close):
        c = clean[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == "," and depth == 0:
            params.append((start, i))
            start = i + 1
    params.append((start, p_close))
    out = []
    for s, e in params:
        text = clean[s:e]
        stripped = text.strip()
        if not stripped or stripped == "void":
            continue
        m = re.search(r"\b(%s)\s*(\[[^\]]*\])?\s*$" % IDENT, stripped)
        if not m:
            continue  # function-pointer or complex declarator: no safe rewrite
        name = m.group(1)
        lead = len(text) - len(text.lstrip())
        ptype = stripped[: m.start()].strip()
        if not ptype:
            continue
        out.append({"start": s, "end": e, "text": stripped, "type": ptype,
                    "name": name, "type_start": s + lead,
                    "type_end": s + lead + m.start()})
    return out


def _function_ctx(source, name=None):
    """Locate one function definition: params + body span, on the blanked text."""
    clean = _blank(source)
    if name:
        m = re.search(r"\b%s\s*\(" % re.escape(name), clean)
        if not m:
            return None
        p_open = m.end() - 1
        p_close = _close(clean, p_open, "(", ")")
        if p_close is None:
            return None
        brace = re.compile(r"\{").search(clean, p_close)
        if not brace:
            return None
        open_i = brace.start()
    else:
        m = re.search(r"\)\s*\{", clean)
        if not m:
            return None
        open_i = clean.index("{", m.start())
        depth, p_open = 0, None
        for j in range(m.start(), -1, -1):
            if clean[j] == ")":
                depth += 1
            elif clean[j] == "(":
                depth -= 1
                if depth == 0:
                    p_open = j
                    break
        if p_open is None:
            return None
        p_close = m.start()
    close_i = _close(clean, open_i, "{", "}")
    if close_i is None:
        return None
    return {"clean": clean, "open": open_i, "close": close_i,
            "p_open": p_open, "p_close": p_close,
            "params": _split_params(clean, p_open, p_close),
            "body": (open_i + 1, close_i)}


def _stmts(clean, open_i, close_i):
    """Statements of a block at brace depth 0: (start, end) spans, ';' included."""
    out, depth, start, i = [], 0, open_i + 1, open_i + 1
    while i < close_i:
        c = clean[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
        elif c == ";" and depth == 0:
            out.append((start, i + 1))
            start = i + 1
        i += 1
    return out


def _stmts_deep(clean, open_i, close_i):
    """Every statement at any depth: (start, end, depth) spans, ';' included."""
    out, depth, start = [], 0, open_i + 1
    for i in range(open_i + 1, close_i):
        c = clean[i]
        if c == "{":
            depth += 1
            start = i + 1
        elif c == "}":
            depth -= 1
        elif c == ";":
            out.append((start, i + 1, depth))
            start = i + 1
    return out


def _stmt_depth(clean, open_i, close_i, pos):
    depth = 0
    for j in range(open_i + 1, pos):
        if clean[j] == "{":
            depth += 1
        elif clean[j] == "}":
            depth -= 1
    return depth


def _decl_of(clean, s, e):
    text = clean[s:e].strip().rstrip(";").strip()
    if not text or text.startswith("#"):
        return None
    m = DECL_RE.match(text)
    if not m or m.group("type").strip() in KEYWORDS:
        return None
    return {"type": m.group("type").strip(), "ptr": m.group("ptr") or "",
            "name": m.group("name"),
            "init": (m.group("init") or "").strip(), "text": text}


def _refs(clean, body, name):
    return list(re.finditer(r"\b%s\b" % re.escape(name), clean[body[0]:body[1]]))


def _blocks(clean, body):
    """Nested (depth-1) block spans of the body: [(open, close), ...]."""
    out, depth = [], 0
    for i in range(body[0], body[1]):
        if clean[i] == "{":
            depth += 1
            if depth == 1:
                out.append([i, None])
        elif clean[i] == "}":
            if depth == 1 and out and out[-1][1] is None:
                out[-1][1] = i
            depth -= 1
    return [(a, b) for a, b in out if b is not None]


def _has_control_flow(clean, body):
    b = clean[body[0]:body[1]]
    return bool(re.search(r"\b(goto|switch|case|default|break|continue|for|while|do)\b", b)
                or re.search(r"(?m)^\s*[A-Za-z_]\w*\s*:", b))


def _apply(source, edits):
    text = source
    for a, b, new in sorted(edits, key=lambda x: x[0], reverse=True):
        text = text[:a] + new + text[b:]
    return text


def _hash(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _int_literals(clean, body):
    """Integer literals of the body that are values, not offsets/sizes:
    skip literals directly preceded by + - # , (pointer arithmetic, pool idx)."""
    out = []
    b = clean[body[0]:body[1]]
    for m in re.finditer(r"\b0x[0-9a-fA-F]+\b|\b\d+\b", b):
        k = m.start() - 1
        while k >= 0 and b[k].isspace():
            k -= 1
        if k >= 0 and b[k] in "+-#,":
            continue
        out.append((body[0] + m.start(), body[0] + m.end(), m.group(0)))
    return out


def normalize_diff(diff):
    """Normalize refine-state diff metadata: metric keys + diff_words rows."""
    d = dict(diff or {})
    words, seen = [], set()
    for row in d.get("diff_words") or []:
        if isinstance(row, dict):
            target, off = row.get("target") or "", row.get("offset")
        elif isinstance(row, int):
            target, off = "0x%x" % row, None
        else:
            target, off = str(row), None
        for m in re.finditer(r"0x[0-9a-fA-F]+|\b\d+\b", target):
            v = int(m.group(0), 0)
            if v not in seen:
                seen.add(v)
                words.append({"offset": off, "value": v, "text": target.strip()[:48]})
    d["diff_words"] = words
    return d


# ------------------------------------------------------------------ the passes

def _pass_literal_value(source, ctx, diff, flags):
    out = []
    words = diff.get("diff_words") or []
    if not words:
        return out
    for ls, le, lit in _int_literals(ctx["clean"], ctx["body"])[:8]:
        cur = int(lit, 0)
        for w in words[:6]:
            v = w["value"]
            if v == cur or v > 0xFFFFFFFF:
                continue
            out.append(("literal value: %s -> 0x%x (diff word '%s' at %s; fam_sti pool-word class)"
                        % (lit, v, w["text"], w["offset"]), [(ls, le, "0x%x" % v)]))
    return out[:12]


def _stmt_extent(clean, i):
    j = i
    while j < len(clean) and clean[j].isspace():
        j += 1
    if j < len(clean) and clean[j] == "{":
        c = _close(clean, j, "{", "}")
        return (c + 1) if c is not None else j
    depth = 0
    while j < len(clean):
        c = clean[j]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
        elif c == ";" and depth == 0:
            return j + 1
        j += 1
    return j


def _if_extent(clean, i):
    """(cond_span, then_span, else_span_or_None, full_end) of an if statement."""
    m = re.match(r"if\s*\(", clean[i:])
    if not m:
        return None
    p_open = i + m.end() - 1
    p_close = _close(clean, p_open, "(", ")")
    if p_close is None:
        return None
    cond = (p_open + 1, p_close)
    j = p_close + 1
    while j < len(clean) and clean[j].isspace():
        j += 1
    then_end = _stmt_extent(clean, j)
    then = (j, then_end)
    k = then_end
    while k < len(clean) and clean[k].isspace():
        k += 1
    els = None
    if clean.startswith("else", k) and not re.match(r"else\w", clean[k:]):
        k += 4
        while k < len(clean) and clean[k].isspace():
            k += 1
        if re.match(r"if\s*\(", clean[k:]):
            sub = _if_extent(clean, k)
            if sub:
                els = (k, sub[3])
                k = sub[3]
        else:
            els = (k, _stmt_extent(clean, k))
            k = els[1]
    return cond, then, els, k


def _pass_branch_arm(source, ctx, diff, flags):
    out = []
    clean, body = ctx["clean"], ctx["body"]
    for m in list(re.finditer(r"\bif\s*\(", clean[body[0]:body[1]]))[:4]:
        i = body[0] + m.start()
        ext = _if_extent(clean, i)
        if not ext:
            continue
        cond, then, els, end = ext
        if els is None:
            continue
        cond_text = clean[cond[0]:cond[1]]
        if re.search(r"\+\+|--|(?<![=!<>+\-*/%&|^])=(?!=)", cond_text):
            continue  # guard must stay single-evaluation and side-effect-free
        then_text = source[then[0]:then[1]]
        els_text = source[els[0]:els[1]]
        out.append(("branch arm order: swap then/else arms, negate guard (if-conversion / branch-layout wall)",
                    [(i, end, "if (!(%s)) %s else %s" % (cond_text, els_text, then_text))]))
        cm = re.fullmatch(r"\s*(.+?)\s*(==|!=|<=|>=|<|>)\s*(.+?)\s*", cond_text)
        if cm and not re.search(r"&&|\|\|", cond_text):
            flip = FLIP[cm.group(2)]
            out.append(("branch arm order: swap arms, flip comparison %s -> %s (branch-cond-flip PERM class)"
                        % (cm.group(2), flip),
                        [(i, end, "if (%s %s %s) %s else %s"
                          % (cm.group(1), flip, cm.group(3), els_text, then_text))]))
    return out[:6]


def _pass_bool_cast(source, ctx, diff, flags):
    out = []
    clean, body = ctx["clean"], ctx["body"]
    for m in list(re.finditer(r"\bif\s*\(", clean[body[0]:body[1]]))[:4]:
        i = body[0] + m.start()
        ext = _if_extent(clean, i)
        if not ext:
            continue
        cond = ext[0]
        cond_text = clean[cond[0]:cond[1]]
        if re.match(r"\s*\(\s*(?:s32|u32|int|unsigned|s16|u16|s8|u8)\s*\)\s*\(", cond_text):
            continue
        out.append(("bool-materialization: explicit (s32) cast on guard '%s' (neg-bool-materialized-guard wall)"
                    % " ".join(cond_text.split()),
                    [(cond[0], cond[1], "(s32)(%s)" % cond_text)]))
    return out[:4]


def _pass_arg_register(source, ctx, diff, flags):
    out = []
    clean, body, params = ctx["clean"], ctx["body"], ctx["params"]
    for p in params[:4]:
        if "*" in p["type"] or re.search(r"\bregister\b", p["text"]):
            continue
        out.append(("arg-carrying: register storage-class hint on param '%s' (which register carries the arg)"
                    % p["name"], [(p["start"], p["start"], "register ")]))
    for p in params[:6]:
        t = " ".join(p["type"].split())
        if t not in SIGNEDNESS:
            continue
        uses = _refs(clean, body, p["name"])
        if uses and not all(re.match(r"\s*(==|!=)\s*0\b", clean[body[0] + u.end(): body[0] + u.end() + 12])
                           for u in uses):
            continue  # signedness could be observable: do not emit
        alts = ["unsigned int", "u32"] if SIGNEDNESS[t] == "s" else ["int", "s32"]
        for alt in alts[:2]:
            out.append(("arg-carrying: param '%s' type %s -> %s (uses are 0-tests only, signedness-invariant; register-class via type)"
                        % (p["name"], t, alt),
                        [(p["type_start"], p["type_end"], alt)]))
    for i in range(len(params) - 1):
        a, b = params[i], params[i + 1]
        ta, tb = " ".join(a["type"].split()), " ".join(b["type"].split())
        if ta != tb or "*" in ta:
            continue
        ra = _refs(clean, body, a["name"])
        rb = _refs(clean, body, b["name"])
        if len(ra) != 1 or len(rb) != 1:
            continue
        m = re.search(r"\b(%s)\s*([+*&|^])\s*(%s)\b" % (re.escape(a["name"]), re.escape(b["name"])),
                      clean[body[0]:body[1]]) or \
            re.search(r"\b(%s)\s*([+*&|^])\s*(%s)\b" % (re.escape(b["name"]), re.escape(a["name"])),
                      clean[body[0]:body[1]])
        if not m or m.group(2) not in COMMUTATIVE:
            continue
        if not ((ra[0].start() == m.start(1) and rb[0].start() == m.start(3))
                or (rb[0].start() == m.start(1) and ra[0].start() == m.start(3))):
            continue
        edits = [(a["start"], a["end"], b["text"]), (b["start"], b["end"], a["text"]),
                 (body[0] + m.start(1), body[0] + m.end(3),
                  "%s %s %s" % (m.group(3), m.group(2), m.group(1)))]
        out.append(("arg-carrying: param reorder %s <-> %s with commutative single use (alpha-rename keeps semantics)"
                    % (a["name"], b["name"]), edits))
        if len([r for r, _ in out if "param reorder" in r]) >= 2:
            break
    for s, e in _stmts(clean, ctx["open"], ctx["close"])[:6]:
        d = _decl_of(clean, s, e)
        if not d or d["ptr"] or d["init"] or re.search(r"\bregister\b", d["text"]):
            continue
        if d["type"] not in SCALAR:
            continue
        at = s + _lead(clean, s, e)
        out.append(("local register hint: register on '%s' (live-range/register carrying)" % d["name"],
                    [(at, at, "register ")]))
    return out[:10]


def _pass_lifetime(source, ctx, diff, flags):
    out = []
    clean, body = ctx["clean"], ctx["body"]
    btext = clean[body[0]:body[1]]
    all_stmts = _stmts_deep(clean, ctx["open"], ctx["close"])
    decls = [(s, e, dth, d) for s, e, dth in all_stmts if (d := _decl_of(clean, s, e))]
    # hoist: a declaration inside a nested block moves to function scope
    for s, e, depth, d in decls:
        if len([r for r, _ in out if "hoist" in r]) >= 3 or depth < 1:
            continue
        x = d["name"]
        if re.search(r"&\s*%s\b" % re.escape(x), btext) or _has_control_flow(clean, body):
            continue
        if len([1 for _, _, _, dd in decls if dd["name"] == x]) > 1:
            continue  # shadowing: not provably safe
        if d["init"] and re.search(r"\b%s\b" % re.escape(x), d["init"]):
            continue
        decl_line = "%s %s%s;" % (d["type"], d["ptr"], x)
        repl = ("%s = %s;" % (x, d["init"][1:].strip())) if d["init"] else ""
        lead = _lead(clean, s, e)
        out.append(("local lifetime: hoist '%s' declaration to function scope, init kept at original site (armcc slot/liveness wall)" % x,
                    [(s + lead, e, repl), (ctx["open"] + 1, ctx["open"] + 1, "\n    " + decl_line)]))
    if _has_control_flow(clean, body):
        return out  # split/narrow need straight-line top level
    top = [(s, e, d) for s, e, depth, d in decls if depth == 0]
    # split: a second top-level assignment starts a fresh, used phase local
    for s, e, d in top[:4]:
        x = d["name"]
        if re.search(r"&\s*%s\b" % re.escape(x), btext):
            continue
        defs = [(s, e)] if d["init"] else []
        for s2, e2, _ in all_stmts:
            t = clean[s2:e2].strip().rstrip(";").strip()
            if re.match(r"^%s\s*=(?!=)" % re.escape(x), t):
                defs.append((s2, e2))
        if len(defs) < 2:
            continue
        s2, e2 = defs[1]
        fresh = "%s__r1" % x
        if re.search(r"\b%s\b" % fresh, clean):
            continue
        later = [u for u in _refs(clean, body, x) if body[0] + u.start() >= e2]
        if not later:
            continue  # nothing uses the later phase: the split would be a dummy
        off = _lead(clean, s2, e2)
        edits = [(e, e, "\n    %s %s;" % (d["type"], fresh)),
                 (s2 + off, s2 + off + len(x), fresh)]
        for u in later:
            edits.append((body[0] + u.start(), body[0] + u.end(), fresh))
        out.append(("local lifetime: split '%s' into phase local '%s' after its 2nd assignment (fresh local is used; liveness wall)" % (x, fresh), edits))
        if len([r for r, _ in out if "split" in r]) >= 2:
            break
    # narrow: all uses inside one nested block -> move the declaration there
    for s, e, d in top[:4]:
        if len([r for r, _ in out if "narrow" in r]) >= 2:
            continue
        x = d["name"]
        if re.search(r"&\s*%s\b" % re.escape(x), btext):
            continue
        uses = [u for u in _refs(clean, body, x) if not (s <= body[0] + u.start() < e)]
        if not uses:
            continue
        first, last = body[0] + uses[0].start(), body[0] + uses[-1].end()
        region = None
        for bs, be in _blocks(clean, body):
            if bs < first and last < be:
                region = (bs, be)
                break
        if region is None:
            continue
        out.append(("local lifetime: narrow '%s' scope into its single use block" % x,
                    [(s, e, ""), (region[0] + 1, region[0] + 1, "\n    " + d["text"] + ";")]))
    return out[:8]


def _commute(rhs):
    """(a, op, b) when rhs is exactly one top-level commutative op of pure
    operands, else None."""
    pure = re.compile(r"^(?:%s|0x[0-9a-fA-F]+|\d+)$" % IDENT)
    depth, op, at = 0, None, -1
    for i, ch in enumerate(rhs):
        if ch in "([":
            depth += 1
        elif ch in ")]":
            depth -= 1
        elif depth == 0 and ch in COMMUTATIVE:
            if op is not None:
                return None
            op, at = ch, i
    if op is None:
        return None
    a, b = rhs[:at].strip(), rhs[at + 1:].strip()
    if not pure.match(a) or not pure.match(b):
        return None
    return a, op, b


def _pass_operand_order(source, ctx, diff, flags):
    out = []
    clean = ctx["clean"]
    for s, e in _stmts(clean, ctx["open"], ctx["close"]):
        if len(out) >= 6 or _stmt_depth(clean, ctx["open"], ctx["close"], s) != 0:
            continue
        t = clean[s:e].strip().rstrip(";").strip()
        m = re.match(r"^(.*?)(%s)\s*=\s*(.+)$" % IDENT, t, re.S)
        if not m:
            continue
        lhs, rhs = m.group(2), m.group(3)
        c = _commute(rhs)
        if not c or re.search(r"\b%s\b" % re.escape(lhs), rhs):
            continue
        a, op, b = c
        lead = _lead(clean, s, e)
        out.append(("operand order: commute '%s %s %s' (armcc operand allocation; commutative pure operands)" % (a, op, b),
                    [(s + lead, e, "%s%s = %s %s %s;" % (t[: m.start(2)], lhs, b, op, a))]))
    return out


def _pass_cast_insert(source, ctx, diff, flags):
    out = []
    clean = ctx["clean"]
    for s, e in _stmts(clean, ctx["open"], ctx["close"]):
        if len(out) >= 4 or _stmt_depth(clean, ctx["open"], ctx["close"], s) != 0:
            continue
        t = clean[s:e].strip().rstrip(";").strip()
        m = re.match(r"^(\*\s*\(\s*(u8|u16|u32|s8|s16|s32)\s*\*\s*\).*?)=\s*(.+)$", t, re.S)
        if not m:
            continue
        lhs, rhs, width = m.group(1), m.group(3).strip(), m.group(2)
        if re.search(r"\b%s\s*\(" % IDENT, rhs) or "++" in rhs or "--" in rhs:
            continue  # RHS must be side-effect-free
        if re.match(r"^\(\s*%s\s*\)\s*\(" % width, rhs):
            continue  # already cast to the store width
        off = _lead(clean, s, e) + t.index(rhs)
        out.append(("explicit cast: (%s) on store RHS (truncation / bool-materialization class)" % width,
                    [(s + off, s + off + len(rhs), "(%s)(%s)" % (width, rhs))]))
    return out


def _pass_literal_type(source, ctx, diff, flags):
    out = []
    for ls, le, lit in _int_literals(ctx["clean"], ctx["body"])[:6]:
        if len(out) >= 8:
            break
        out.append(("literal type: (u32) cast on %s (pool word typing)" % lit,
                    [(ls, le, "(u32)%s" % lit)]))
        out.append(("literal type: u suffix on %s (unsigned pool word)" % lit,
                    [(ls, le, "%su" % lit)]))
    return out[:8]


def _pass_volatile_move(source, ctx, diff, flags):
    out = []
    clean, body = ctx["clean"], ctx["body"]
    for s, e in _stmts(clean, ctx["open"], ctx["close"]):
        if len(out) >= 2 or _stmt_depth(clean, ctx["open"], ctx["close"], s) != 0:
            continue
        t = clean[s:e].strip().rstrip(";").strip()
        m = re.match(r"^volatile\s+(%s)\s*\*\s*(%s)\s*(?:=\s*.+)?$" % (IDENT, IDENT), t)
        if not m:
            continue
        typ, p = m.group(1), m.group(2)
        uses = [u for u in _refs(clean, body, p) if not (s <= body[0] + u.start() < e)]
        if not uses:
            continue
        edits, ok = [], True
        for u in uses:
            ustart = body[0] + u.start()
            if ustart == 0 or clean[ustart - 1] != "*":
                ok = False  # p[i], p->f, &p, f(p): not a simple deref -> skip
                break
            edits.append((ustart - 1, ustart + len(p), "*(volatile %s *)%s" % (typ, p)))
        if not ok:
            continue
        edits.append((s + _lead(clean, s, e), s + _lead(clean, s, e) + len("volatile"), ""))
        out.append(("volatile placement: move volatile from '%s *%s' declaration to its deref sites" % (typ, p), edits))
    return out


PASSES = {"literal_value": _pass_literal_value, "branch_arm": _pass_branch_arm,
          "bool_cast": _pass_bool_cast, "arg_register": _pass_arg_register,
          "lifetime": _pass_lifetime, "operand_order": _pass_operand_order,
          "cast_insert": _pass_cast_insert, "literal_type": _pass_literal_type,
          "volatile_move": _pass_volatile_move}


# ------------------------------------------------------------------- entry API

def run_pass(source, name=None, diff=None, flags=None, budget=DEFAULT_BUDGET,
             skip_hashes=()):
    """All repair variants of `source`, ordered by family rank, within budget.

    Returns {variants, skipped, families, seconds, budget}; `variants` is the
    ordered list of {index, name, family, reason, hash, source}. `skipped`
    counts cache hits (skip_hashes) and duplicates. Deterministic in `variants`.
    """
    t0 = time.perf_counter()
    diff = normalize_diff(diff)
    order = list(FAMILY_ORDER)
    if flags and "-O2" in flags.split():
        # recipe zero-loop-r2: at -O2 a live 2nd arg pins the value in r2, so
        # register/lifetime carrying outranks branch layout
        order = [f for f in ("arg_register", "lifetime") if f in order] + \
                [f for f in order if f not in ("arg_register", "lifetime")]
    ctx = _function_ctx(source, name)
    variants, seen = [], {source}
    skipped, families = 0, {}
    if ctx:
        for fam in order:
            for reason, edits in PASSES[fam](source, ctx, diff, flags):
                text = _apply(source, edits)
                if text == source or text in seen:
                    skipped += 1
                    continue
                h = _hash(text)
                if h in skip_hashes:
                    skipped += 1
                    continue
                seen.add(text)
                variants.append({"index": len(variants) + 1,
                                 "name": "repair#%02d" % (len(variants) + 1),
                                 "family": fam, "reason": reason,
                                 "hash": h, "source": text})
                families[fam] = families.get(fam, 0) + 1
                if budget is not None and len(variants) >= budget:
                    break
            if budget is not None and len(variants) >= budget:
                break
    return {"variants": variants, "skipped": skipped, "families": families,
            "seconds": time.perf_counter() - t0, "budget": budget}


def propose(source, name=None, diff=None, flags=None, budget=DEFAULT_BUDGET,
            skip_hashes=()):
    """Ordered list of repair variants: [{name, reason, source, ...}, ...].

    Pure proposal: nothing is compiled, checked, or registered here.
    """
    return run_pass(source, name=name, diff=diff, flags=flags, budget=budget,
                    skip_hashes=skip_hashes)["variants"]


def load_rejected_hashes(root, addr, state_dir=None):
    """Read-only union of recorded rejected variant hashes for one target:
    the refine state's rejected_hashes plus the permuter's tried-candidates
    cache (logs/permuter/<addr8>/tried.txt) when present."""
    out = set()
    sd = state_dir or os.path.join(root, "logs", "refine", "%08X" % addr)
    sp = os.path.join(sd, "state.json")
    if os.path.exists(sp):
        try:
            with open(sp, encoding="utf-8") as fh:
                st = json.load(fh)
            out |= {h for h in (st.get("rejected_hashes") or []) if isinstance(h, str)}
        except (ValueError, OSError):
            pass
    tried = os.path.join(root, "logs", "permuter", "%08X" % addr, "tried.txt")
    if os.path.exists(tried):
        with open(tried, encoding="utf-8") as fh:
            out |= {ln.strip() for ln in fh if ln.strip()}
    return out

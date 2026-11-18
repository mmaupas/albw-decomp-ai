"""Generate Zakuro input replays (ZAKURO_REPLAY files) for coverage scenarios.

  python tools/coverage_scenarios.py build [--out-dir tools/coverage-scenarios]
  python tools/coverage_scenarios.py list

A scenario is a Python list of "holds": press some buttons from frame F for D
frames. `build` expands them into the plain-text replay format zakuro-core's
replay::Replay reads:

  clock <millis since 1900>
  <frame> <buttons-hex> <circle_x> <circle_y> <touch_x> <touch_y>

one line per input *change* (a hold = on-change at F, off-change at F+D).
The fixed clock makes every run bit-reproducible; ZAKURO_REPLAY also makes
zakuro start its clock at that value, so replays are self-contained.

Button bits (zakuro_core::services::hid::PadState):
  A=0x001 B=0x002 SELECT=0x004 START=0x008 RIGHT=0x010 LEFT=0x020 UP=0x040
  DOWN=0x080 R=0x100 L=0x200 X=0x400 Y=0x800 ZL=0x4000 ZR=0x8000
  C_STICK_RIGHT=0x1000000 ... CIRCLE_RIGHT=0x10000000 CIRCLE_LEFT=0x20000000
  CIRCLE_UP=0x40000000 CIRCLE_DOWN=0x80000000

Scenarios are hand-tuned against coverage deltas + dumped screens
(ZAKURO_DUMP_AT), not against what we wish the game did — each scenario's
header comment records what it actually reached when last run.
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import ROOT

DEFAULT_OUT = os.path.join(ROOT, "tools", "coverage-scenarios")
CLOCK = 3972412800000  # 2026-11-18T00:00:00Z in millis since 1900; fixed for reproducibility

BUTTONS = {
    "A": 0x001, "B": 0x002, "SELECT": 0x004, "START": 0x008,
    "RIGHT": 0x010, "LEFT": 0x020, "UP": 0x040, "DOWN": 0x080,
    "R": 0x100, "L": 0x200, "X": 0x400, "Y": 0x800,
    "ZL": 0x4000, "ZR": 0x8000,
    "CSRIGHT": 0x1000000, "CSLEFT": 0x2000000, "CSUP": 0x4000000, "CSDOWN": 0x8000000,
    "CRIGHT": 0x10000000, "CLEFT": 0x20000000, "CUP": 0x40000000, "CDOWN": 0x80000000,
}


def hold(frame, dur, *buttons, touch=None, circle=None):
    """one hold: (frame, dur, buttons-bitmask, touch, circle)"""
    bits = 0
    for b in buttons:
        bits |= BUTTONS[b.upper()]
    return (frame, dur, bits, touch, circle)


def tap(frame, *buttons, touch=None, circle=None, dur=6):
    return hold(frame, dur, *buttons, touch=touch, circle=circle)


def mash(start, end, period=40, press=4):
    """the ZAKURO_MASH_BUTTONS pattern from zakuro's boot example, as explicit holds:
    every `period` frames, one button of the cycle held for `press` frames + a touch tap"""
    order = ["A", "B", "START", "SELECT", "X", "Y", "UP", "DOWN"]
    out = []
    frame = start
    while frame < end:
        b = order[((frame - start) // period) % len(order)]
        tapno = ((frame - start) // period) % 30
        x = 40 + (tapno % 5) * 60
        y = 30 + ((tapno // 5) % 6) * 35
        out.append(hold(frame, press, b, touch=(x, y)))
        frame += period
    return out


def walk(start, dur, direction):
    """hold a dpad direction + a full circle-pad push in the same direction (walking)"""
    circle = {"UP": (0.0, -1.0), "DOWN": (0.0, 1.0), "LEFT": (-1.0, 0.0), "RIGHT": (1.0, 0.0)}[direction]
    return hold(start, dur, direction, circle=circle)


# ---------------------------------------------------------------- scenarios
# Each entry: name -> (frames, [holds], notes)
# Frames are 59.83 Hz, so 600 frames ~= 10 s of game time.

SCENARIOS = {}

SCENARIOS["title-600"] = (
    600,
    [],
    "no input; boots to the title screen and idles (the 2026-11-07 baseline run)",
)

SCENARIOS["mash-1800"] = (
    1800,
    mash(0, 1800),
    "ZAKURO_MASH_BUTTONS pattern baked in: cycles A,B,START,SELECT,X,Y,UP,DOWN with a "
    "touch tap every 40 frames; blitzes through title / file select / new-game screens",
)

SCENARIOS["press-start-1200"] = (
    1200,
    [tap(f, "START") for f in range(300, 1200, 120)] + [tap(f, "A") for f in range(360, 1200, 120)],
    "periodic START+A to advance menus and dismiss dialogs",
)


def attack_mash(start, end, period=60):
    """alternate A/B presses (sword swings / item use) with short gaps"""
    out = []
    for i, f in enumerate(range(start, end, period)):
        out.append(tap(f, "A" if i % 2 == 0 else "B", dur=5))
        out.append(tap(f + 20, "A", dur=5))
    return out


def roam(start, end, leg=240, stride=300):
    """walk in a slow square pattern: each leg holds a direction + circle pad"""
    out = []
    for i, f in enumerate(range(start, end, stride)):
        out.append(walk(f, leg, ["UP", "RIGHT", "DOWN", "LEFT"][i % 4]))
    return out


SCENARIOS["walk-combat-1800"] = (
    1800,
    mash(0, 1200) + roam(1200, 1800) + attack_mash(1200, 1800),
    "mash thru the title/file screens for 1200 frames, then roam in a square "
    "pattern while mashing A/B (walking + combat); validated on the EU cart",
)

SCENARIOS["menu-1200"] = (
    1200,
    mash(0, 900) + [hold(f, 30, "START") for f in range(900, 1200, 90)]
    + [tap(f, d) for f in range(960, 1200, 60) for d in ("DOWN", "A", "UP", "A")],
    "mash to reach gameplay, then open the pause menu (START) and page through it",
)

# Scenario families to grow once a USA ROM is supplied: load-save (file
# select on an existing save), area transitions (walk through doors /
# Hyrule gates), dungeon combat, shop/menu browsing, etc. Tune each by
# watching the per-scenario coverage delta and ZAKURO_DUMP_AT screens.


def expand(holds):
    """holds -> sorted list of (frame, buttons, circle_x, circle_y, touch_x, touch_y) changes.

    Builds the per-frame input state, then emits one line per change (what
    replay::Replay expects). Simultaneous holds OR their buttons together.
    """
    NONE = (0, 0.0, 0.0, -1, -1)
    state = {}
    for frame, dur, bits, touch, circle in holds:
        cx, cy = circle if circle else (0.0, 0.0)
        tx, ty = touch if touch else (-1, -1)
        for f in range(frame, frame + dur):
            cur = state.get(f, NONE)
            state[f] = (cur[0] | bits,
                        cx if circle else cur[1],
                        cy if circle else cur[2],
                        tx if touch else cur[3],
                        ty if touch else cur[4])
    changes = []
    prev = NONE
    last = max(state) if state else 0
    for f in range(0, last + 2):
        s = state.get(f, NONE)
        if s != prev:
            changes.append((f,) + s)
            prev = s
    return changes


def render(frames, holds):
    """pure replay format: `clock` line first, then one line per input change
    (zakuro's replay::Replay reads no comments)"""
    lines = ["clock %d" % CLOCK]
    for f, b, cx, cy, tx, ty in expand(holds):
        lines.append("%d %x %.1f %.1f %d %d" % (f, b, cx, cy, tx, ty))
    return "\n".join(lines) + "\n"


def cmd_build(args):
    os.makedirs(args.out_dir, exist_ok=True)
    index = {}
    for name, (frames, holds, notes) in sorted(SCENARIOS.items()):
        path = os.path.join(args.out_dir, name + ".replay")
        with open(path, "w", encoding="utf-8") as f:
            f.write(render(frames, holds))
        index[name] = {"replay": os.path.basename(path), "frames": frames,
                       "changes": len(expand(holds)), "notes": notes}
        print("wrote %s (%d input changes, %d frames)" % (path, len(expand(holds)), frames))
    import json
    with open(os.path.join(args.out_dir, "index.json"), "w", encoding="utf-8") as f:
        json.dump(index, f, indent=1)
        f.write("\n")
    print("wrote %s" % os.path.join(args.out_dir, "index.json"))
    return 0


def cmd_list(args):
    for name, (frames, holds, notes) in sorted(SCENARIOS.items()):
        print("%-18s %5d frames  %4d holds  %s" % (name, frames, len(holds), notes))
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("build", help="write *.replay files")
    p.add_argument("--out-dir", default=DEFAULT_OUT)
    p.set_defaults(func=cmd_build)
    p = sub.add_parser("list")
    p.set_defaults(func=cmd_list)
    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())

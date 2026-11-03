"""Exact/near ops-sequence twin scanner.

Finds remaining worklist candidates whose mnemonic-op sequence exactly
matches (or shares an 8-op prefix with) an already-honest-matched
function — the highest-probability targets for the twin-source
adaptation workflow.

  python tools/ops_twins.py            # summary
  python tools/ops_twins.py --full     # list every candidate with its twin

Reads only logs/dna.jsonl + functions.json + the triage candidate list;
no compiler runs.
"""
import collections
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dna

ROOT = dna.ROOT


def scan():
    idx = dna.load_index()
    status = dna.load_status()
    honest = {a for a, st in status.items() if st.get('status') == 'honest'}

    cands = set()
    with open(os.path.join(ROOT, 'logs', 'triage', 'unindexed_candidate.txt')) as f:
        for line in f:
            parts = line.split()
            if parts:
                cands.add(parts[0])

    by_full = collections.defaultdict(lambda: {'honest': [], 'cand': []})
    by_prefix = collections.defaultdict(lambda: {'honest': [], 'cand': []})
    for e in idx:
        if not e['ops']:
            continue
        if e['addr'] in honest:
            by_full[e['ops']]['honest'].append(e['addr'])
            by_prefix[' '.join(e['ops'].split()[:8])]['honest'].append(e['addr'])
        elif e['addr'] in cands:
            by_full[e['ops']]['cand'].append(e['addr'])
            by_prefix[' '.join(e['ops'].split()[:8])]['cand'].append(e['addr'])

    exact = [(d['cand'], d['honest'], s) for s, d in sorted(by_full.items())
             if d['honest'] and d['cand']]
    prefix = [(d['cand'], d['honest'], s) for s, d in sorted(by_prefix.items())
              if d['honest'] and d['cand']
              and s not in {s for _, _, s in exact}]
    return exact, prefix


def main():
    argv = sys.argv[1:]
    exact, prefix = scan()
    print(f"exact full-ops twin groups: {len(exact)} "
          f"({sum(len(c) for c, _, _ in exact)} candidates)")
    for c, h, ops in exact:
        print(f"  cand {c}\n    <- honest {h}\n    ops: {ops}")
    if '--full' in argv:
        print(f"\n8-op-prefix twin groups: {len(prefix)} "
              f"({sum(len(c) for c, _, _ in prefix)} candidates)")
        for c, h, ops in prefix:
            print(f"  {len(c):3d} cand {c[:6]}{'...' if len(c) > 6 else ''}"
                  f" <- {len(h):3d} honest  [{ops}]")


if __name__ == '__main__':
    main()

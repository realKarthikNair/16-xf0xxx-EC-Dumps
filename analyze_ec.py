#!/usr/bin/env python3
"""EC register analysis utility

This script inspects Embedded Controller dump files (``.rw``) organized in
subfolders representing different operating states and prints a series of
generic reports to help discover control, status, and gating registers.

Key capabilities:
- Build a per-register signature across groups to compare representative values.
- Report registers that differ between two groups.
- Report registers that increase notably between a base and a target group.
- Detect registers with stable bit flips relative to a base group across others.
- Identify registers that remain nearly stable across some groups but jump in another.
- Optionally, find registers whose values match a reference register across groups.

Invocation examples:
  python3 analyze_ec.py
  python3 analyze_ec.py --groups beforeomen omenauto lowestmanual rampedupmanual max \
      --match-ref 0x11 --min-matches 3 \
      --diff lowestmanual rampedupmanual \
      --spike omenauto max --min-target 0x30 --min-delta 0x0A \
      --stable-flips beforeomen lowestmanual rampedupmanual --masks 0x01 0x02 0x10 0x40 \
      --near-stable lowestmanual rampedupmanual --base omenauto --target max

If no options are provided, the script attempts a set of sensible default
reports based on common group names. Reports that require unavailable groups
are skipped automatically.
"""
from __future__ import annotations
import os
import re
from collections import defaultdict
from typing import Dict, List, Tuple
import argparse

ROOT = os.path.dirname(os.path.abspath(__file__))


def parse_rw(path: str) -> Dict[int, int]:
    """Parse a single ``.rw`` dump file into a mapping of register->value.

    The expected format is space-separated ``ADDR=VAL`` pairs per line with
    hexadecimal bytes (e.g., ``10=00 11=14``). Lines without assignments are
    ignored. Only the last occurrence of a register on a line/file is kept.
    """
    data: Dict[int, int] = {}
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or '=' not in line:
                continue
            for token in line.split():
                if '=' not in token:
                    continue
                addr_s, val_s = token.split('=', 1)
                try:
                    addr = int(addr_s, 16)
                    val = int(val_s, 16)
                except ValueError:
                    continue
                data[addr] = val
    return data


def load_group(folder: str) -> List[Dict[int, int]]:
    """Load and parse all ``.rw`` files within a folder as one group.

    Returns a list of register->value maps, one per dump file in the folder.
    Files are processed in sorted order for reproducibility.
    """
    path = os.path.join(ROOT, folder)
    files = [os.path.join(path, f) for f in sorted(os.listdir(path)) if f.endswith('.rw')]
    return [parse_rw(p) for p in files]

def summarize_value(values: List[int]) -> Tuple[int, bool]:
    """Return (majority_value, all_equal) for a list of byte values."""
    if not values:
        return (None, True)  # type: ignore
    counts = defaultdict(int)
    for v in values:
        counts[v] += 1
    maj = max(counts.items(), key=lambda kv: kv[1])[0]
    return maj, len(counts) == 1

def build_signature(groups: List[str]) -> Dict[int, Dict[str, int]]:
    """Build a representative value per register for each group.

    For each register, the majority value across all files in a group is used
    as that group's representative for the register. Missing registers are
    left absent from the signature.
    """
    groups_data: Dict[str, List[Dict[int, int]]] = {g: load_group(g) for g in groups}
    sig: Dict[int, Dict[str, int]] = {i: {} for i in range(256)}
    for reg in range(256):
        for g in groups:
            vals = [d.get(reg) for d in groups_data[g] if reg in d]
            if not vals:
                continue
            val, _ = summarize_value(vals)
            sig[reg][g] = val
    return sig


def fmt_vec(sig: Dict[int, Dict[str, int]], groups: List[str], reg: int) -> str:
    """Format a register's signature vector across groups for display."""
    v = sig[reg]
    return ' '.join(
        f"{g}:{v.get(g, None):02X}" if v.get(g) is not None else f"{g}:--" for g in groups
    )


def print_diff_between(sig: Dict[int, Dict[str, int]], groups: List[str], a: str, b: str) -> None:
    """Print registers whose representative values differ between two groups."""
    if a not in groups or b not in groups:
        return
    print(f"== Registers differing between '{a}' and '{b}' ==")
    for reg in range(256):
        va = sig[reg].get(a)
        vb = sig[reg].get(b)
        if va is None or vb is None:
            continue
        if va != vb:
            print(f"0x{reg:02X}: {a}={va:02X} {b}={vb:02X} | {fmt_vec(sig, groups, reg)}")
    print()


def print_spikes(sig: Dict[int, Dict[str, int]], groups: List[str], base: str, target: str,
                 min_target: int = 0x30, min_delta: int = 0x0A) -> None:
    """Print registers with notable increase at target vs base.

    A register is reported if both groups are present, values differ, the
    target value is at least ``min_target``, and the difference is at least
    ``min_delta``.
    """
    if base not in groups or target not in groups:
        return
    print(f"== Registers with notable increase at '{target}' vs '{base}' ==")
    for reg in range(256):
        vb = sig[reg].get(base)
        vt = sig[reg].get(target)
        if vb is None or vt is None:
            continue
        if vt != vb and vt >= min_target and (vt - vb) >= min_delta:
            print(f"0x{reg:02X}: {base}={vb:02X} {target}={vt:02X} | {fmt_vec(sig, groups, reg)}")
    print()


def print_stable_bit_flips(sig: Dict[int, Dict[str, int]], groups: List[str], base: str,
                           others: List[str], allowed_masks: Tuple[int, ...]) -> None:
    """Print registers with a consistent XOR mask relative to ``base`` across ``others``.

    Only masks in ``allowed_masks`` are reported to highlight small/single-bit flips.
    """
    if base not in groups:
        return
    for g in others:
        if g not in groups:
            return
    print(f"== Registers with stable bit flips relative to '{base}' across {others} ==")
    for reg in range(256):
        b = sig[reg].get(base)
        if b is None:
            continue
        masks = []
        ok = True
        for g in others:
            v = sig[reg].get(g)
            if v is None:
                ok = False
                break
            masks.append(b ^ v)
        if not ok or not masks:
            continue
        if all(m == masks[0] and m in allowed_masks and m != 0 for m in masks):
            xor_mask = masks[0]
            values = ' '.join(f"{g}={sig[reg][g]:02X}" for g in [base] + others)
            print(f"0x{reg:02X}: {values} xor=0x{xor_mask:02X}")
    print()


def print_near_stable_then_jump(sig: Dict[int, Dict[str, int]], groups: List[str],
                                stable_groups: List[str], base: str, target: str,
                                max_stable_diff: int = 2, min_target: int = 0x20,
                                min_delta: int = 0x08) -> None:
    """Print registers nearly stable across ``stable_groups`` but increased at ``target`` vs ``base``."""
    for g in stable_groups + [base, target]:
        if g not in groups:
            return
    print(f"== Near-stable in {stable_groups}, higher at '{target}' vs '{base}' ==")
    for reg in range(256):
        st_vals = [sig[reg].get(g) for g in stable_groups]
        if any(v is None for v in st_vals):
            continue
        if max(st_vals) - min(st_vals) > max_stable_diff:
            continue
        vb = sig[reg].get(base)
        vt = sig[reg].get(target)
        if vb is None or vt is None or vt == vb:
            continue
        if vt >= min_target and (vt - vb) >= min_delta:
            sg = '/'.join(f"{g}={sig[reg][g]:02X}" for g in stable_groups)
            print(f"0x{reg:02X}: stable[{sg}] {base}={vb:02X} {target}={vt:02X} | {fmt_vec(sig, groups, reg)}")
    print()


def print_matches_reference(sig: Dict[int, Dict[str, int]], groups: List[str],
                            ref_reg: int, min_matches: int = 3,
                            exclude: Tuple[int, ...] = ()) -> None:
    """Print registers whose values match a reference register across groups.

    A register is reported if its values equal the reference's values in at
    least ``min_matches`` groups. Registers in ``exclude`` are skipped.
    """
    if ref_reg not in range(256):
        return
    print(f"== Registers matching reference 0x{ref_reg:02X} (>= {min_matches} groups) ==")
    ref_vec = [sig[ref_reg].get(g) for g in groups]
    for reg in range(256):
        if reg == ref_reg or reg in exclude:
            continue
        vec = [sig[reg].get(g) for g in groups]
        matches = sum(1 for a, b in zip(vec, ref_vec) if a is not None and b is not None and a == b)
        if matches >= min_matches:
            print(f"0x{reg:02X}: {fmt_vec(sig, groups, reg)} matches={matches}")
    print()


def parse_int(s: str) -> int:
    """Parse an integer from decimal or hex string (e.g., '42' or '0x2A')."""
    s = s.strip().lower()
    if s.startswith('0x'):
        return int(s, 16)
    return int(s, 10)


def main() -> None:
    """Entry point for CLI argument parsing and report execution."""
    default_groups = ['beforeomen', 'omenauto', 'lowestmanual', 'rampedupmanual', 'max']

    ap = argparse.ArgumentParser(description='Analyze EC (.rw) dumps across groups.')
    ap.add_argument('--groups', nargs='+', default=default_groups,
                    help='List of folders (relative to script) containing .rw files for each group.')
    ap.add_argument('--match-ref', type=parse_int, default=None,
                    help='Reference register to match across groups (e.g., 0x11).')
    ap.add_argument('--min-matches', type=int, default=3,
                    help='Minimum groups that must match the reference pattern.')
    ap.add_argument('--diff', nargs=2, metavar=('A', 'B'), default=None,
                    help='Report registers differing between groups A and B.')
    ap.add_argument('--spike', nargs=2, metavar=('BASE', 'TARGET'), default=None,
                    help='Report registers with notable increase at TARGET vs BASE.')
    ap.add_argument('--min-target', type=parse_int, default=0x30,
                    help='Minimum absolute value at TARGET to report a spike.')
    ap.add_argument('--min-delta', type=parse_int, default=0x0A,
                    help='Minimum difference TARGET-BASE to report a spike.')
    ap.add_argument('--stable-flips', nargs='+', metavar=('BASE', 'OTHERS'), default=None,
                    help='Report registers with a consistent XOR mask relative to BASE across OTHERS.')
    ap.add_argument('--masks', nargs='*', type=parse_int, default=[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80],
                    help='Allowed XOR masks to consider for stable bit flips.')
    ap.add_argument('--near-stable', nargs='+', metavar='STABLE_GROUP', default=None,
                    help='Groups considered stable among themselves for the near-stable-then-jump report.')
    ap.add_argument('--base', default='omenauto', help='Base group for spike and near-stable reports.')
    ap.add_argument('--target', default='max', help='Target group for spike and near-stable reports.')
    ap.add_argument('--max-stable-diff', type=int, default=2,
                    help='Maximum span among stable groups to be considered nearly stable.')

    args = ap.parse_args()

    groups = [g for g in args.groups if os.path.isdir(os.path.join(ROOT, g))]
    if not groups:
        raise SystemExit('No valid groups found. Ensure folders exist or pass --groups.')

    sig = build_signature(groups)

    if args.match_ref is not None:
        print_matches_reference(sig, groups, args.match_ref, args.min_matches)

    if args.diff is not None:
        a, b = args.diff
        print_diff_between(sig, groups, a, b)

    if args.spike is not None:
        base, target = args.spike
        print_spikes(sig, groups, base, target, args.min_target, args.min_delta)

    if args.stable_flips is not None and len(args.stable_flips) >= 2:
        base, *others = args.stable_flips
        print_stable_bit_flips(sig, groups, base, others, tuple(args.masks))

    if args.near_stable is not None and len(args.near_stable) >= 2:
        print_near_stable_then_jump(
            sig, groups,
            stable_groups=args.near_stable,
            base=args.base,
            target=args.target,
            max_stable_diff=args.max_stable_diff,
            min_target=args.min_target,
            min_delta=args.min_delta,
        )

    if all(opt is None for opt in [args.match_ref, args.diff, args.spike, args.stable_flips, args.near_stable]):
        if 'lowestmanual' in groups and 'rampedupmanual' in groups:
            print_diff_between(sig, groups, 'lowestmanual', 'rampedupmanual')
        if 'omenauto' in groups and 'max' in groups:
            print_spikes(sig, groups, 'omenauto', 'max', args.min_target, args.min_delta)
        if all(g in groups for g in ['beforeomen', 'lowestmanual', 'rampedupmanual']):
            print_stable_bit_flips(sig, groups, 'beforeomen', ['lowestmanual', 'rampedupmanual'], tuple(args.masks))
        if all(g in groups for g in ['lowestmanual', 'rampedupmanual', 'omenauto', 'max']):
            print_near_stable_then_jump(
                sig, groups,
                stable_groups=['lowestmanual', 'rampedupmanual'],
                base='omenauto',
                target='max',
                max_stable_diff=args.max_stable_diff,
                min_target=args.min_target,
                min_delta=args.min_delta,
            )


if __name__ == '__main__':
    main()

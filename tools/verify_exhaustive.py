"""Cross-check the prefix-trie DP against brute-force enumeration.

Runs on deliberately tiny universes (B-bit address spaces). No production
address space is ever enumerated: B bits is a testing trick only.
"""

import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netaddr.ip.summarization import (
    _build_trie,
    _intervals_to_cidrs,
    _merge_intervals,
    _TrieSolver,
)
from tools._reference import reference_solve, random_problem


def mask_to_intervals(mask, bits):
    intervals = []
    start = None
    for i in range(1 << bits):
        if (mask >> i) & 1:
            if start is None:
                start = i
        else:
            if start is not None:
                intervals.append((start, i - 1))
                start = None
    if start is not None:
        intervals.append((start, (1 << bits) - 1))
    return intervals


def trie_solve(target_mask, forbidden_mask, bits, max_rules):
    ti = _merge_intervals(mask_to_intervals(target_mask, bits))
    fi = _merge_intervals(mask_to_intervals(forbidden_mask, bits))
    tp = _intervals_to_cidrs(ti, bits)
    fp = _intervals_to_cidrs(fi, bits)
    target_size = sum(hi - lo + 1 for lo, hi in ti)

    root = _build_trie(tp, fp, bits)
    solver = _TrieSolver(root, bits, max_rules)
    dp = solver.cost_dp(root)
    counts = [r for r in dp if r <= max_rules]
    if not counts:
        return False, None, None, None, root.min_rules
    best = min(counts, key=lambda r: (dp[r][0], r))
    chosen = solver.rules_for(root, best)
    covered = sum(1 << (bits - pref) for _, pref in chosen)
    extra = covered - target_size
    return True, extra, best, list(chosen), root.min_rules


def run():
    rng = random.Random(20261005)
    total = 0
    infeasible_seen = 0
    t0 = time.perf_counter()

    plan = [(4, 4, 300), (5, 3, 500), (6, 3, 500), (7, 3, 400), (8, 2, 120)]

    def check(bits, max_rules, tm, fm, tag):
        nonlocal total, infeasible_seen
        ref = reference_solve(tm, fm, bits, max_rules)
        got = trie_solve(tm, fm, bits, max_rules)
        total += 1
        if not ref[0]:
            infeasible_seen += 1
        assert_equivalent(bits, tm, fm, ref, got, tag, max_rules)

    def assert_equivalent(bits, tm, fm, ref, got, tag, max_rules):
        if ref[0] != got[0]:
            raise AssertionError(
                'feasibility mismatch (%s) B=%d tm=%s fm=%s ref=%s got=%s'
                % (tag, bits, bin(tm), bin(fm), ref[:3], got[:3])
            )
        if ref[0]:
            if (ref[1], ref[2]) != (got[1], got[2]):
                raise AssertionError(
                    'optimum mismatch (%s) B=%d tm=%s fm=%s ref=%s got=%s'
                    % (tag, bits, bin(tm), bin(fm), ref[:3], got[:3])
                )
            if sorted(ref[3]) != sorted(got[3]):
                raise AssertionError(
                    'tie-break mismatch (%s) B=%d tm=%s fm=%s %s vs %s'
                    % (tag, bits, bin(tm), bin(fm),
                       sorted(ref[3]), sorted(got[3]))
                )
        ref2 = reference_solve(tm, fm, bits, 1 << 10)
        got2 = trie_solve(tm, fm, bits, 1 << 10)
        if ref2[0] != got2[0] or (ref2[1], ref2[2]) != (got2[1], got2[2]):
            raise AssertionError(
                'unlimited mismatch (%s) B=%d tm=%s fm=%s'
                % (tag, bits, bin(tm), bin(fm))
            )
        if got[4] != ref2[2]:
            raise AssertionError(
                'minimum_rules mismatch (%s) B=%d %s vs %s'
                % (tag, bits, got[4], ref2[2])
            )

    #   Targeted infeasibility: sparse singleton targets, K below count.
    for bits in (4, 5, 6):
        for _ in range(200):
            n_positions = rng.randint(2, min(4, (1 << bits) - 2))
            positions = rng.sample(range(1 << bits), n_positions)
            tm = 0
            for pos in positions:
                tm |= 1 << pos
            #   Occupy gap addresses as forbidden to block coarse CIDRs.
            fm = 0
            for pos in range(1 << bits):
                if not ((tm >> pos) & 1) and rng.random() < 0.6:
                    fm |= 1 << pos
            check(bits, 1, tm, fm, 'forced-1')
            if tm.bit_count() >= 3:
                check(bits, 2, tm, fm, 'forced-2')

    for bits, max_rules, cases in plan:
        for _ in range(cases):
            tm, fm = random_problem(rng, bits)
            ref = reference_solve(tm, fm, bits, max_rules)
            got = trie_solve(tm, fm, bits, max_rules)
            total += 1
            if not ref[0]:
                infeasible_seen += 1

            if ref[0] != got[0]:
                raise AssertionError(
                    'feasibility mismatch B=%d tm=%s fm=%s ref=%s got=%s'
                    % (bits, bin(tm), bin(fm), ref[:3], got[:3])
                )
            if ref[0]:
                if (ref[1], ref[2]) != (got[1], got[2]):
                    raise AssertionError(
                        'optimum mismatch B=%d tm=%s fm=%s ref=%s got=%s'
                        % (bits, bin(tm), bin(fm), ref[:3], got[:3])
                    )
                ref_tuples = sorted(ref[3])
                got_tuples = sorted(got[3])
                if ref_tuples != got_tuples:
                    raise AssertionError(
                        'tie-break mismatch B=%d tm=%s fm=%s ref=%s got=%s'
                        % (bits, bin(tm), bin(fm), ref_tuples, got_tuples)
                    )

            #   Also verify with generous limits: optimum must stay exact.
            ref2 = reference_solve(tm, fm, bits, 1 << 10)
            got2 = trie_solve(tm, fm, bits, 1 << 10)
            if ref2[0] != got2[0] or (ref2[1], ref2[2]) != (
                got2[1],
                got2[2],
            ):
                raise AssertionError(
                    'unlimited-limit mismatch B=%d tm=%s fm=%s'
                    % (bits, bin(tm), bin(fm))
                )
            if got[4] != ref2[2]:
                raise AssertionError(
                    'minimum_rules mismatch B=%d tm=%s fm=%s %s vs %s'
                    % (bits, bin(tm), bin(fm), got.min_rules, ref2[2])
                )

    dt = time.perf_counter() - t0
    print(
        'exhaustive cross-check: %d cases OK (%d infeasible), %.2fs'
        % (total, infeasible_seen, dt)
    )


if __name__ == '__main__':
    run()

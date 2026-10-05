"""Independent reference solver for tiny address spaces (verification only).

Enumerates combinations of all valid CIDRs of a B-bit universe using
branch-and-bound over at most K rules. It deliberately mirrors the address
*mask* view rather than the trie DP, so agreement is a meaningful check.
"""

import random


def all_cidrs(bits):
    for prefix_len in range(bits + 1):
        host_bits = bits - prefix_len
        size = 1 << host_bits
        for start in range(0, 1 << bits, size):
            yield (start, prefix_len)


def cidr_mask(cidr, bits):
    start, prefix_len = cidr
    host_bits = bits - prefix_len
    return (((1 << (1 << host_bits)) - 1) << start) & (
        (1 << (1 << bits)) - 1
    )


def reference_solve(target_mask, forbidden_mask, bits, max_rules):
    """Return (feasible, extra, n_rules, sorted_tuple)."""
    universe_size = 1 << bits
    full_mask = (1 << universe_size) - 1

    candidates = []
    for cidr in all_cidrs(bits):
        mask = cidr_mask(cidr, bits)
        if mask & forbidden_mask:
            continue
        if not (mask & target_mask):
            continue
        candidates.append((cidr, mask))

    #   Candidates containing a target always have extra >= 0; singleton
    #   target blocks guarantee feasibility at n_targets rules.
    best = None  # (extra, n_rules, tuple sorted by (start, prefix))

    def record(extra, selected):
        nonlocal best
        ordered = tuple(sorted(selected))
        key = (extra, len(ordered), ordered)
        if best is None or key < best:
            best = key

    def dfs(i, covered, selected):
        nonlocal best
        rules = len(selected)
        if (covered & target_mask) == target_mask:
            extra = (covered & ~target_mask & full_mask).bit_count()
            record(extra, selected)
            return
        if rules >= max_rules:
            return
        if i == len(candidates):
            return

        #   Feasibility pruning: remaining candidates must jointly be able
        #   to cover every still-uncovered target bit.
        remaining_union = 0
        for j in range(i, len(candidates)):
            remaining_union |= candidates[j][1]
        uncovered_targets = target_mask & ~covered & full_mask
        if uncovered_targets & ~remaining_union:
            return

        cidr, mask = candidates[i]

        #   Skip this candidate (only when later candidates can still cover
        #   the uncovered targets; descendants appear later in the order).
        later_union = 0
        for j in range(i + 1, len(candidates)):
            later_union |= candidates[j][1]
        if not (uncovered_targets & ~later_union):
            dfs(i + 1, covered, selected)

        if not (mask & covered):
            dfs(i + 1, covered | mask, selected + [cidr])

    candidates.sort(key=lambda cm: cm[0])
    dfs(0, 0, [])

    if best is None:
        return False, None, None, None
    extra, n_rules, selected = best
    return True, extra, n_rules, list(selected)


def random_problem(rng, bits):
    n_targets = rng.randint(1, min(5, (1 << bits) - 2))
    n_forbidden = rng.randint(0, 4)

    def random_mask():
        kind = rng.random()
        if kind < 0.5:
            host_bits = rng.randint(0, min(2, bits - 1))
            size = 1 << host_bits
            start = rng.randrange(0, bits - size + 1)
            start -= start % size
            return ((1 << size) - 1) << start
        bit = rng.randrange(bits)
        return 1 << bit

    target_mask = 0
    while target_mask.bit_count() < 1 or target_mask.bit_count() > max(
        6, (1 << bits) - 3
    ):
        target_mask = 0
        for _ in range(n_targets):
            target_mask |= random_mask()

    forbidden_mask = 0
    for _ in range(n_forbidden):
        m = random_mask()
        if m & target_mask:
            continue
        forbidden_mask |= m

    return target_mask, forbidden_mask

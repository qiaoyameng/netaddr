import itertools
import random

import pytest

from netaddr import IPNetwork, IPSet
from netaddr.ip.summarization import (
    AggregationResult,
    ExtraRange,
    summarize_ipset,
    summarize_ipsets,
    _build_trie,
    _intervals_to_cidrs,
    _merge_intervals,
    _TrieSolver,
)


def test_exact_merge_single_rule():
    result = summarize_ipset(
        IPSet(['10.0.0.0/25', '10.0.0.128/25']), max_rules=1
    )
    assert result.feasible
    assert result.rules == [IPNetwork('10.0.0.0/24')]
    assert result.extra_addresses == 0
    assert result.extra_ranges == []
    assert result.covered_addresses == 256
    assert result.target_addresses == 256
    assert result.minimum_rules == 1


def test_extra_coverage_with_forbidden_guard():
    #   .0 and .2 must be covered; .3 is forbidden so /30 cannot be used.
    result = summarize_ipset(
        IPSet(['10.0.0.0/32', '10.0.0.2/32']),
        IPSet(['10.0.0.3/32']),
        max_rules=2,
    )
    assert result.feasible
    assert result.rules == [
        IPNetwork('10.0.0.0/32'),
        IPNetwork('10.0.0.2/32'),
    ]
    assert result.extra_addresses == 0
    assert result.minimum_rules == 2


def test_coarse_rule_preferred_under_rule_limit_without_forbidden():
    result = summarize_ipset(
        IPSet(['10.0.0.1/32', '10.0.0.2/32']), max_rules=1
    )
    assert result.feasible
    assert result.rules == [IPNetwork('10.0.0.0/30')]
    assert result.extra_addresses == 2
    sizes = [(str(x.cidr), x.size, str(x.rule)) for x in result.extra_ranges]
    assert sizes == [
        ('10.0.0.0/32', 1, '10.0.0.0/30'),
        ('10.0.0.3/32', 1, '10.0.0.0/30'),
    ]
    assert sum(x.size for x in result.extra_ranges) == result.extra_addresses


def test_infeasible_reports_minimum_rules():
    result = summarize_ipset(
        IPSet(['10.0.0.1/32', '10.0.0.2/32']),
        IPSet(['10.0.0.3/32']),
        max_rules=1,
    )
    assert not result.feasible
    assert result.rules == []
    assert result.minimum_rules == 2
    assert result.extra_addresses is None
    assert result.extra_ranges is None


def test_rule_limit_never_exceeded_when_coarse_cheaper_in_rules():
    #   Two /24s with a forbidden net between them: one rule impossible;
    #   the answer must still not exceed max_rules.
    result = summarize_ipset(
        IPSet(['10.0.0.0/24', '10.0.2.0/24']),
        IPSet(['10.0.1.0/24']),
        max_rules=1,
    )
    assert not result.feasible
    assert result.minimum_rules == 2

    result = summarize_ipset(
        IPSet(['10.0.0.0/24', '10.0.2.0/24']),
        IPSet(['10.0.1.0/24']),
        max_rules=2,
    )
    assert result.feasible
    assert len(result.rules) == 2
    assert result.extra_addresses == 0


def test_extra_preferred_over_more_rules_when_both_feasible():
    #   With K=2 and no forbidden, exact cover needs 2 rules (extra 0);
    #   K=1 must take the coarse CIDR even though it adds addresses.
    result = summarize_ipset(
        IPSet(['10.0.0.1/32', '10.0.0.2/32']), max_rules=2
    )
    assert result.rules == [
        IPNetwork('10.0.0.1/32'),
        IPNetwork('10.0.0.2/32'),
    ]
    assert result.extra_addresses == 0
    assert len(result.rules) == 2


def test_forbidden_set_never_intersects_rules():
    target = IPSet(['198.51.100.0/30', '198.51.100.8/30'])
    forbidden = IPSet(['198.51.100.4/30', '198.51.100.12/30'])
    result = summarize_ipset(target, forbidden, max_rules=4)
    assert result.feasible
    rule_set = IPSet(result.rules)
    assert rule_set.isdisjoint(forbidden)
    assert target.issubset(rule_set)
    assert len(result.rules) <= 4


def test_ipv6_exact_big_integer():
    result = summarize_ipset(
        IPSet(['2001:db8::1', '2001:db8:0:ffff::1']), max_rules=1
    )
    assert result.feasible
    assert result.rules == [IPNetwork('2001:db8::/48')]
    assert result.extra_addresses == 2 ** 80 - 2
    assert isinstance(result.extra_addresses, int)
    assert sum(x.size for x in result.extra_ranges) == 2 ** 80 - 2


def test_ipv6_prefix_depth_not_address_count():
    #   Same trie shape at different widths: cardinality 2**56 larger but
    #   identical feasibility and rule structure.
    for width in (120, 64):
        block = 1 << (128 - width)
        base = IPNetwork('2001:db8::/128').first
        t1 = IPNetwork((base, width), version=6)
        t2 = IPNetwork((base + 2 * block, width), version=6)
        forbidden = IPNetwork((base + block, width), version=6)
        tight = summarize_ipset(IPSet([t1, t2]), IPSet([forbidden]), 1)
        exact = summarize_ipset(IPSet([t1, t2]), IPSet([forbidden]), 2)
        assert not tight.feasible
        assert tight.minimum_rules == 2
        assert exact.extra_addresses == 0
        assert len(exact.rules) == 2


def test_summarize_ipsets_splits_families():
    results = summarize_ipsets(
        IPSet(['192.0.2.0/31', '2001:db8::1', '2001:db8::2']),
        IPSet(['2001:db8::3']),
        max_rules=2,
    )
    assert set(results) == {4, 6}
    assert results[4].rules == [IPNetwork('192.0.2.0/31')]
    assert results[6].version == 6
    assert results[6].extra_addresses == 0
    assert [str(c) for c in results[6].rules] == [
        '2001:db8::1/128',
        '2001:db8::2/128',
    ]


def test_summarize_ipsets_omits_empty_family():
    results = summarize_ipsets(IPSet(['192.0.2.0/30']))
    assert set(results) == {4}


def test_overlapping_target_and_forbidden_raises():
    with pytest.raises(ValueError, match='disjoint'):
        summarize_ipset(
            IPSet(['10.0.0.0/24']), IPSet(['10.0.0.5/32']), max_rules=4
        )


def test_mixed_versions_single_call_raises():
    with pytest.raises(ValueError, match='one IP version at a time'):
        summarize_ipset(IPSet(['10.0.0.0/32', '2001:db8::1']))


def test_invalid_max_rules():
    with pytest.raises(ValueError):
        summarize_ipset(IPSet(['10.0.0.0/32']), max_rules=0)
    with pytest.raises(TypeError):
        summarize_ipset(IPSet(['10.0.0.0/32']), max_rules=1.5)


def test_empty_inputs():
    result = summarize_ipset(IPSet(), IPSet(['10.0.0.0/24']), max_rules=4)
    assert result.feasible
    assert result.rules == []
    assert result.extra_addresses == 0
    assert summarize_ipsets(IPSet()) == {}


def test_iterable_inputs_accepted():
    result = summarize_ipset(
        ['10.0.0.1/32', '10.0.0.2/32'], ['10.0.0.3/32'], max_rules=2
    )
    assert result.feasible
    assert result.extra_addresses == 0


def test_surrounded_target_uses_exact_host_route():
    target = IPSet(['192.0.2.1/32'])
    forbidden = IPSet(['0.0.0.0/0']).difference(target)
    result = summarize_ipset(target, forbidden, max_rules=5)
    assert result.feasible
    assert result.rules == [IPNetwork('192.0.2.1/32')]
    assert result.extra_addresses == 0


def test_whole_address_family_target():
    result = summarize_ipset(IPSet(['0.0.0.0/0']), max_rules=1)
    assert result.rules == [IPNetwork('0.0.0.0/0')]
    assert result.extra_addresses == 0
    assert result.covered_addresses == 2 ** 32


def test_coarse_block_with_adjacent_forbidden_unaffected():
    result = summarize_ipset(
        IPSet(['10.0.0.0/30']), IPSet(['10.0.0.4/30']), max_rules=1
    )
    assert result.feasible
    assert result.rules == [IPNetwork('10.0.0.0/30')]
    assert result.extra_addresses == 0


def test_zero_extra_preferred_when_limit_is_generous():
    result = summarize_ipset(
        IPSet(['10.0.0.0/24', '10.0.1.0/24']), max_rules=100
    )
    assert result.rules == [IPNetwork('10.0.0.0/23')]
    assert result.extra_addresses == 0
    assert len(result.rules) == 1


def test_bool_max_rules_rejected():
    with pytest.raises(TypeError):
        summarize_ipset(IPSet(['10.0.0.1/32']), max_rules=True)


def test_summarize_ipsets_overlap_still_raises():
    with pytest.raises(ValueError, match='disjoint'):
        summarize_ipsets(
            IPSet(['2001:db8::1']), IPSet(['2001:db8::/32'])
        )


def test_deterministic_tie_break():
    target = IPSet(['10.0.0.1/32', '10.0.0.2/32'])
    first = summarize_ipset(target, max_rules=1)
    second = summarize_ipset(target, max_rules=1)
    assert [str(c) for c in first.rules] == [str(c) for c in second.rules]


def test_to_dict_preserves_exact_ints():
    result = summarize_ipset(
        IPSet(['2001:db8::1', '2001:db8:0:ffff::1']), max_rules=1
    )
    data = result.to_dict()
    assert data['feasible'] is True
    assert data['version'] == 6
    assert data['rules'] == ['2001:db8::/48']
    assert data['extra_addresses'] == 2 ** 80 - 2
    assert data['extra_ranges'][0]['rule'] == '2001:db8::/48'


# -----------------------------------------------------------------------------
#   Independent brute-force cross-check on a small B-bit universe.
# -----------------------------------------------------------------------------


def _mask_to_intervals(mask, bits):
    intervals = []
    start = None
    for i in range(1 << bits):
        if (mask >> i) & 1:
            if start is None:
                start = i
        elif start is not None:
            intervals.append((start, i - 1))
            start = None
    if start is not None:
        intervals.append((start, (1 << bits) - 1))
    return intervals


def _trie_solve(target_mask, forbidden_mask, bits, max_rules):
    ti = _merge_intervals(_mask_to_intervals(target_mask, bits))
    fi = _merge_intervals(_mask_to_intervals(forbidden_mask, bits))
    target_size = sum(hi - lo + 1 for lo, hi in ti)
    root = _build_trie(
        _intervals_to_cidrs(ti, bits), _intervals_to_cidrs(fi, bits), bits
    )
    solver = _TrieSolver(root, bits, max_rules)
    dp = solver.cost_dp(root)
    counts = [r for r in dp if r <= max_rules]
    if not counts:
        return None
    best = min(counts, key=lambda r: (dp[r][0], r))
    chosen = solver.rules_for(root, best)
    covered = sum(1 << (bits - pref) for _, pref in chosen)
    return covered - target_size, best, sorted(chosen)


def _brute_force(target_mask, forbidden_mask, bits, max_rules):
    universe = (1 << (1 << bits)) - 1
    candidates = []
    for prefix_len in range(bits + 1):
        size = 1 << (bits - prefix_len)
        block_bits = (1 << size) - 1
        for start in range(0, 1 << bits, size):
            mask = (block_bits << start) & universe
            if mask & forbidden_mask or not (mask & target_mask):
                continue
            candidates.append(((start, prefix_len), mask))

    best = None
    for count in range(1, max_rules + 1):
        for combo in itertools.combinations(candidates, count):
            covered = 0
            for _, mask in combo:
                if mask & covered:
                    break
                covered |= mask
            else:
                if (covered & target_mask) != target_mask:
                    continue
                extra = (covered & ~target_mask & universe).bit_count()
                key = (extra, count, tuple(sorted(c[0] for c in combo)))
                if best is None or key < best:
                    best = key
    return None if best is None else (best[0], best[1], list(best[2]))


def test_matches_brute_force_on_small_universes():
    rng = random.Random(90210)
    checked = 0
    for bits, max_rules, cases in ((4, 4, 120), (5, 3, 60)):
        for _ in range(cases):
            n_targets = rng.randint(1, min(4, (1 << bits) - 2))
            positions = rng.sample(range(1 << bits), n_targets)
            target_mask = sum(1 << pos for pos in positions)
            forbidden_mask = 0
            for pos in range(1 << bits):
                if not ((target_mask >> pos) & 1) and rng.random() < 0.4:
                    forbidden_mask |= 1 << pos

            for limit in (max_rules, 1 << 8):
                expected = _brute_force(
                    target_mask, forbidden_mask, bits, limit
                )
                actual = _trie_solve(
                    target_mask, forbidden_mask, bits, limit
                )
                assert (expected is None) == (actual is None), (
                    bits,
                    bin(target_mask),
                    bin(forbidden_mask),
                    limit,
                )
                if expected is not None:
                    assert expected[:2] == actual[:2]
                    assert expected[2] == actual[2]
                checked += 1
    assert checked > 0

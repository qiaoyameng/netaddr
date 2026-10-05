import itertools
import random
import time

import pytest

from netaddr import CIDRSummary, IPRange, IPNetwork, IPSet, cidr_exclude, cidr_summarize


def _brute_force_summary(base, target_values, forbidden_values, max_rules):
    candidates = []
    for prefixlen in range(base.prefixlen, 33):
        size = 1 << (32 - prefixlen)
        for first in range(base.first, base.last + 1, size):
            network = IPNetwork((first, prefixlen))
            values = range(first - base.first, first - base.first + size)
            candidates.append((network, frozenset(values)))

    target_mask = frozenset(target_values)
    forbidden_mask = frozenset(forbidden_values)
    best = None

    for rule_count in range(1, max_rules + 1):
        for selection in itertools.combinations(candidates, rule_count):
            covered = frozenset().union(*(mask for _, mask in selection))
            if target_mask - covered or forbidden_mask & covered:
                continue
            cidrs = tuple(sorted(network for network, _ in selection))
            score = (len(covered - target_mask), rule_count, cidrs)
            if best is None or score < best[0]:
                best = (score, cidrs)

    if best is None:
        return None
    return best[1]


def test_cidr_summary_matches_brute_force_in_small_space():
    base = IPNetwork('192.0.2.0/28')
    outside_base = IPSet(cidr_exclude(IPNetwork('0.0.0.0/0'), base))
    rng = random.Random(20261005)

    for _ in range(40):
        target_values = frozenset(rng.sample(range(16), rng.randint(1, 5)))
        forbidden_values = frozenset(rng.sample(sorted(frozenset(range(16)) - target_values), 3))
        target = IPSet(
            IPNetwork((base.first + value, 32)) for value in target_values
        )
        forbidden = outside_base.union(
            IPSet(IPNetwork((base.first + value, 32)) for value in forbidden_values)
        )

        for max_rules in range(1, 5):
            summary = cidr_summarize(target, forbidden, max_rules)
            expected = _brute_force_summary(
                base, target_values, forbidden_values, max_rules
            )
            if expected is None:
                assert not summary.feasible
                assert summary.reason == 'rule limit is too small'
                assert summary.cidrs == []
            else:
                assert summary.feasible
                assert summary.cidrs == list(expected)
                assert summary.rules_used <= max_rules
                assert target.issubset(IPSet(summary.cidrs))
                assert IPSet(summary.cidrs).intersection(forbidden) == IPSet()
                covered_values = set()
                for cidr in summary.cidrs:
                    covered_values.update(range(cidr.first, cidr.last + 1))
                assert summary.extra_addresses == len(
                    covered_values - set(base.first + value for value in target_values)
                )


def test_cidr_summary_reports_exact_extra_ranges():
    summary = cidr_summarize(
        IPSet(['192.0.2.0/32', '192.0.2.3/32']),
        IPSet(['192.0.2.4/32']),
        1,
    )

    assert summary.feasible
    assert summary.cidrs == [IPNetwork('192.0.2.0/30')]
    assert summary.rules_used == 1
    assert summary.target_addresses == 2
    assert summary.extra_addresses == 2
    assert summary.extra_ranges == [IPRange('192.0.2.1', '192.0.2.2')]


def test_cidr_summary_uses_deterministic_tie_break():
    summary = cidr_summarize(
        IPSet(
            [
                '192.0.2.0/32',
                '192.0.2.3/32',
                '192.0.2.4/32',
                '192.0.2.7/32',
            ]
        ),
        IPSet(),
        3,
    )

    assert summary.feasible
    assert summary.extra_addresses == 2
    assert summary.cidrs == [
        IPNetwork('192.0.2.0/30'),
        IPNetwork('192.0.2.4/32'),
        IPNetwork('192.0.2.7/32'),
    ]


def test_cidr_summary_reports_overlap_as_infeasible():
    summary = cidr_summarize(
        IPSet(['192.0.2.0/31']), IPSet(['192.0.2.1/32']), 4
    )

    assert isinstance(summary, CIDRSummary)
    assert not summary.feasible
    assert summary.reason == 'target and forbidden sets overlap'
    assert summary.cidrs == []
    assert summary.rules_used == 0
    assert summary.minimum_rules == (None, 0)


def test_cidr_summary_does_not_exceed_shared_rule_limit():
    summary = cidr_summarize(
        IPSet(['192.0.2.0/32', '2001:db8::/128', '2001:db8::2/128']),
        IPSet(),
        1,
    )

    assert not summary.feasible
    assert summary.reason == 'rule limit is too small'
    assert summary.cidrs == []
    assert summary.ipv4.feasible
    assert summary.ipv6.feasible
    assert summary.ipv6.minimum_rules == 1


def test_cidr_summary_ipv6_large_prefixes_keep_exact_integers():
    target = IPSet(['2001:db8::/64', '2001:db8:0:1::/65'])
    forbidden = IPSet(['2001:db8:0:2::/64'])

    started = time.perf_counter()
    summary = cidr_summarize(target, forbidden, 1)
    elapsed = time.perf_counter() - started

    assert summary.feasible
    assert summary.cidrs == [IPNetwork('2001:db8::/63')]
    assert summary.target_addresses == 3 * (2 ** 63)
    assert summary.extra_addresses == 2 ** 63
    assert summary.extra_ranges == [
        IPRange(
            '2001:db8:0:1:8000::',
            '2001:db8:0:1:ffff:ffff:ffff:ffff',
        )
    ]
    assert elapsed < 1.0


def test_cidr_summary_runtime_follows_prefix_structure_not_address_count():
    target = IPSet(['2001:db8:1::/97', '2001:db8:1::8000:0/97'])
    forbidden = IPSet(['2001:db8:1:0:0:1::/96'])

    started = time.perf_counter()
    summary = cidr_summarize(target, forbidden, 1)
    elapsed = time.perf_counter() - started

    assert summary.feasible
    assert summary.cidrs == [IPNetwork('2001:db8:1::/96')]
    assert summary.extra_addresses == 0
    assert elapsed < 1.0


def test_cidr_summary_accepts_iterables_and_ipset_method():
    summary = IPSet(['10.0.0.0/31']).summarize_cidrs(['10.0.0.2/32'], 1)

    assert summary.feasible
    assert summary.cidrs == [IPNetwork('10.0.0.0/31')]
    assert summary.extra_addresses == 0


def test_cidr_summary_rejects_negative_rule_limit():
    with pytest.raises(ValueError):
        cidr_summarize(IPSet(), IPSet(), -1)

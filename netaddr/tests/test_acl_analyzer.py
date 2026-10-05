import pytest

from netaddr import IPNetwork, IPSet
from netaddr.contrib.acl_analyzer import (
    Rule, analyze_rules, decision_regions, format_report,
    joint_shadow_example, verify_removals,
)


def cidrs_of(ipset):
    return set(str(c) for c in ipset.iter_cidrs())


def test_joint_shadow_by_three_rules():
    """Three rules jointly (not pairwise) cover a fourth."""
    rules, default = joint_shadow_example()
    analyses = analyze_rules(rules, default)
    target = analyses[3]

    assert target.status == 'redundant'
    assert target.safe_to_remove
    assert not target.effective
    assert cidrs_of(target.redundant) == {'10.0.0.0/8'}

    # shadowed by the union of exactly rules 0, 1 and 2
    assert [s.index for s in target.shadowers] == [0, 1, 2]
    assert all(s.same_action for s in target.shadowers)

    # no single preceding rule covers it on its own: an adjacent-pair-only
    # analysis would miss this redundancy entirely
    for s in target.shadowers:
        assert s.overlap != target.match


def test_truncation_reported_separately_from_redundancy():
    rules = [
        Rule('a', 'allow', ['10.0.0.0/24']),
        Rule('b', 'allow', ['10.0.1.0/24']),
        Rule('c', 'deny', ['10.0.0.0/23']),
    ]
    analyses = analyze_rules(rules, 'deny')
    target = analyses[2]

    assert target.status == 'overridden'
    assert not target.safe_to_remove
    assert cidrs_of(target.truncated) == {'10.0.0.0/23'}
    assert not target.redundant
    assert [s.relation for s in target.shadowers] == [
        'opposite-action', 'opposite-action']


def test_partial_shadow_splits_same_and_opposite():
    rules = [
        Rule('a', 'allow', ['10.0.0.0/25']),
        Rule('b', 'deny', ['10.0.0.128/26']),
        Rule('c', 'allow', ['10.0.0.0/24']),
    ]
    analyses = analyze_rules(rules, 'deny')
    target = analyses[2]

    assert target.status == 'partially-shadowed'
    assert not target.safe_to_remove
    assert cidrs_of(target.redundant) == {'10.0.0.0/25'}
    assert cidrs_of(target.truncated) == {'10.0.0.128/26'}
    assert cidrs_of(target.effective) == {'10.0.0.192/26'}


def test_exclusions_carve_out_match_set():
    rules = [
        Rule('dmz', 'allow', ['192.168.0.0/24'],
             excludes=['192.168.0.128/25']),
    ]
    (analysis,) = analyze_rules(rules, 'deny')
    assert cidrs_of(analysis.match) == {'192.168.0.0/25'}
    assert cidrs_of(analysis.effective) == {'192.168.0.0/25'}


def test_ipv6_regions_are_merged_cidrs_not_enumerated():
    rules = [
        Rule('v6', 'allow', ['2001:db8::/32'],
             excludes=['2001:db8:bad::/48']),
    ]
    (analysis,) = analyze_rules(rules, 'deny')
    # /32 minus a /48 must come back as a handful of merged CIDRs
    blocks = cidrs_of(analysis.match)
    assert '2001:db8:bad::/48' not in blocks
    assert len(blocks) < 32
    # sizes computed arithmetically, no address enumeration
    assert analysis.match.size == 2 ** 96 - 2 ** 80


def test_verify_removals_of_safe_rules_preserves_all_partitions():
    rules, default = joint_shadow_example()
    analyses = analyze_rules(rules, default)
    safe = [a.index for a in analyses if a.safe_to_remove]
    assert safe == [3]

    equivalent, before, after = verify_removals(rules, default, safe)
    assert equivalent
    assert before == after

    # every original effective region keeps its decision after removal
    remaining = [r for i, r in enumerate(rules) if i not in safe]
    after_regions = decision_regions(remaining, default)
    for analysis in analyses:
        if analysis.effective:
            assert analysis.effective <= after_regions[analysis.rule.action]


def test_removing_a_live_rule_is_detected():
    rules, default = joint_shadow_example()
    # rule 6 is the only decider of its IPv6 region; removing it flips
    # that region to the default action
    equivalent, before, after = verify_removals(rules, default, [6])
    assert not equivalent
    assert before['allow'] != after['allow']


def test_removing_overridden_rule_changes_nothing_but_is_not_safe():
    """Dead-by-opposite-action rules are flagged for review, not auto-safe."""
    rules = [
        Rule('a', 'allow', ['10.0.0.0/24']),
        Rule('b', 'deny', ['10.0.0.0/24']),
    ]
    analyses = analyze_rules(rules, 'deny')
    assert analyses[1].fully_shadowed
    assert not analyses[1].safe_to_remove
    # behaviourally it is still dead, and verification confirms it
    equivalent, _, _ = verify_removals(rules, 'deny', [1])
    assert equivalent


def test_decision_regions_partition_the_universe():
    rules, default = joint_shadow_example()
    regions = decision_regions(rules, default)
    total = IPSet()
    for region in regions.values():
        assert total.isdisjoint(region)
        total = total | region
    assert total == IPSet(['0.0.0.0/0', '::/0'])
    assert default in regions


def test_report_mentions_status_and_shadowers():
    rules, default = joint_shadow_example()
    report = format_report(rules, default)
    assert 'SAFE TO REMOVE' in report
    assert 'legacy-catchall' in report
    assert 'truncated (opposite-action' in report
    assert '10.0.0.0/8' in report

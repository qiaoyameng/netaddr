import json

from netaddr import IPSet

from netaddr.contrib.firewall_analyzer import main
from netaddr.contrib.firewall_analyzer import (
    ALLOW,
    DENY,
    FirewallRule,
    analyze_firewall,
    compile_firewall_policy,
    format_analysis,
    verify_safe_deletions,
)


def test_declared_region_merges_cidrs_and_applies_exclusions():
    rule = FirewallRule(
        'r1',
        DENY,
        ['10.0.0.0/24', '10.0.1.0/24'],
        excludes=['10.0.0.128/25'],
    )
    analysis = analyze_firewall([rule])

    assert analysis.rules[0].declared_cidrs == [
        '10.0.0.0/25',
        '10.0.1.0/24',
    ]
    assert analysis.rules[0].effective_cidrs == [
        '10.0.0.0/25',
        '10.0.1.0/24',
    ]


def test_same_decision_redundancy_and_opposite_truncation_are_separate():
    rules = [
        FirewallRule('same', ALLOW, ['10.0.0.0/25']),
        FirewallRule('opposite', DENY, ['10.0.0.128/25']),
        FirewallRule('target', ALLOW, ['10.0.0.0/24']),
    ]
    report = analyze_firewall(rules).rules[-1]

    assert report.status == 'fully_shadowed_mixed'
    assert report.redundant_cidrs == ['10.0.0.0/25']
    assert report.truncated_cidrs == ['10.0.0.128/25']
    assert report.redundant_rule_ids == ['same']
    assert report.truncating_rule_ids == ['opposite']
    assert report.effective_cidrs == []
    assert report.safe_to_delete is True


def test_three_preceding_ranges_jointly_shadow_fourth_rule():
    rules = [
        FirewallRule('r1', DENY, ['192.0.2.0/26']),
        FirewallRule('r2', DENY, ['192.0.2.64/26']),
        FirewallRule('r3', DENY, ['192.0.2.128/25']),
        FirewallRule('r4', DENY, ['192.0.2.0/24']),
    ]
    report = analyze_firewall(rules).rules[-1]

    assert report.fully_shadowed_individually_by == []
    assert report.partially_shadowed_by == ['r1', 'r2', 'r3']
    assert report.jointly_fully_shadowed is True
    assert report.status == 'fully_redundant'
    assert report.redundant_cidrs == ['192.0.2.0/24']
    assert report.effective_cidrs == []


def test_single_predecessor_can_fully_shadow_later_rule():
    rules = [
        FirewallRule('broad', ALLOW, ['10.0.0.0/24']),
        FirewallRule('narrow', DENY, ['10.0.0.0/25']),
    ]
    report = analyze_firewall(rules).rules[-1]

    assert report.status == 'fully_truncated'
    assert report.fully_shadowed_individually_by == ['broad']
    assert report.partially_shadowed_by == []
    assert report.truncated_cidrs == ['10.0.0.0/25']
    assert report.safe_to_delete is True


def test_partial_opposite_decision_truncation_leaves_effective_region():
    rules = [
        FirewallRule('allow-part', ALLOW, ['10.0.0.0/24']),
        FirewallRule('deny-more', DENY, ['10.0.0.0/23']),
    ]
    report = analyze_firewall(rules).rules[-1]

    assert report.status == 'partially_shadowed'
    assert report.truncated_cidrs == ['10.0.0.0/24']
    assert report.effective_cidrs == ['10.0.1.0/24']
    assert report.safe_to_delete is False


def test_ipv6_regions_are_reported_as_merged_cidrs():
    rules = [
        FirewallRule('r1', ALLOW, ['2001:db8::/33']),
        FirewallRule('r2', ALLOW, ['2001:db8:8000::/33']),
        FirewallRule('r3', ALLOW, ['2001:db8::/32']),
    ]
    report = analyze_firewall(rules, default_action=DENY).rules[-1]

    assert report.redundant_cidrs == ['2001:db8::/32']
    assert report.effective_cidrs == []


def test_deleting_all_safe_rules_preserves_all_policy_partitions():
    rules = [
        FirewallRule('r1', ALLOW, ['192.0.2.0/26']),
        FirewallRule('r2', ALLOW, ['192.0.2.64/26']),
        FirewallRule('r3', ALLOW, ['192.0.2.128/25']),
        FirewallRule('same-decision-redundant', ALLOW, ['192.0.2.0/24']),
        FirewallRule('opposite-truncated', DENY, ['192.0.2.0/24']),
        FirewallRule('active', ALLOW, ['203.0.113.0/24']),
    ]
    analysis = analyze_firewall(rules, default_action=DENY)

    assert analysis.safe_to_delete == [
        'same-decision-redundant',
        'opposite-truncated',
    ]

    verification = verify_safe_deletions(rules, default_action=DENY)

    assert verification.equivalent is True
    assert verification.differences == {}
    assert verification.before.decisions[ALLOW] == verification.after.decisions[ALLOW]
    assert verification.before.decisions[DENY] == verification.after.decisions[DENY]
    assert verification.after.decisions[ALLOW] == IPSet(
        ['192.0.2.0/24', '203.0.113.0/24']
    )


def test_policy_uses_default_action_for_unmatched_addresses():
    policy = compile_firewall_policy(
        [FirewallRule('allow-test', ALLOW, ['192.0.2.0/24', '2001:db8::/32'])],
        default_action=DENY,
    )

    assert policy.partitions[ALLOW] == ['192.0.2.0/24', '2001:db8::/32']
    assert '192.0.2.0/24' not in policy.decisions[DENY]
    assert '2001:db8::/32' not in policy.decisions[DENY]
    assert IPSet(['0.0.0.0/0', '::/0']) == (
        policy.decisions[ALLOW] | policy.decisions[DENY]
    )


def test_custom_universe_clips_rule_and_policy_to_analyzed_partitions():
    rules = [FirewallRule('r1', DENY, ['192.0.2.0/24', '198.51.100.0/24'])]
    universe = IPSet(['192.0.2.0/25'])
    analysis = analyze_firewall(rules, default_action=ALLOW, universe=universe)

    assert analysis.rules[0].declared_cidrs == ['192.0.2.0/25']
    assert analysis.policy.partitions == {
        ALLOW: [],
        DENY: ['192.0.2.0/25'],
    }


def test_mapping_input_and_text_report():
    analysis = analyze_firewall(
        [
            {
                'id': 'r1',
                'action': DENY,
                'cidrs': ['10.0.0.0/24', '10.0.1.0/24'],
                'exclusions': ['10.0.0.0/25'],
            }
        ],
        default_action=ALLOW,
    )
    report = format_analysis(analysis)

    assert 'default action: allow' in report
    assert 'r1 (deny): active' in report
    assert 'declared after exclusions: 10.0.0.128/25, 10.0.1.0/24' in report


def test_json_serializable_report_and_cli_verification(tmp_path, capsys):
    rules = [
        {'id': 'r1', 'action': DENY, 'cidrs': ['192.0.2.0/25']},
        {'id': 'r2', 'action': DENY, 'cidrs': ['192.0.2.128/25']},
        {'id': 'r3', 'action': DENY, 'cidrs': ['192.0.2.0/24']},
    ]
    config = {'default_action': ALLOW, 'rules': rules}
    config_path = tmp_path / 'rules.json'
    config_path.write_text(json.dumps(config), encoding='utf-8')

    assert main([str(config_path), '--json', '--verify-safe-deletions']) == 0

    output = capsys.readouterr().out
    payload = json.loads(output)
    assert payload['safe_to_delete'] == ['r3']
    assert payload['deletion_verification']['equivalent'] is True

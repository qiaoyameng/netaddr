import pytest

from netaddr.contrib.network_migration import (
    CONFLICT,
    MAPPED,
    NOT_IN_MIGRATION,
    FORBIDDEN_TARGET,
    OCCUPIED_TARGET,
    PLAN_CONFLICT,
    UNUSED_TARGET,
    NetworkMigrationPlanner,
)
from netaddr.ip import IPAddress, IPNetwork, IPRange


def test_plans_mapping_and_uses_only_required_prefix_part():
    planner = NetworkMigrationPlanner(
        [('10.0.0.0/24', '192.0.2.0/23', 'site-a')],
    )
    result = planner.plan()

    assert result.executable is True
    assert result.conflicts == ()
    assert result.mappings[0].source == IPNetwork('10.0.0.0/24')
    assert result.mappings[0].target == IPNetwork('192.0.2.0/24')
    assert result.mappings[0].requested_target == IPNetwork('192.0.2.0/23')

    mapped = planner.lookup('10.0.0.5')
    assert mapped.status == MAPPED
    assert mapped.target == IPAddress('192.0.2.5')
    reverse = planner.reverse_lookup('192.0.2.5')
    assert reverse.source == IPAddress('10.0.0.5')
    assert reverse.source_network == IPNetwork('10.0.0.0/24')

    assert planner.lookup('10.0.1.5').status == NOT_IN_MIGRATION
    unused = planner.reverse_lookup('192.0.3.5')
    assert unused.status == UNUSED_TARGET
    assert unused.plan_id == 'site-a'


def test_source_overlap_is_rejected():
    with pytest.raises(ValueError, match='overlap'):
        NetworkMigrationPlanner(
            [('10.0.0.0/24', '192.0.2.0/24'), ('10.0.0.128/25', '198.51.100.0/25')]
        )


def test_target_capacity_shortage_is_rejected():
    with pytest.raises(ValueError, match='too small'):
        NetworkMigrationPlanner([('10.0.0.0/24', '192.0.2.0/25')]).plan()


def test_occupied_and_forbidden_ranges_create_conflicts():
    planner = NetworkMigrationPlanner(
        [
            ('10.0.0.0/24', '192.0.2.0/24', 'occupied'),
            ('10.1.0.0/24', '198.51.100.0/24', 'forbidden'),
        ],
        occupied=[IPRange('192.0.2.10', '192.0.2.20')],
        forbidden=['198.51.100.128/25'],
    )
    result = planner.plan()

    assert result.executable is False
    assert result.mappings == ()
    assert result.conflicts[0].kind == OCCUPIED_TARGET
    assert result.conflicts[0].overlap == IPRange('192.0.2.10', '192.0.2.20')
    assert result.conflicts[1].kind == FORBIDDEN_TARGET
    assert result.conflicts[1].overlap == IPRange('198.51.100.128', '198.51.100.255')
    assert planner.lookup('10.0.0.10').status == CONFLICT
    assert planner.reverse_lookup('192.0.2.10').status == CONFLICT


def test_two_plans_on_same_target_fragment_report_both_sources_and_true_overlap():
    planner = NetworkMigrationPlanner(
        [
            ('10.0.0.0/24', '203.0.112.0/23', 'first'),
            ('172.16.0.0/24', '203.0.112.0/24', 'second'),
        ]
    )
    result = planner.plan()

    assert result.executable is False
    assert result.mappings == ()
    assert len(result.conflicts) == 1
    conflict = result.conflicts[0]
    assert conflict.kind == PLAN_CONFLICT
    assert conflict.plan_id == 'first'
    assert conflict.source == IPNetwork('10.0.0.0/24')
    assert conflict.target == IPNetwork('203.0.112.0/24')
    assert conflict.other_plan_id == 'second'
    assert conflict.other_source == IPNetwork('172.16.0.0/24')
    assert conflict.other_target == IPNetwork('203.0.112.0/24')
    assert conflict.overlap == IPRange('203.0.112.0', '203.0.112.255')
    assert planner.lookup('10.0.0.1').status == CONFLICT
    assert planner.lookup('172.16.0.1').status == CONFLICT
    assert planner.reverse_lookup('203.0.112.1').status == CONFLICT
    assert planner.reverse_lookup('203.0.113.1').status == UNUSED_TARGET


def test_ipv4_to_ipv6_requires_explicit_permission_and_preserves_offsets():
    pairs = [('192.0.2.0/24', '2001:db8::/32')]

    with pytest.raises(ValueError, match='requires allow_ipv4_to_ipv6'):
        NetworkMigrationPlanner(pairs)

    planner = NetworkMigrationPlanner(pairs, allow_ipv4_to_ipv6=True)
    result = planner.plan()

    assert result.mappings[0].target == IPNetwork('2001:db8::/120')
    assert planner.lookup('192.0.2.10').target == IPAddress('2001:db8::a')
    reverse = planner.reverse_lookup('2001:db8::a')
    assert reverse.source == IPAddress('192.0.2.10')
    assert reverse.source_network == IPNetwork('192.0.2.0/24')


def test_ipv6_to_ipv4_requires_explicit_permission_and_preserves_offsets():
    pairs = [('2001:db8::/120', '192.0.2.0/24')]

    with pytest.raises(ValueError, match='requires allow_ipv6_to_ipv4'):
        NetworkMigrationPlanner(pairs)

    planner = NetworkMigrationPlanner(pairs, allow_ipv6_to_ipv4=True)
    result = planner.plan()

    assert result.mappings[0].target == IPNetwork('192.0.2.0/24')
    assert planner.lookup('2001:db8::ff').target == IPAddress('192.0.2.255')
    reverse = planner.reverse_lookup('192.0.2.255')
    assert reverse.source == IPAddress('2001:db8::ff')
    assert reverse.source_network == IPNetwork('2001:db8::/120')

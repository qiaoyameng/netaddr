import pytest

from netaddr import IPAddress, IPNetwork, IPRange
from netaddr.contrib.migration_planner import (
    ConflictKind,
    LookupStatus,
    MigrationPair,
    MigrationPlanner,
    intersect_ranges,
    plan_migrations,
)


def test_simple_plan_preserves_offset_and_uses_only_prefix():
    # target is larger (/23) than source (/24): only the leading /24 part
    # of the target may be consumed.
    pair = MigrationPair('10.0.0.0/24', '192.0.2.0/23', name='web')
    report = MigrationPlanner().plan([pair])

    assert report.ok
    plan = report.plans[0]
    assert plan.used == IPRange('192.0.2.0', '192.0.2.255')
    assert plan.translate(IPAddress('10.0.0.1')) == IPAddress('192.0.2.1')
    assert plan.translate(IPAddress('10.0.0.255')) == IPAddress('192.0.2.255')
    assert plan.reverse(IPAddress('192.0.2.200')) == IPAddress('10.0.0.200')

    # the trailing part of the bigger target was not consumed
    assert report.reverse_lookup('192.0.3.5').status == LookupStatus.UNUSED_TARGET


def test_insufficient_target_capacity_is_an_error_not_a_plan():
    pair = MigrationPair('10.0.0.0/24', '192.0.2.0/25', name='too-small')
    report = MigrationPlanner().plan([pair])

    assert report.plans == ()
    conflict = report.conflicts[0]
    assert conflict.kind == ConflictKind.INSUFFICIENT_TARGET_CAPACITY
    assert conflict.plans[0].pair.name == 'too-small'


def test_ambiguous_source_overlap_blocks_both_sides():
    pairs = [
        MigrationPair('10.0.0.0/24', '192.0.2.0/25', name='a'),
        MigrationPair('10.0.0.128/25', '203.0.113.0/25', name='b'),
    ]
    report = MigrationPlanner().plan(pairs)

    assert report.plans == ()
    conflict = report.conflicts[0]
    assert conflict.kind == ConflictKind.SOURCE_OVERLAP
    assert {plan.pair.name for plan in conflict.plans} == {'a', 'b'}
    assert conflict.overlap == IPRange('10.0.0.128', '10.0.0.255')

    result = report.lookup('10.0.0.130')
    assert result.status == LookupStatus.CONFLICT


def test_occupied_and_forbidden_target_ranges():
    pair = MigrationPair('10.0.0.0/24', '192.0.2.0/24', name='x')

    occupied = MigrationPlanner(occupied=['192.0.2.10-192.0.2.20']).plan([pair])
    assert occupied.plans == ()
    assert occupied.conflicts[0].kind == ConflictKind.TARGET_OCCUPIED
    assert occupied.conflicts[0].overlap == IPRange('192.0.2.10', '192.0.2.20')

    forbidden = MigrationPlanner(forbidden=['192.0.2.0/28']).plan([pair])
    assert forbidden.plans == ()
    assert forbidden.conflicts[0].kind == ConflictKind.TARGET_FORBIDDEN
    assert forbidden.conflicts[0].overlap == IPRange('192.0.2.0', '192.0.2.15')

    # unrelated occupied range on the same network does not block
    fine = MigrationPlanner(occupied=['198.51.100.0/24']).plan([pair])
    assert fine.ok


def test_two_plans_on_same_target_fragment_report_both_sources_and_real_overlap():
    pairs = [
        MigrationPair('10.0.0.0/24', '192.0.2.0/24', name='web'),
        MigrationPair('172.16.0.128/25', '192.0.2.128/25', name='db'),
    ]
    report = MigrationPlanner().plan(pairs)

    # neither failed plan is wrapped as an executable result
    assert report.plans == ()
    assert not report.ok

    collision = [
        conflict
        for conflict in report.conflicts
        if conflict.kind == ConflictKind.TARGET_COLLISION
    ]
    assert len(collision) == 1
    conflict = collision[0]

    # both sources named
    assert {plan.pair.name for plan in conflict.plans} == {'web', 'db'}
    assert {plan.pair.source for plan in conflict.plans} == {
        IPRange('10.0.0.0', '10.0.0.255'),
        IPRange('172.16.0.128', '172.16.0.255'),
    }

    # the *genuinely* overlapping interval, not the whole /24
    assert conflict.overlap == IPRange('192.0.2.128', '192.0.2.255')

    # addresses inside the disputed fragment report conflict
    assert report.reverse_lookup('192.0.2.200').status == LookupStatus.CONFLICT


def test_target_collision_partial_overlap_interval():
    # overlapping used portions are not aligned blocks; overlap must be
    # computed by interval arithmetic, not block labels
    pairs = [
        MigrationPair(IPRange('10.0.0.0', '10.0.0.199'), IPRange('192.0.2.0', '192.0.2.255')),
        MigrationPair(IPRange('172.16.0.0', '172.16.0.99'), IPRange('192.0.2.150', '192.0.2.255')),
    ]
    report = plan_migrations(pairs)
    assert report.plans == ()
    assert report.conflicts[0].overlap == IPRange('192.0.2.150', '192.0.2.199')


def test_lookup_distinguishes_all_three_states():
    report = plan_migrations([MigrationPair('10.0.0.0/24', '192.0.2.0/23')])

    mapped = report.lookup('10.0.0.42')
    assert mapped.status == LookupStatus.MAPPED
    assert mapped.counterpart == IPAddress('192.0.2.42')

    back = report.reverse_lookup('192.0.2.42')
    assert back.status == LookupStatus.MAPPED
    assert back.counterpart == IPAddress('10.0.0.42')

    assert report.lookup('10.0.1.1').status == LookupStatus.NOT_MIGRATED
    assert report.reverse_lookup('203.0.113.1').status == LookupStatus.NOT_MIGRATED

    # inside the target network but in the part no plan needs
    unused = report.reverse_lookup('192.0.3.10')
    assert unused.status == LookupStatus.UNUSED_TARGET


def test_cross_family_migration_requires_opt_in_and_keeps_offset():
    pair = MigrationPair('10.0.0.0/24', '2001:db8::/120', name='v4-to-v6')

    rejected = MigrationPlanner().plan([pair])
    assert rejected.plans == ()
    assert rejected.conflicts[0].kind == ConflictKind.ADDRESS_FAMILY_MISMATCH

    allowed = MigrationPlanner(allow_cross_family=True).plan([pair])
    assert allowed.ok
    plan = allowed.plans[0]
    assert plan.used == IPRange(IPAddress('2001:db8::'), IPAddress('2001:db8::ff'))
    assert plan.translate(IPAddress('10.0.0.255')) == IPAddress('2001:db8::ff')

    # reverse direction: IPv6 source larger than IPv4 target cannot keep the
    # offset for every address, so it must fail loudly rather than truncate
    too_big = MigrationPlanner(allow_cross_family=True).plan(
        [MigrationPair('2001:db8::/112', '192.0.2.0/24')]
    )
    assert too_big.plans == ()
    assert too_big.conflicts[0].kind == ConflictKind.INSUFFICIENT_TARGET_CAPACITY

    # small IPv6 source into IPv4 target with the flag preserves offsets
    small = MigrationPlanner(allow_cross_family=True).plan(
        [MigrationPair('2001:db8::/120', '192.0.2.0/24')]
    )
    assert small.ok
    assert small.plans[0].translate(IPAddress('2001:db8::10')) == IPAddress('192.0.2.16')


def test_range_helpers_never_mix_families_or_expand():
    assert intersect_ranges(IPRange('10.0.0.0', '10.0.0.9'),
                            IPRange('10.0.0.5', '10.0.0.20')) == IPRange('10.0.0.5', '10.0.0.9')
    assert intersect_ranges(IPRange('10.0.0.0', '10.0.0.4'),
                            IPRange('10.0.0.5', '10.0.0.9')) is None
    v6 = IPRange(IPAddress('::1', 6), IPAddress('::ffff:ffff', 6))
    assert intersect_ranges(v6, IPRange('0.0.0.1', '0.0.0.9')) is None

    assert str(intersect_ranges(
        IPRange(IPAddress('2001:db8::', 6), IPAddress('2001:db8::ff', 6)),
        IPRange(IPAddress('2001:db8::10', 6), IPAddress('2001:db8::100', 6)),
    )) == '2001:db8::10-2001:db8::ff'


def test_coerce_range_accepts_cidr_and_endpoint_forms():
    from netaddr.contrib.migration_planner import coerce_range

    assert coerce_range('10.0.0.0/31') == IPRange('10.0.0.0', '10.0.0.1')
    assert coerce_range(IPNetwork('10.0.0.0/32')) == IPRange('10.0.0.0', '10.0.0.0')
    assert coerce_range(('10.0.0.3', '10.0.0.7')) == IPRange('10.0.0.3', '10.0.0.7')
    assert coerce_range('10.0.0.3-10.0.0.7') == IPRange('10.0.0.3', '10.0.0.7')


def test_unrelated_plans_still_execute_alongside_a_failure():
    pairs = [
        MigrationPair('10.0.0.0/24', '192.0.2.0/24', name='collides'),
        MigrationPair('172.16.0.0/24', '192.0.2.0/24', name='collides-too'),
        MigrationPair('10.1.0.0/24', '203.0.113.0/24', name='fine'),
    ]
    report = MigrationPlanner().plan(pairs)

    assert len(report.plans) == 1
    assert report.plans[0].pair.name == 'fine'
    assert report.plans[0].used == IPRange('203.0.113.0', '203.0.113.255')

import pytest

from netaddr import (
    CNAMERecord,
    IPNetwork,
    IPRange,
    NSRecord,
    PTRRecord,
    ReverseDNSPlanner,
)


NAMESERVERS = ('ns1.example.com', 'ns2.example.com')


def test_rfc2317_delegation_keeps_network_and_broadcast_addresses():
    planner = ReverseDNSPlanner(nameservers=NAMESERVERS)

    plan = planner.plan(
        IPNetwork('192.0.2.0/28'),
        ptr_targets={
            '192.0.2.0': 'network.example.com',
            '192.0.2.15': 'broadcast.example.com',
        },
    )

    delegation, = plan.delegations
    assert delegation.network == IPNetwork('192.0.2.0/28')
    assert delegation.parent_zone == '2.0.192.in-addr.arpa.'
    assert delegation.child_zone == '0-15.2.0.192.in-addr.arpa.'
    assert delegation.classless

    cnames = list(plan.cname_records())
    assert len(cnames) == 16
    assert cnames[0] == CNAMERecord(
        '0.2.0.192.in-addr.arpa.',
        '0.0-15.2.0.192.in-addr.arpa.',
    )
    assert cnames[-1] == CNAMERecord(
        '15.2.0.192.in-addr.arpa.',
        '15.0-15.2.0.192.in-addr.arpa.',
    )
    assert set(plan.ptr_names()) == {
        '%d.0-15.2.0.192.in-addr.arpa.' % number for number in range(16)
    }
    assert list(plan.ptr_records()) == [
        PTRRecord('0.0-15.2.0.192.in-addr.arpa.', 'network.example.com.'),
        PTRRecord('15.0-15.2.0.192.in-addr.arpa.', 'broadcast.example.com.'),
    ]


def test_rfc2317_single_address_label_does_not_alias_zone_apex():
    plan = ReverseDNSPlanner(nameservers=NAMESERVERS).plan(IPNetwork('192.0.2.5/32'))

    delegation, = plan.delegations
    assert delegation.child_zone == '5-5.2.0.192.in-addr.arpa.'
    assert list(plan.cname_records()) == [
        CNAMERecord('5.2.0.192.in-addr.arpa.', '5.5-5.2.0.192.in-addr.arpa.')
    ]


def test_cross_24_range_splits_without_claiming_outside_addresses():
    planner = ReverseDNSPlanner(nameservers=NAMESERVERS)
    addresses = IPRange('192.0.2.252', '192.0.3.3')
    targets = {
        str(address): 'host-%d.example.com' % int(address)
        for address in addresses
    }

    plan = planner.plan(addresses, ptr_targets=targets)

    assert [delegation.network for delegation in plan.delegations] == [
        IPNetwork('192.0.2.252/30'),
        IPNetwork('192.0.3.0/30'),
    ]
    assert [delegation.parent_zone for delegation in plan.delegations] == [
        '2.0.192.in-addr.arpa.',
        '3.0.192.in-addr.arpa.',
    ]
    assert [delegation.child_zone for delegation in plan.delegations] == [
        '252-255.2.0.192.in-addr.arpa.',
        '0-3.3.0.192.in-addr.arpa.',
    ]

    cnames = list(plan.cname_records())
    ptrs = list(plan.ptr_records())

    expected_owners = {address.reverse_dns for address in addresses}
    assert {record.name for record in cnames} == expected_owners

    expected_ptr_names = set()
    for address in addresses:
        delegation = next(item for item in plan.delegations if address in item.network)
        expected_ptr_names.add(delegation.ptr_name(address))
        cname = next(record for record in cnames if record.name == address.reverse_dns)
        assert cname.target == delegation.ptr_name(address)

    assert {record.name for record in ptrs} == expected_ptr_names
    assert {record.target for record in ptrs} == {
        'host-%d.example.com.' % int(address) for address in addresses
    }
    assert len(cnames) == addresses.size
    assert not any(record.name.startswith(('250.2.', '251.2.', '4.3.')) for record in cnames)


def test_parent_and_child_records_include_delegation_and_requested_ptr_records():
    plan = ReverseDNSPlanner(
        parent_zone='0.192.in-addr.arpa.',
        nameservers=NAMESERVERS,
    ).plan(
        [IPNetwork('192.0.2.0/30')],
        ptr_targets={'192.0.2.1': 'host.example.com'},
    )

    parent_records = list(plan.parent_records())
    child_records = list(plan.child_records())

    assert parent_records[:2] == [
        NSRecord('0-3.2.0.192.in-addr.arpa.', 'ns1.example.com.'),
        NSRecord('0-3.2.0.192.in-addr.arpa.', 'ns2.example.com.'),
    ]
    assert len(parent_records) == 6
    assert child_records[:2] == parent_records[:2]
    assert child_records[-1] == PTRRecord(
        '1.0-3.2.0.192.in-addr.arpa.',
        'host.example.com.',
    )


def test_direct_octet_boundary_delegation_does_not_use_rfc2317_cnames():
    plan = ReverseDNSPlanner(nameservers=NAMESERVERS).plan(
        IPNetwork('192.0.2.0/24'),
        ptr_targets={
            '192.0.2.0': 'network.example.com',
            '192.0.2.255': 'broadcast.example.com',
        },
    )

    delegation, = plan.delegations
    assert plan.nameservers == ('ns1.example.com.', 'ns2.example.com.')
    assert delegation.parent_zone == '0.192.in-addr.arpa.'
    assert delegation.child_zone == '2.0.192.in-addr.arpa.'
    assert not delegation.classless
    assert list(plan.cname_records()) == []
    assert plan.parent_ns_records == [
        NSRecord('2.0.192.in-addr.arpa.', 'ns1.example.com.'),
        NSRecord('2.0.192.in-addr.arpa.', 'ns2.example.com.'),
    ]
    assert list(plan.ptr_records()) == [
        PTRRecord('0.2.0.192.in-addr.arpa.', 'network.example.com.'),
        PTRRecord('255.2.0.192.in-addr.arpa.', 'broadcast.example.com.'),
    ]


def test_non_contiguous_and_oversized_ranges_split_without_overlap():
    plan = ReverseDNSPlanner(nameservers=NAMESERVERS).plan(
        [
            IPNetwork('198.51.100.0/25'),
            IPNetwork('198.51.100.128/26'),
            IPNetwork('203.0.113.0/23'),
        ]
    )

    networks = [delegation.network for delegation in plan.delegations]
    assert networks == [
        IPNetwork('198.51.100.0/25'),
        IPNetwork('198.51.100.128/26'),
        IPNetwork('203.0.112.0/24'),
        IPNetwork('203.0.113.0/24'),
    ]

    for left_index, left in enumerate(networks):
        for right in networks[left_index + 1:]:
            assert left not in right
            assert right not in left


def test_ipv6_nibble_alignment_splits_exactly_to_requested_space():
    plan = ReverseDNSPlanner(nameservers=NAMESERVERS).plan(IPNetwork('2001:db8::/58'))

    assert [delegation.network for delegation in plan.delegations] == [
        IPNetwork('2001:db8::/60'),
        IPNetwork('2001:db8:0:10::/60'),
        IPNetwork('2001:db8:0:20::/60'),
        IPNetwork('2001:db8:0:30::/60'),
    ]

    first, second = plan.delegations[:2]
    assert first.parent_zone == (
        '0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
    )
    assert first.child_zone == (
        '0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
    )
    assert second.child_zone == (
        '1.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
    )
    assert not any(delegation.classless for delegation in plan.delegations)
    assert list(plan.cname_records()) == []


def test_ipv6_aligned_nibble_delegates_one_zone():
    plan = ReverseDNSPlanner(nameservers=NAMESERVERS).plan(
        IPNetwork('2001:db8::/128'),
        ptr_targets={'2001:db8::': 'loopback.example.com'},
    )

    delegation, = plan.delegations
    expected_zone = plan.delegations[0].ptr_name(IPNetwork('2001:db8::/128').ip)
    assert delegation.child_zone == expected_zone
    assert list(plan.ptr_records()) == [PTRRecord(expected_zone, 'loopback.example.com.')]


def test_callable_label_and_parent_zone_rules():
    plan = ReverseDNSPlanner(
        parent_zone=lambda network, natural: natural,
        nameservers=NAMESERVERS,
        label_rule=lambda network: 'pool-%d' % (network.first & 255),
    ).plan(IPNetwork('192.0.2.64/26'))

    delegation, = plan.delegations
    assert delegation.parent_zone == '2.0.192.in-addr.arpa.'
    assert delegation.child_zone == 'pool-64.2.0.192.in-addr.arpa.'


def test_record_budget_rejects_oversized_concrete_output():
    planner = ReverseDNSPlanner(nameservers=NAMESERVERS)

    with pytest.raises(ValueError, match='record_budget'):
        planner.plan(IPNetwork('192.0.2.0/28'), record_budget=19)

    plan = planner.plan(IPNetwork('192.0.2.0/28'), record_budget=20)
    assert len(list(plan.parent_records())) == 18
    assert len(list(plan.child_records())) == 2


def test_ptr_target_outside_requested_space_is_rejected():
    planner = ReverseDNSPlanner(nameservers=NAMESERVERS)

    with pytest.raises(ValueError, match='outside delegated address space'):
        planner.plan(
            IPNetwork('192.0.2.0/29'),
            ptr_targets={'192.0.2.8': 'outside.example.com'},
        )

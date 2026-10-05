"""Tests for the RFC 2317 / nibble reverse DNS delegation planner.

These tests never make any DNS requests; they only inspect the planned zone
data.
"""
import pytest

from netaddr import IPAddress, IPNetwork, IPRange, IPSet
from netaddr.contrib.reverse_delegation import (
    CIDRLabelRule,
    DashRangeLabelRule,
    DelegationPlan,
    DNSRecord,
    PTRBudgetExceeded,
    ReverseDNSDelegationPlanner,
    ReverseZone,
    plan_reverse_delegation,
)

NS = ['ns1.example.com.', 'ns2.example.org.']


def names(plan, kind=None):
    zones = plan.zones if kind is None else getattr(plan, kind + '_zones')
    return sorted(zone.name for zone in zones)


# ---------------------------------------------------------------------------
#   IPv4: RFC 2317 classless delegation
# ---------------------------------------------------------------------------
def test_slash28_uses_rfc2317_tagged_zone():
    planner = ReverseDNSDelegationPlanner(['192.0.2.16/28'], NS)
    plan = planner.plan()

    assert names(plan) == [
        '16-31.2.0.192.in-addr.arpa.',
        '2.0.192.in-addr.arpa.',
    ]
    parent = plan.zone('2.0.192.in-addr.arpa.')
    child = plan.zone('16-31.2.0.192.in-addr.arpa.')

    #   Parent delegates the tagged zone with one NS per name server.
    assert sorted(rec.value for rec in parent.ns_records) == sorted(NS)
    assert all(rec.owner == '16-31.2.0.192.in-addr.arpa.'
               and rec.rtype == 'NS' for rec in parent.ns_records)

    #   One CNAME per covered address, all 16 of them -- .16 and .31
    #   (network + broadcast) included.
    cname_owners = sorted(rec.owner for rec in parent.cname_records)
    assert cname_owners == sorted(
        '%d.2.0.192.in-addr.arpa.' % i for i in range(16, 32))
    for rec in parent.cname_records:
        assert rec.rtype == 'CNAME'
        head = rec.owner.split('.', 1)[0]
        assert rec.value == '%s.16-31.2.0.192.in-addr.arpa.' % head

    #   Child coverage must be exactly the /28, never the surrounding /24.
    assert list(child.coverage.iter_cidrs()) == [IPNetwork('192.0.2.16/28')]
    ptrs = list(child.iter_ptr_records())
    assert len(ptrs) == 16
    assert [p.owner for p in ptrs][0] == '16.16-31.2.0.192.in-addr.arpa.'
    assert [p.owner for p in ptrs][-1] == '31.16-31.2.0.192.in-addr.arpa.'
    assert all(p.value is None for p in ptrs)
    assert child.rfc2317 is True


def test_slash28_does_not_become_plain_three_octet_zone():
    #   The exact mistake the task warns about: reversing the first three
    #   octets and delegating that as if it were the /28.
    plan = ReverseDNSDelegationPlanner(['192.0.2.16/28'], NS).plan()
    child = plan.child_zones
    #   There is no child named after the bare /24.
    assert all(zone.name != '2.0.192.in-addr.arpa.' for zone in child)
    #   The /24 itself stays a parent zone.
    assert plan.zone('2.0.192.in-addr.arpa.').kind == 'parent'


def test_network_and_broadcast_have_ptr_owners():
    plan = ReverseDNSDelegationPlanner(['192.0.2.16/28'], NS).plan()
    for last_octet in (16, 31):
        chain = plan.ptr_chain('192.0.2.%d' % last_octet)
        assert chain[-1].rtype == 'PTR'


def test_natural_octet_aligned_prefixes_delegate_directly():
    #   /24 is a genuine reverse-tree cut: no CNAMEs.
    plan = ReverseDNSDelegationPlanner(['10.11.12.0/24'], NS).plan()
    assert names(plan) == ['11.10.in-addr.arpa.', '12.11.10.in-addr.arpa.']
    parent = plan.zone('11.10.in-addr.arpa.')
    assert len(parent.ns_records) == len(NS)
    assert parent.cname_records == []
    child = plan.zone('12.11.10.in-addr.arpa.')
    assert len(list(child.iter_ptr_records())) == 256

    #   /16 and /8 cut directly as well.
    plan16 = ReverseDNSDelegationPlanner(['10.11.0.0/16'], NS).plan()
    assert names(plan16) == ['10.in-addr.arpa.', '11.10.in-addr.arpa.']


def test_non_aligned_octet_prefix_expands_to_aligned_children():
    #   /23 -> two fully covered /24s, nothing over-delegated.
    plan = ReverseDNSDelegationPlanner(['10.11.12.0/23'], NS).plan()
    assert names(plan, 'child') == [
        '12.11.10.in-addr.arpa.', '13.11.10.in-addr.arpa.']
    assert plan.coverage() == IPSet(['10.11.12.0/23'])


def test_slash32_is_a_natural_single_address_zone():
    plan = ReverseDNSDelegationPlanner(['10.11.12.5/32'], NS).plan()
    assert names(plan, 'child') == ['5.12.11.10.in-addr.arpa.']
    parent = plan.zone('12.11.10.in-addr.arpa.')
    assert parent.cname_records == []


# ---------------------------------------------------------------------------
#   Acceptance: small range crossing two /24s, per-address CNAME trace
# ---------------------------------------------------------------------------
def test_cross_slash24_range_trace_each_address():
    #   Six addresses on each side of a /24 boundary -> 12 in total.
    address_range = IPRange('192.0.2.250', '192.0.3.5')
    plan = ReverseDNSDelegationPlanner([address_range], NS).plan()

    assert names(plan) == [
        '0-5.3.0.192.in-addr.arpa.',
        '2.0.192.in-addr.arpa.',
        '250-255.2.0.192.in-addr.arpa.',
        '3.0.192.in-addr.arpa.',
    ]

    expected = {}
    for address in iter_iprange_plain('192.0.2.250', '192.0.3.5'):
        octets = address.split('.')
        parent_zone = '%s.0.192.in-addr.arpa.' % octets[2]
        tag = ('250-255' if octets[2] == '2' else '0-5')
        arpa = '%s.%s' % (octets[3], parent_zone)
        final = '%s.%s.%s' % (octets[3], tag, parent_zone)
        expected[address] = (parent_zone, arpa, tag + '.' + parent_zone, final)

    #   Exactly 12 addresses accounted for, no more and no less.
    traced = set()
    for address, (parent_zone, arpa, tagged_zone, final) in expected.items():
        chain = plan.ptr_chain(address)
        assert len(chain) == 2, address           # one CNAME + terminal PTR
        cname, ptr = chain
        assert cname.rtype == 'CNAME'
        assert cname.zone == parent_zone
        assert cname.owner == arpa
        assert cname.value == final
        assert ptr.rtype == 'PTR'
        assert ptr.owner == final
        assert ptr.zone == tagged_zone
        traced.add(address)
    assert len(traced) == 12

    #   Nothing outside the requested range was delegated.
    for outside in ('192.0.2.249', '192.0.3.6', '192.0.2.0', '192.0.4.1'):
        with pytest.raises(KeyError):
            plan.ptr_chain(outside)

    #   Covered address space is exactly the request.
    assert plan.coverage() == IPSet([address_range])
    #   Child zones never claim the surrounding /24 space.
    outside = IPSet(['192.0.2.0/24', '192.0.3.0/24']) - IPSet([address_range])
    for child in plan.child_zones:
        assert child.coverage.isdisjoint(outside)

    #   Parents contain CNAMEs only for the requested addresses.
    for parent in plan.parent_zones:
        for rec in parent.cname_records:
            head = int(rec.owner.split('.', 1)[0])
            if parent.name == '2.0.192.in-addr.arpa.':
                assert 250 <= head <= 255
            else:
                assert 0 <= head <= 5


def test_disjoint_ranges_in_same_slash24_become_separate_zones():
    plan = ReverseDNSDelegationPlanner(
        [IPRange('10.11.12.0', '10.11.12.3'),
         IPRange('10.11.12.8', '10.11.12.11')], NS).plan()
    assert names(plan, 'child') == [
        '0-3.12.11.10.in-addr.arpa.',
        '8-11.12.11.10.in-addr.arpa.',
    ]
    #   Addresses in the gap must not have been claimed.
    for gap in range(4, 8):
        with pytest.raises(KeyError):
            plan.ptr_chain('10.11.12.%d' % gap)
    assert plan.coverage() == IPSet([
        IPNetwork('10.11.12.0/30'), IPNetwork('10.11.12.8/30')])


def iter_iprange_plain(start, end):
    for ip in __import__('netaddr').iter_iprange(start, end):
        yield str(ip)


# ---------------------------------------------------------------------------
#   IPv6: nibble boundary zones
# ---------------------------------------------------------------------------
def test_ipv6_nibble_aligned_slash64_delegates_directly():
    plan = ReverseDNSDelegationPlanner(['2001:db8::/64'], NS).plan()
    child_name = '0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
    parent_name = '0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.'
    assert names(plan) == sorted([child_name, parent_name])
    child = plan.zone(child_name)
    parent = plan.zone(parent_name)
    assert child.rfc2317 is False
    assert parent.cname_records == []
    assert [r.value for r in parent.ns_records] == list(reversed(NS)) or \
        sorted(r.value for r in parent.ns_records) == sorted(NS)
    #   2^64 PTR owners, streamed lazily rather than materialised.
    first_ranges = child._ptr_ranges[0]
    assert str(first_ranges[0]) == '2001:db8::'
    assert int(first_ranges[1]) - int(first_ranges[0]) + 1 == 2 ** 64


def test_ipv6_slash62_splits_into_four_slash64():
    plan = ReverseDNSDelegationPlanner(['2001:db8::/62'], NS).plan()
    children = plan.child_zones
    assert len(children) == 4
    assert plan.coverage() == IPSet(['2001:db8::/62'])
    #   Must not over-delegate a containing nibble block.
    for child in children:
        assert list(child.coverage.iter_cidrs())[0].prefixlen == 64
    top_nibbles = sorted(zone.name.split('.', 1)[0] for zone in children)
    assert top_nibbles == ['0', '1', '2', '3']


def test_ipv6_non_nibble_slash65_uses_contained_nibble_blocks():
    #   A /65 cannot be one zone (65 is not a nibble boundary) and must not
    #   be rounded UP to a /64 (that would over-delegate the top half).
    plan = ReverseDNSDelegationPlanner(['2001:db8::/65'], NS).plan()
    children = plan.child_zones
    assert len(children) == 8
    for child in children:
        cidr = list(child.coverage.iter_cidrs())[0]
        assert cidr.prefixlen == 68
    assert plan.coverage() == IPSet(['2001:db8::/65'])


def test_ipv6_bare_host_goes_in_enclosing_nibble_zone():
    plan = ReverseDNSDelegationPlanner(['2001:db8::1'], NS).plan()
    assert names(plan, 'child') == []
    parent = plan.parent_zones[0]
    assert len(parent.bare_ptr_records) == 1
    rec = parent.bare_ptr_records[0]
    assert rec.rtype == 'PTR'
    assert rec.owner == IPAddress('2001:db8::1').reverse_dns


# ---------------------------------------------------------------------------
#   Bare hosts vs delegated networks; PTR targets
# ---------------------------------------------------------------------------
def test_bare_host_only_emits_parent_ptr():
    plan = ReverseDNSDelegationPlanner(['10.11.12.7'], NS).plan()
    assert plan.child_zones == ()
    parent = plan.zone('12.11.10.in-addr.arpa.')
    assert len(parent.bare_ptr_records) == 1
    assert parent.bare_ptr_records[0].owner == '7.12.11.10.in-addr.arpa.'


def test_host_inside_delegated_network_is_not_bare():
    plan = ReverseDNSDelegationPlanner(
        ['10.11.12.0/28', '10.11.12.9', '10.11.12.40'], NS).plan()
    parent = plan.zone('12.11.10.in-addr.arpa.')
    bare_owners = {rec.owner for rec in parent.bare_ptr_records}
    assert bare_owners == {'40.12.11.10.in-addr.arpa.'}
    #   .9 is reached through the tagged zone, not a bare PTR.
    chain = plan.ptr_chain('10.11.12.9')
    assert chain[0].rtype == 'CNAME'


def test_ptr_targets_callable_and_mapping():
    targets = {'192.0.2.16': 'host16.example.com.'}
    plan = ReverseDNSDelegationPlanner(
        ['192.0.2.16/28'], NS, ptr_targets=targets).plan()
    ptrs = list(plan.zone('16-31.2.0.192.in-addr.arpa.').iter_ptr_records())
    by_owner = {p.owner: p.value for p in ptrs}
    assert by_owner['16.16-31.2.0.192.in-addr.arpa.'] == 'host16.example.com.'
    assert by_owner['17.16-31.2.0.192.in-addr.arpa.'] is None

    plan2 = ReverseDNSDelegationPlanner(
        ['10.0.0.1'], NS,
        ptr_targets=lambda ip: 'x.example.com.').plan()
    assert plan2.parent_zones[0].bare_ptr_records[0].value == 'x.example.com.'


# ---------------------------------------------------------------------------
#   Label rules
# ---------------------------------------------------------------------------
def test_cidr_label_rule():
    plan = ReverseDNSDelegationPlanner(
        ['192.0.2.16/28'], NS, label_rule=CIDRLabelRule()).plan()
    assert '16/28.2.0.192.in-addr.arpa.' in names(plan)


def test_cidr_label_rule_rejects_non_cidr_group():
    with pytest.raises(ValueError):
        ReverseDNSDelegationPlanner(
            [IPRange('10.11.12.0', '10.11.12.5')], NS,
            label_rule=CIDRLabelRule()).plan()


def test_custom_label_callable():
    plan = ReverseDNSDelegationPlanner(
        ['192.0.2.16/28'], NS,
        label_rule=lambda rng: 'myblock').plan()
    assert 'myblock.2.0.192.in-addr.arpa.' in names(plan)


def test_label_must_be_single_dns_label():
    with pytest.raises(ValueError):
        ReverseDNSDelegationPlanner(
            ['192.0.2.16/28'], NS,
            label_rule=lambda rng: 'a.b').plan()


# ---------------------------------------------------------------------------
#   Parent zone, name servers and validation
# ---------------------------------------------------------------------------
def test_parent_zone_override():
    plan = ReverseDNSDelegationPlanner(
        ['10.11.12.16/28'], NS,
        parent_zone='12.11.10.in-addr.arpa.').plan()
    assert '12.11.10.in-addr.arpa.' in names(plan)


def test_parent_zone_override_mismatch_rejected():
    with pytest.raises(ValueError):
        ReverseDNSDelegationPlanner(
            ['10.11.12.16/28'], NS,
            parent_zone='99.11.10.in-addr.arpa.').plan()


def test_requires_nameservers_and_addresses():
    with pytest.raises(ValueError):
        ReverseDNSDelegationPlanner(['10.0.0.0/24'], [])
    with pytest.raises(ValueError):
        ReverseDNSDelegationPlanner([], NS)


def test_nameservers_added_as_fqdn():
    #   A missing trailing dot is normalised rather than treated as relative.
    plan = ReverseDNSDelegationPlanner(
        ['192.0.2.16/28'], ['ns1.example.com']).plan()
    assert plan.zone('2.0.192.in-addr.arpa.').ns_records[0].value == \
        'ns1.example.com.'


# ---------------------------------------------------------------------------
#   Budgeting and streaming (no eager blow-up on large ranges)
# ---------------------------------------------------------------------------
def test_ptr_budget_enforced_on_plan():
    planner = ReverseDNSDelegationPlanner(['10.0.0.0/24'], NS)
    with pytest.raises(PTRBudgetExceeded):
        planner.plan(ptr_budget=255)
    planner.plan(ptr_budget=256)  # exactly fits


def test_records_method_budget_only_counts_ptr():
    planner = ReverseDNSDelegationPlanner(['10.0.0.0/24'], NS)
    with pytest.raises(PTRBudgetExceeded):
        planner.plan().records(ptr_budget=255)
    records = planner.plan().records(ptr_budget=256)
    assert sum(1 for r in records if r.rtype == 'PTR') == 256


def test_iter_records_streams_without_budget():
    plan = ReverseDNSDelegationPlanner(['2001:db8::/64'], NS).plan()
    it = plan.iter_records()
    #   NS record comes first; we never materialise 2^64 PTRs.
    first = next(it)
    assert first.rtype == 'NS'


def test_iter_ptr_names_is_lazy():
    import itertools
    planner = ReverseDNSDelegationPlanner(['2001:db8::/64'], NS)
    names_iter = planner.iter_ptr_names()
    first_three = list(itertools.islice(names_iter, 3))
    assert len(first_three) == 3


def test_convenience_function_returns_records():
    records = plan_reverse_delegation(['192.0.2.16/28'], NS)
    kinds = {rec.rtype for rec in records}
    assert kinds == {'NS', 'CNAME', 'PTR'}
    assert len(records) == 2 + 16 + 16

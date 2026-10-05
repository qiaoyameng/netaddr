import time

import pytest

from netaddr import IPAddress, IPNetwork, IPSet
from netaddr.contrib.route_table import (
    BLACKHOLE,
    ForwardingDecision,
    RouteEntry,
    RouteTable,
)


# ---------------------------------------------------------------------------
# Brute-force reference resolver: linear LPM, independent of the trie.
# ---------------------------------------------------------------------------

def _reference_lookup(routes, address):
    """
    Obvious, slow resolver used to cross-check the trie implementation.

    :return: a ``(prefix, is_blackhole, nexthops, metric)`` tuple or ``None``.
    """
    target = IPAddress(address)
    matching = [
        entry
        for entry in routes
        if entry.cidr.version == target.version and target in entry.cidr
    ]
    if not matching:
        return None
    best_prefixlen = max(entry.cidr.prefixlen for entry in matching)
    candidates = [entry for entry in matching if entry.cidr.prefixlen == best_prefixlen]
    best_metric = min(entry.metric for entry in candidates)
    winners = [entry for entry in candidates if entry.metric == best_metric]
    prefix = winners[0].cidr
    if any(entry.nexthop is BLACKHOLE for entry in winners):
        return prefix, True, (BLACKHOLE,), best_metric
    nexthops = tuple(
        sorted({entry.nexthop for entry in winners}, key=lambda hop: hop.value)
    )
    return prefix, False, nexthops, best_metric


def _decision_tuple(decision):
    if decision is None:
        return None
    return decision.prefix, decision.is_blackhole, decision.nexthops, decision.metric


# ---------------------------------------------------------------------------
# Small IPv4 domain, enumerated address by address.
#
#   198.51.100.0/27     pure blackhole (more specific)
#   198.51.100.32/27    blackhole tied at equal metric with a normal route
#   198.51.100.64/27    ECMP pair (two equal-metric next hops)
#   198.51.100.96/27    single normal /27 (with a /32 host route inside)
#   .128-.255           governed directly by the /24 ECMP parent pair
#   198.51.100.100/32   host route (inside the single /27)
# ---------------------------------------------------------------------------

DOMAIN = IPNetwork('198.51.100.0/24')

V4_RECORDS = [
    ('0.0.0.0/0', '203.0.113.1', 100, 'default'),
    ('198.0.0.0/10', '192.0.2.254', 90, 'aggregate'),
    # /24 parent: ECMP pair plus a shadowed worse-metric route.
    ('198.51.100.0/24', '192.0.2.1', 50, 'static-a'),
    ('198.51.100.0/24', '192.0.2.2', 50, 'static-b'),
    ('198.51.100.0/24', '192.0.2.9', 60, 'ospf-backup'),
    # More specific pure blackhole.
    ('198.51.100.0/27', BLACKHOLE, 40, 'rtbh'),
    # Equal-metric blackhole + normal next hop: blackhole wins.
    ('198.51.100.32/27', '192.0.2.20', 40, 'leak'),
    ('198.51.100.32/27', BLACKHOLE, 40, 'rtbh-leak'),
    # ECMP pair.
    ('198.51.100.64/27', '192.0.2.10', 40, 'rack-a'),
    ('198.51.100.64/27', '192.0.2.11', 40, 'rack-b'),
    # Single normal /26.
    ('198.51.100.96/27', '192.0.2.30', 40, 'edge'),
    # Host route inside the /26.
    ('198.51.100.100/32', '192.0.2.77', 10, 'host'),
]


def _domain_addresses():
    return list(DOMAIN)


@pytest.fixture
def populated_v4_table():
    table = RouteTable()
    for record in V4_RECORDS:
        table.add(*record)
    return table


# --- Reference cross-checks -------------------------------------------------

def test_ipv4_full_domain_matches_reference(populated_v4_table):
    table = populated_v4_table
    routes = table.routes()
    for address in _domain_addresses():
        assert _decision_tuple(table.lookup(address)) == _reference_lookup(routes, address)


def test_ipv4_incremental_adds_match_reference():
    table = RouteTable()
    live_routes = []
    previous = {address: None for address in _domain_addresses()}
    for cidr, nexthop, metric, source in V4_RECORDS:
        changed = set(table.add(cidr, nexthop, metric, source))
        stored_nexthop = BLACKHOLE if nexthop is BLACKHOLE else IPAddress(nexthop)
        live_routes.append(RouteEntry(IPNetwork(cidr), stored_nexthop, metric, source))
        for address in _domain_addresses():
            expected = _reference_lookup(live_routes, address)
            assert _decision_tuple(table.lookup(address)) == expected
            region_changed = any(address in block for block in changed)
            assert region_changed == (expected != previous[address]), (
                cidr,
                source,
                address,
            )
        previous = {
            address: _reference_lookup(live_routes, address) for address in _domain_addresses()
        }
    assert len(table) == len(V4_RECORDS)


def test_ipv4_incremental_deletes_match_reference(populated_v4_table):
    table = populated_v4_table
    live_routes = table.routes()
    for cidr, nexthop, metric, source in V4_RECORDS:
        previous = {
            address: _reference_lookup(live_routes, address) for address in _domain_addresses()
        }
        changed = set(table.delete(cidr, source))
        live_routes = [
            entry
            for entry in live_routes
            if not (entry.cidr == IPNetwork(cidr) and entry.source == source)
        ]
        for address in _domain_addresses():
            expected = _reference_lookup(live_routes, address)
            assert _decision_tuple(table.lookup(address)) == expected
            region_changed = any(address in block for block in changed)
            assert region_changed == (expected != previous[address]), (cidr, source, address)
    assert len(table) == 0
    assert all(table.lookup(address) is None for address in _domain_addresses())


# --- Explicit semantics ------------------------------------------------------

def test_ipv4_explicit_regions(populated_v4_table):
    table = populated_v4_table
    assert table.lookup('198.51.100.0') == ForwardingDecision(
        IPNetwork('198.51.100.0/27'), True, (BLACKHOLE,), 40
    )
    assert table.lookup('198.51.100.31').is_blackhole
    # Tied blackhole wins over the normal next hop.
    assert table.lookup('198.51.100.40').is_blackhole
    # ECMP pair, stable order.
    assert table.lookup('198.51.100.70').nexthops == (
        IPAddress('192.0.2.10'),
        IPAddress('192.0.2.11'),
    )
    # Single /27 route, except at the host.
    assert table.lookup('198.51.100.120').nexthops == (IPAddress('192.0.2.30'),)
    assert table.lookup('198.51.100.126').prefix == IPNetwork('198.51.100.96/27')
    assert table.lookup('198.51.100.100') == ForwardingDecision(
        IPNetwork('198.51.100.100/32'), False, (IPAddress('192.0.2.77'),), 10
    )
    # The rest of the /24 (.128-.255) is governed by the /24 ECMP pair.
    assert table.lookup('198.51.100.200').nexthops == (
        IPAddress('192.0.2.1'),
        IPAddress('192.0.2.2'),
    )
    # Outside the /24 (but inside the /10 aggregate) the /10 route applies.
    assert table.lookup('198.51.101.5').nexthops == (IPAddress('192.0.2.254'),)
    assert table.lookup('198.51.101.5').metric == 90
    # Everything else falls through to the default route.
    assert table.lookup('203.0.113.10').nexthops == (IPAddress('203.0.113.1'),)


def test_delete_one_ecmp_member_keeps_the_other(populated_v4_table):
    table = populated_v4_table
    assert table.delete('198.51.100.64/27', 'rack-a') == (IPNetwork('198.51.100.64/27'),)
    decision = table.lookup('198.51.100.70')
    assert decision.prefix == IPNetwork('198.51.100.64/27')
    assert decision.nexthops == (IPAddress('192.0.2.11'),)
    # The other source's record is still present.
    assert ('198.51.100.64/27', 'rack-b') in [
        (str(entry.cidr), entry.source) for entry in table.routes()
    ]


def test_delete_last_member_falls_back(populated_v4_table):
    table = populated_v4_table
    table.delete('198.51.100.64/27', 'rack-a')
    assert table.delete('198.51.100.64/27', 'rack-b') == (IPNetwork('198.51.100.64/27'),)
    decision = table.lookup('198.51.100.70')
    assert decision.prefix == IPNetwork('198.51.100.0/24')
    assert decision.nexthops == (IPAddress('192.0.2.1'), IPAddress('192.0.2.2'))


def test_delete_blackhole_falls_back_to_ecmp(populated_v4_table):
    table = populated_v4_table
    assert table.delete('198.51.100.0/27', 'rtbh') == (IPNetwork('198.51.100.0/27'),)
    assert table.lookup('198.51.100.5').nexthops == (
        IPAddress('192.0.2.1'),
        IPAddress('192.0.2.2'),
    )


def test_fallback_chain_to_default_then_unreachable(populated_v4_table):
    table = populated_v4_table
    table.delete('198.51.100.0/24', 'static-a')
    table.delete('198.51.100.0/24', 'static-b')
    table.delete('198.51.100.0/24', 'ospf-backup')
    assert table.lookup('198.51.101.5').prefix == IPNetwork('198.0.0.0/10')
    table.delete('198.0.0.0/10', 'aggregate')
    assert table.lookup('198.51.101.5').prefix == IPNetwork('0.0.0.0/0')
    table.delete('0.0.0.0/0', 'default')
    assert table.lookup('198.51.101.5') is None


def test_delete_unknown_raises_keyerror(populated_v4_table):
    table = populated_v4_table
    with pytest.raises(KeyError):
        table.delete('198.51.100.0/24', 'no-such-source')
    with pytest.raises(KeyError):
        table.delete('192.0.2.0/24', 'static-a')
    assert len(table) == len(V4_RECORDS)


def test_delete_shadowed_entry_changes_nothing(populated_v4_table):
    table = populated_v4_table
    assert table.delete('198.51.100.0/24', 'ospf-backup') == ()
    assert table.lookup('198.51.100.200').nexthops == (
        IPAddress('192.0.2.1'),
        IPAddress('192.0.2.2'),
    )


def test_replace_same_source_updates_in_place(populated_v4_table):
    table = populated_v4_table
    changed = table.add('198.51.100.96/27', '192.0.2.99', 40, 'edge')
    # Only the part of the /27 governed by the edge route changes (the /32
    # host route is excluded).
    expected = IPSet([IPNetwork('198.51.100.96/27')]) - IPSet(
        [IPNetwork('198.51.100.100/32')]
    )
    assert IPSet(changed) == expected
    decision = table.lookup('198.51.100.120')
    assert IPAddress('192.0.2.99') in decision.nexthops
    assert IPAddress('192.0.2.30') not in decision.nexthops
    assert len(table) == len(V4_RECORDS)


def test_identical_readd_changes_nothing(populated_v4_table):
    table = populated_v4_table
    assert table.add('198.51.100.64/27', '192.0.2.10', 40, 'rack-a') == ()


def test_minimal_change_region_examples():
    table = RouteTable()
    assert table.add('198.51.100.0/24', '192.0.2.1', 10, 'a') == (
        IPNetwork('198.51.100.0/24'),
    )
    assert table.add('198.51.100.0/27', BLACKHOLE, 5, 'b') == (
        IPNetwork('198.51.100.0/27'),
    )
    assert table.add('198.51.100.96/27', BLACKHOLE, 5, 'c') == (
        IPNetwork('198.51.100.96/27'),
    )
    # ECMP sibling at /24 only changes the regions still governed by /24.
    changed = table.add('198.51.100.0/24', '192.0.2.2', 10, 'd')
    assert IPSet(changed) == IPSet(
        [
            IPNetwork('198.51.100.32/27'),
            IPNetwork('198.51.100.64/27'),
            IPNetwork('198.51.100.128/25'),
        ]
    )
    assert table.delete('198.51.100.0/27', 'b') == (IPNetwork('198.51.100.0/27'),)


# ---------------------------------------------------------------------------

V6_RECORDS = [
    ('::/0', '2001:db8:ffff::1', 100, 'v6-default'),
    ('2001:db8::/32', '2001:db8:1::1', 50, 'v6-prefix'),
    ('2001:db8::/48', '2001:db8:0:1::1', 40, 'v6-subnet'),
    ('2001:db8:1::/48', BLACKHOLE, 40, 'v6-blackhole'),
    ('2001:db8::1/128', '2001:db8:dead::beef', 10, 'v6-host'),
]


@pytest.fixture
def populated_v6_table():
    table = RouteTable()
    for record in V6_RECORDS:
        table.add(*record)
    return table


V6_BOUNDARIES = {
    # Default route region (outside 2001:db8::/32).
    '2001:db9::1': ('::/0', False, ('2001:db8:ffff::1',), 100),
    'ffff::': ('::/0', False, ('2001:db8:ffff::1',), 100),
    # /32 but outside both /48s (check both /48 edges).
    '2001:db8:2::1': ('2001:db8::/32', False, ('2001:db8:1::1',), 50),
    '2001:db8:ff::1': ('2001:db8::/32', False, ('2001:db8:1::1',), 50),
    # /48 subnet boundary addresses.
    '2001:db8::': ('2001:db8::/48', False, ('2001:db8:0:1::1',), 40),
    '2001:db8:0:1:ffff:ffff:ffff:ffff': ('2001:db8::/48', False, ('2001:db8:0:1::1',), 40),
    # Blackholed /48.
    '2001:db8:1::': ('2001:db8:1::/48', True, (BLACKHOLE,), 40),
    '2001:db8:1:0:ffff:ffff:ffff:ffff': ('2001:db8:1::/48', True, (BLACKHOLE,), 40),
    # Host route.
    '2001:db8::1': ('2001:db8::1/128', False, ('2001:db8:dead::beef',), 10),
}


def test_ipv6_boundary_addresses(populated_v6_table):
    table = populated_v6_table
    for address, (prefix, is_blackhole, nexthop_strs, metric) in V6_BOUNDARIES.items():
        decision = table.lookup(address)
        assert decision.prefix == IPNetwork(prefix), address
        assert decision.is_blackhole is is_blackhole, address
        assert decision.metric == metric, address
        if not is_blackhole:
            assert decision.nexthops == tuple(IPAddress(h) for h in nexthop_strs)
        else:
            assert decision.nexthops == (BLACKHOLE,)
        assert _decision_tuple(decision) == _reference_lookup(table.routes(), address)


def test_ipv6_default_and_blackhole_fallback(populated_v6_table):
    table = populated_v6_table
    assert table.delete('2001:db8:1::/48', 'v6-blackhole') == (IPNetwork('2001:db8:1::/48'),)
    assert table.lookup('2001:db8:1::').prefix == IPNetwork('2001:db8::/32')
    table.delete('2001:db8::/32', 'v6-prefix')
    table.delete('2001:db8::/48', 'v6-subnet')
    table.delete('2001:db8::1/128', 'v6-host')
    assert table.lookup('2001:db8::1').prefix == IPNetwork('::/0')
    assert table.delete('::/0', 'v6-default') == (IPNetwork('::/0'),)
    assert table.lookup('2001:db8::1') is None


def test_ipv6_minimal_change_region(populated_v6_table):
    table = populated_v6_table
    # Adding an equal-metric ECMP next hop into the /32 only affects the part
    # of the /32 not covered by the two /48s and the /128.
    changed = table.add('2001:db8::/32', '2001:db8:1::2', 50, 'v6-prefix-b')
    governed = IPSet([IPNetwork('2001:db8::/32')]) - IPSet(
        [
            IPNetwork('2001:db8::/48'),
            IPNetwork('2001:db8:1::/48'),
            IPNetwork('2001:db8::1/128'),
        ]
    )
    assert IPSet(changed) == governed


# ---------------------------------------------------------------------------
# Family isolation, validation and container helpers.
# ---------------------------------------------------------------------------

def test_ipv4_and_ipv6_tables_are_independent(populated_v4_table, populated_v6_table):
    v4 = populated_v4_table
    v6 = populated_v6_table
    assert len(v4.routes(family=4)) == len(V4_RECORDS)
    assert len(v4.routes(family=6)) == 0
    assert len(v6.routes(family=6)) == len(V6_RECORDS)
    assert len(v6.routes(family=4)) == 0
    assert v4.lookup('2001:db8::1') is None
    assert v6.lookup('198.51.100.1') is None


def test_nexthop_family_must_match_prefix():
    table = RouteTable()
    with pytest.raises(ValueError):
        table.add('10.0.0.0/8', '2001:db8::1', 10, 'bad')
    with pytest.raises(ValueError):
        table.add('2001:db8::/32', '10.0.0.1', 10, 'bad')
    # BLACKHOLE is family agnostic.
    assert table.add('2001:db8::/32', BLACKHOLE, 10, 'bh') == (
        IPNetwork('2001:db8::/32'),
    )


def test_invalid_metric_and_source():
    table = RouteTable()
    for bad_metric in (-1, 1.5, '10', True):
        with pytest.raises((TypeError, ValueError)):
            table.add('10.0.0.0/8', '10.0.0.1', bad_metric, 's')
    with pytest.raises(TypeError):
        table.add('10.0.0.0/8', '10.0.0.1', 10, ['not', 'hashable'])
    assert len(table) == 0


def test_host_bits_are_normalised():
    table = RouteTable()
    table.add('10.0.0.5/24', '10.1.0.1', 10, 's')
    assert '10.0.0.0/24' in table
    assert '10.0.0.5/24' in table
    assert table.lookup('10.0.0.250').nexthops == (IPAddress('10.1.0.1'),)
    table.delete('10.0.0.5/24', 's')
    assert '10.0.0.0/24' not in table


def test_duplicate_next_hops_collapse_into_one_ecmp_member():
    table = RouteTable()
    table.add('10.0.0.0/8', '10.9.9.9', 10, 'a')
    table.add('10.0.0.0/8', '10.9.9.9', 10, 'b')
    assert table.lookup('10.0.0.1').nexthops == (IPAddress('10.9.9.9'),)


# ---------------------------------------------------------------------------
# Lookup never scans the table: walk depth is bounded by prefix length.
# ---------------------------------------------------------------------------

def test_lookup_walks_at_math_max_prefixlen_bits(monkeypatch):
    from netaddr.contrib.route_table import _FamilyTable

    table = RouteTable()
    for index in range(2000):
        table.add(f'10.{(index // 256) % 256}.{index % 256}.0/24', '10.0.0.1', 10, index)

    depths = []
    original = _FamilyTable.lookup_node

    def counting_lookup(self, address):
        node = self.root
        touched = 0
        for depth in range(self.max_prefixlen):
            bit = (address >> (self.max_prefixlen - 1 - depth)) & 1
            node = node.one if bit else node.zero
            touched += 1
            if node is None:
                break
        depths.append(touched)
        return original(self, address)

    monkeypatch.setattr(_FamilyTable, 'lookup_node', counting_lookup)
    assert table.lookup('10.5.5.5') is not None
    table.lookup('8.8.8.8')
    assert max(depths) <= 32


def test_lookup_performance_is_independent_of_table_size():
    small = RouteTable()
    small.add('0.0.0.0/0', '10.0.0.254', 100, 'default')
    for index in range(16):
        small.add(f'10.0.{index}.0/24', '10.0.0.1', 10, index)

    large = RouteTable()
    large.add('0.0.0.0/0', '10.0.0.254', 100, 'default')
    for index in range(4000):
        large.add(f'10.{(index // 256) % 256}.{index % 256}.0/24', '10.0.0.1', 10, index)

    query = '198.51.100.9'
    rounds = 3000

    def timed(candidate):
        start = time.perf_counter()
        for _ in range(rounds):
            candidate.lookup(query)
        return time.perf_counter() - start

    large_time = timed(large)
    small_time = timed(small)
    # A 250x larger table must not make lookups dramatically slower.
    assert large_time < small_time * 5 + 0.2

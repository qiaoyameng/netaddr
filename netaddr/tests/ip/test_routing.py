import pytest

from netaddr import IPAddress, IPNetwork
from netaddr.core import AddrFormatError
from netaddr.ip.routing import RoutingTable


def reference_forwarding(routes, ip):
    """Brute-force reference model scanning every route linearly.

    routes is a list of (prefix, nexthop, metric, source) tuples where a
    nexthop of None denotes a blackhole.
    """
    matches = []
    for prefix, nexthop, metric, _source in routes:
        network = IPNetwork(prefix)
        if ip in network:
            matches.append((network.prefixlen, metric, nexthop))
    if not matches:
        return None
    best_len = max(match[0] for match in matches)
    best_metric = min(match[1] for match in matches if match[0] == best_len)
    winners = [
        match[2]
        for match in matches
        if match[0] == best_len and match[1] == best_metric
    ]
    nexthops = frozenset(nh for nh in winners if nh is not None)
    if not nexthops:
        return 'blackhole'
    return nexthops


def actual_forwarding(table, ip):
    result = table.lookup(ip)
    if result is None:
        return None
    if result.is_blackhole:
        return 'blackhole'
    return frozenset(str(nexthop) for nexthop in result.nexthops)


def build_table(routes):
    table = RoutingTable()
    for prefix, nexthop, metric, source in routes:
        table.add(prefix, nexthop, metric=metric, source=source)
    return table


V4_ROUTES = [
    ('0.0.0.0/0', '192.0.2.1', 100, 'static'),
    ('10.0.0.0/24', '192.0.2.2', 10, 'ospf'),
    ('10.0.0.0/26', '192.0.2.3', 10, 'ospf'),
    ('10.0.0.0/26', '192.0.2.4', 10, 'bgp'),
    ('10.0.0.0/26', '192.0.2.5', 20, 'rip'),
    ('10.0.0.16/28', None, 5, 'static'),
]


def check_domain(table, routes, domain):
    for value in range(domain.first, domain.last + 1):
        ip = IPAddress(value)
        expected = reference_forwarding(routes, ip)
        assert actual_forwarding(table, ip) == expected, ip


def test_ipv4_forwarding_matches_reference_for_every_address():
    table = build_table(V4_ROUTES)
    check_domain(table, V4_ROUTES, IPNetwork('10.0.0.0/24'))
    # Addresses outside the detailed domain fall back to the default route.
    for ip in ('10.0.1.7', '172.16.0.1', '203.0.113.9'):
        assert actual_forwarding(table, IPAddress(ip)) == {'192.0.2.1'}


def test_ipv4_ecmp_and_blackhole_results():
    table = build_table(V4_ROUTES)

    result = table.lookup('10.0.0.40')
    assert result.prefix == IPNetwork('10.0.0.0/26')
    assert result.metric == 10
    assert result.nexthops == {IPAddress('192.0.2.3'), IPAddress('192.0.2.4')}
    assert not result.is_blackhole

    result = table.lookup('10.0.0.20')
    assert result.prefix == IPNetwork('10.0.0.16/28')
    assert result.is_blackhole
    assert result.nexthops is None


def test_ipv4_delete_source_and_fallback():
    routes = list(V4_ROUTES)
    table = build_table(routes)
    domain = IPNetwork('10.0.0.0/24')

    # Withdrawing one ECMP contributor leaves the other source intact.
    table.remove('10.0.0.0/26', source='bgp')
    routes = [route for route in routes if route[3] != 'bgp']
    check_domain(table, routes, domain)

    # Withdrawing the best metric source falls back to the worse metric.
    table.remove('10.0.0.0/26', source='ospf')
    routes = [route for route in routes if not (
        route[0] == '10.0.0.0/26' and route[3] == 'ospf'
    )]
    check_domain(table, routes, domain)
    assert actual_forwarding(table, IPAddress('10.0.0.40')) == {'192.0.2.5'}

    # Withdrawing the blackhole exposes the less specific prefix again.
    table.remove('10.0.0.16/28', source='static')
    routes = [route for route in routes if route[0] != '10.0.0.16/28']
    check_domain(table, routes, domain)
    assert actual_forwarding(table, IPAddress('10.0.0.20')) == {'192.0.2.5'}


def test_ipv4_changed_regions_are_minimal():
    table = RoutingTable()
    assert table.add('0.0.0.0/0', '192.0.2.1', metric=100) == [
        IPNetwork('0.0.0.0/0'),
    ]
    assert table.add('10.0.0.0/24', '192.0.2.2', metric=10, source='ospf') == [
        IPNetwork('10.0.0.0/24'),
    ]
    assert table.add('10.0.0.0/26', '192.0.2.3', metric=10, source='ospf') == [
        IPNetwork('10.0.0.0/26'),
    ]
    assert table.add('10.0.0.16/28', None, metric=5) == [
        IPNetwork('10.0.0.16/28'),
    ]
    # A shadowed entry changes no forwarding result.
    assert table.add('10.0.0.0/26', '192.0.2.5', metric=20, source='rip') == []
    # Re-adding an identical entry is a no-op.
    assert table.add('10.0.0.0/26', '192.0.2.3', metric=10, source='ospf') == []

    # A new ECMP peer changes the /26 except the blackholed /28 inside it.
    assert table.add('10.0.0.0/26', '192.0.2.4', metric=10, source='bgp') == [
        IPNetwork('10.0.0.0/28'),
        IPNetwork('10.0.0.32/27'),
    ]
    # Withdrawing that peer restores the previous outcome over the same area.
    assert table.remove('10.0.0.0/26', source='bgp') == [
        IPNetwork('10.0.0.0/28'),
        IPNetwork('10.0.0.32/27'),
    ]
    # Withdrawing the blackhole only affects its own /28.
    assert table.remove('10.0.0.16/28', source='static') == [
        IPNetwork('10.0.0.16/28'),
    ]
    # Removing the shadowed entry changes nothing.
    assert table.remove('10.0.0.0/26', source='rip') == []


def test_remove_only_revokes_the_given_source():
    table = RoutingTable()
    table.add('10.0.0.0/24', '192.0.2.1', metric=10, source='ospf')
    table.add('10.0.0.0/24', '192.0.2.2', metric=10, source='bgp')

    assert table.remove('10.0.0.0/24', source='bgp') == [IPNetwork('10.0.0.0/24')]
    assert table.lookup('10.0.0.7').nexthops == {IPAddress('192.0.2.1')}

    with pytest.raises(KeyError):
        table.remove('10.0.0.0/24', source='bgp')
    with pytest.raises(KeyError):
        table.remove('10.1.0.0/24', source='ospf')


def test_remove_specific_nexthop_only():
    table = RoutingTable()
    table.add('10.0.0.0/24', '192.0.2.1', metric=10, source='ospf')
    table.add('10.0.0.0/24', '192.0.2.2', metric=10, source='ospf')

    table.remove('10.0.0.0/24', source='ospf', nexthop='192.0.2.1')
    assert table.lookup('10.0.0.7').nexthops == {IPAddress('192.0.2.2')}
    assert len(table) == 1


def test_nexthop_family_must_match_prefix():
    table = RoutingTable()
    with pytest.raises(AddrFormatError):
        table.add('10.0.0.0/24', '2001:db8::1')
    with pytest.raises(AddrFormatError):
        table.add('2001:db8::/32', '192.0.2.1')


def test_lookup_without_any_route():
    table = RoutingTable()
    assert table.lookup('10.0.0.1') is None
    assert '10.0.0.1' not in table
    assert len(table) == 0


def test_address_families_are_independent():
    table = RoutingTable()
    table.add('0.0.0.0/0', '192.0.2.1')
    assert table.lookup('::1') is None
    table.add('::/0', '2001:db8::ffff')
    assert table.lookup('::1').nexthops == {IPAddress('2001:db8::ffff')}
    assert table.lookup('10.9.8.7').nexthops == {IPAddress('192.0.2.1')}
    assert len(table) == 2


def test_ipv6_boundary_lookups():
    table = RoutingTable()
    table.add('::/0', '2001:db8:ffff::1', metric=100)
    table.add('2001:db8::/32', '2001:db8::1', metric=10, source='bgp')
    table.add('2001:db8:1::/48', None, metric=10, source='static')

    expected = {
        '::1': {'2001:db8:ffff::1'},
        # Just below 2001:db8::/32.
        '2001:db7:ffff:ffff:ffff:ffff:ffff:ffff': {'2001:db8:ffff::1'},
        # First address of 2001:db8::/32.
        '2001:db8::': {'2001:db8::1'},
        # Inside the /32 but just below the blackholed /48.
        '2001:db8:0:ffff:ffff:ffff:ffff:ffff': {'2001:db8::1'},
        # First and last address of the blackholed /48.
        '2001:db8:1::': 'blackhole',
        '2001:db8:1:ffff:ffff:ffff:ffff:ffff': 'blackhole',
        # Just above the blackholed /48.
        '2001:db8:2::': {'2001:db8::1'},
        # Last address of 2001:db8::/32.
        '2001:db8:ffff:ffff:ffff:ffff:ffff:ffff': {'2001:db8::1'},
        # Just above 2001:db8::/32.
        '2001:db9::': {'2001:db8:ffff::1'},
    }
    for ip, outcome in expected.items():
        assert actual_forwarding(table, IPAddress(ip)) == outcome, ip


def test_ipv6_changed_regions():
    table = RoutingTable()
    assert table.add('::/0', '2001:db8:ffff::1', metric=100) == [
        IPNetwork('::/0'),
    ]
    assert table.add('2001:db8::/32', '2001:db8::1', metric=10) == [
        IPNetwork('2001:db8::/32'),
    ]
    assert table.add('2001:db8:1::/48', None, metric=10) == [
        IPNetwork('2001:db8:1::/48'),
    ]
    assert table.remove('2001:db8:1::/48', source='static') == [
        IPNetwork('2001:db8:1::/48'),
    ]

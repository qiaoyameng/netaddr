import pickle

import pytest

from netaddr import (
    ANY_ZONE,
    AddrFormatError,
    IPAddress,
    IPNetwork,
    ScopedIPSet,
    ScopedIPv6Address,
    ScopedIPv6Network,
    Zone,
)


def test_same_link_local_address_on_two_interfaces_is_not_equal():
    eth0 = ScopedIPv6Address('fe80::1%eth0')
    eth1 = ScopedIPv6Address('fe80::1%eth1')

    assert eth0 != eth1
    assert hash(eth0) != hash(eth1)
    assert eth0 == ScopedIPv6Address('fe80::1%eth0')
    assert hash(eth0) == hash(ScopedIPv6Address('fe80::1%eth0'))

    #   Both differ from the unscoped address, and none of them is equal
    #   to a plain IPAddress.
    assert eth0 != ScopedIPv6Address('fe80::1')
    assert eth0 != IPAddress('fe80::1')
    assert IPAddress('fe80::1') != eth0


def test_existing_ipaddress_equality_rules_unchanged():
    assert IPAddress('fe80::1') == IPAddress('fe80::1')
    assert IPAddress('fe80::1') == IPAddress('FE80::1')
    assert IPAddress('fe80::1') != IPAddress('fe80::2')


def test_zone_compared_by_caller_supplied_identifier_only():
    #   Identifiers are opaque strings; no system interface lookup
    #   happens, so a nonexistent interface name is a perfectly valid
    #   zone and compares by string identity.
    assert Zone('no_such_interface_zzz') == Zone('no_such_interface_zzz')
    assert Zone('eth0') != Zone('eth1')
    assert Zone('eth0') != 'eth0'
    assert Zone('Eth0') != Zone('eth0')

    with pytest.raises(ValueError):
        Zone('')
    with pytest.raises(ValueError):
        Zone('*')
    with pytest.raises(ValueError):
        Zone('bad%name')
    with pytest.raises(ValueError):
        Zone('bad/name')
    with pytest.raises(TypeError):
        Zone(3)


def test_zone_eligibility():
    #   Link-local unicast and interface/link-local multicast may carry
    #   a zone.
    assert ScopedIPv6Address('fe80::1%eth0').is_scoped
    assert ScopedIPv6Address('ff02::1%eth0').is_scoped
    assert ScopedIPv6Address('ff01::1%eth0').is_scoped
    assert ScopedIPv6Network('fe80::/10%*').is_scoped
    assert ScopedIPv6Network('ff02::/16%eth0').is_scoped

    #   Global unicast and wider-scope multicast may not.
    with pytest.raises(AddrFormatError):
        ScopedIPv6Address('2001:db8::1%eth0')
    with pytest.raises(AddrFormatError):
        ScopedIPv6Address('ff05::1%eth0')
    with pytest.raises(AddrFormatError):
        ScopedIPv6Network('2001:db8::/64%eth0')
    with pytest.raises(AddrFormatError):
        ScopedIPv6Network('ff00::/8%eth0')


def test_default_zone_does_not_match_all_interfaces():
    unscoped = ScopedIPv6Network('fe80::/64')

    assert not unscoped.is_scoped
    assert ScopedIPv6Address('fe80::1%eth0') not in unscoped
    assert ScopedIPv6Address('fe80::1') in unscoped
    assert IPAddress('fe80::1') in unscoped

    #   Only the explicit wildcard matches every interface.
    wildcard = ScopedIPv6Network('fe80::/64%*')
    assert ScopedIPv6Address('fe80::1%eth0') in wildcard
    assert ScopedIPv6Address('fe80::1%eth1') in wildcard
    assert ScopedIPv6Address('fe80::1') not in wildcard
    assert IPAddress('fe80::1') not in wildcard


def test_wildcard_minus_single_interface_remainder():
    wildcard = ScopedIPv6Network('fe80::/64%*')
    eth0 = ScopedIPv6Network('fe80::/64%eth0')

    rest = wildcard - eth0

    #   The remainder is represented as the wildcard range with eth0
    #   excluded.
    assert list(rest) == [ScopedIPv6Network('fe80::/64%*!eth0')]
    assert str(list(rest)[0]) == 'fe80::/64%*!eth0'

    assert ScopedIPv6Address('fe80::1%eth0') not in rest
    assert ScopedIPv6Address('fe80::1%eth1') in rest

    #   Subtracting a second interface extends the exclusion list.
    rest2 = rest - ScopedIPv6Network('fe80::/64%eth1')
    assert list(rest2) == [ScopedIPv6Network('fe80::/64%*!eth0!eth1')]
    assert ScopedIPv6Address('fe80::1%eth1') not in rest2

    #   Adding a carved-out interface back restores the wildcard.
    assert rest | eth0 == ScopedIPSet([wildcard])
    assert (rest | eth0).issuperset(wildcard)


def test_algebra_with_two_link_addresses_and_a_global_network():
    eth0 = ScopedIPv6Network('fe80::1%eth0')
    eth1 = ScopedIPv6Network('fe80::1%eth1')
    wildcard = ScopedIPv6Network('fe80::/64%*')
    global_net = ScopedIPv6Network('2001:db8::/64')

    #   The two same-valued link addresses stay distinct in a set.
    both = eth0 | eth1
    assert len(both) == 2
    assert eth0 & eth1 == ScopedIPSet()

    #   Wildcard range intersected with one interface yields that
    #   interface's range.
    assert wildcard & eth0 == ScopedIPSet([eth0])

    #   The global network is disjoint from everything link-local.
    assert wildcard & global_net == ScopedIPSet()
    assert global_net - wildcard == ScopedIPSet([global_net])
    union = wildcard | global_net
    assert sorted(map(str, union)) == ['2001:db8::/64', 'fe80::/64%*']
    assert ScopedIPv6Address('2001:db8::1') in union
    assert ScopedIPv6Address('fe80::1%eth0') in union

    #   Unscoped and scoped spaces never mix implicitly.
    assert ScopedIPv6Network('fe80::/64') & wildcard == ScopedIPSet()


def test_network_difference_within_one_interface():
    net = ScopedIPv6Network('fe80::/64%eth0')
    sub = ScopedIPv6Network('fe80::/65%eth0')

    diff = net - sub
    assert list(diff) == [ScopedIPv6Network('fe80::8000:0:0:0/65%eth0')]

    #   Subtracting a different interface leaves the range untouched.
    assert net - ScopedIPv6Network('fe80::/64%eth1') == ScopedIPSet([net])

    #   Subtracting the wildcard removes the range entirely.
    assert net - ScopedIPv6Network('fe80::/64%*') == ScopedIPSet()


def test_membership_and_containment():
    wildcard = ScopedIPv6Network('fe80::/64%*')
    excluded = ScopedIPv6Network('fe80::/64%*!eth0')

    assert ScopedIPv6Network('fe80::/64%eth0') in wildcard
    assert ScopedIPv6Network('fe80::/64%eth0') not in excluded
    assert ScopedIPv6Network('fe80::/64%eth1') in excluded
    assert ScopedIPv6Network('fe80::/64%*!eth0') in wildcard
    assert wildcard not in excluded

    assert 'fe80::1%eth0' in ScopedIPSet([wildcard])
    assert 'fe80::1%eth0' not in ScopedIPSet([excluded])


def test_text_round_trip_matches_identity():
    samples = [
        'fe80::1',
        'fe80::1%eth0',
        'fe80::1%*',
        'ff02::1%eth0',
    ]
    for text in samples:
        addr = ScopedIPv6Address(text)
        assert ScopedIPv6Address(str(addr)) == addr
        assert str(addr) == text

    networks = [
        'fe80::/64',
        'fe80::/64%eth0',
        'fe80::/64%*',
        'fe80::/64%*!eth0',
        'fe80::/64%*!eth0!eth1',
        '2001:db8::/64',
    ]
    for text in networks:
        net = ScopedIPv6Network(text)
        assert ScopedIPv6Network(str(net)) == net
        assert str(net) == text
        assert eval(repr(net)) == net


def test_hash_and_ordering_consistent_with_identity():
    addrs = [
        ScopedIPv6Address('fe80::1'),
        ScopedIPv6Address('fe80::1%*'),
        ScopedIPv6Address('fe80::1%eth0'),
        ScopedIPv6Address('fe80::1%eth1'),
        ScopedIPv6Address('fe80::2%eth0'),
    ]
    #   Unscoped sorts before wildcard, wildcard before concrete zones;
    #   address value dominates.
    assert sorted(addrs) == [
        ScopedIPv6Address('fe80::1'),
        ScopedIPv6Address('fe80::1%*'),
        ScopedIPv6Address('fe80::1%eth0'),
        ScopedIPv6Address('fe80::1%eth1'),
        ScopedIPv6Address('fe80::2%eth0'),
    ]
    #   Equal objects hash equally and can be used as dict keys.
    mapping = {ScopedIPv6Address('fe80::1%eth0'): 'x'}
    assert mapping[ScopedIPv6Address('fe80::1%eth0')] == 'x'
    assert len({a for a in addrs} | {ScopedIPv6Address('fe80::1%eth0')}) == 5

    nets = [
        ScopedIPv6Network('fe80::/64%eth1'),
        ScopedIPv6Network('fe80::/64'),
        ScopedIPv6Network('fe80::/64%*'),
        ScopedIPv6Network('fe80::/64%eth0'),
    ]
    assert [str(n) for n in sorted(nets)] == [
        'fe80::/64',
        'fe80::/64%*',
        'fe80::/64%eth0',
        'fe80::/64%eth1',
    ]


def test_set_operations_and_normalization():
    a = ScopedIPv6Network('fe80::/65%eth0')
    b = ScopedIPv6Network('fe80::8000:0:0:0/65%eth0')

    #   Adjacent ranges on the same zone merge.
    assert a | b == ScopedIPSet([ScopedIPv6Network('fe80::/64%eth0')])

    #   Same ranges on different zones do not merge.
    assert len(a | ScopedIPv6Network('fe80::/65%eth1')) == 2

    union = ScopedIPSet(['fe80::/64%eth0', '2001:db8::/64'])
    assert union.isdisjoint(ScopedIPv6Network('fe80::/64%eth1'))
    assert not union.isdisjoint(ScopedIPv6Network('fe80::/64%*'))

    #   Disjoint ranges: symmetric difference is the union.
    assert a ^ b == (a | b)
    assert (a ^ ScopedIPv6Network('fe80::/65%eth1')) == (a | ScopedIPv6Network('fe80::/65%eth1'))
    #   Identical ranges cancel out.
    assert a ^ a == ScopedIPSet()


def test_construction_and_copy_semantics():
    assert ScopedIPv6Address(ScopedIPv6Address('fe80::1%eth0')) == ScopedIPv6Address('fe80::1%eth0')
    assert ScopedIPv6Address(IPAddress('fe80::1'), 'eth0') == ScopedIPv6Address('fe80::1%eth0')
    assert ScopedIPv6Address('fe80::1', ANY_ZONE) == ScopedIPv6Address('fe80::1%*')

    net = ScopedIPv6Network(IPNetwork('fe80::/64'), Zone('eth0'))
    assert net == ScopedIPv6Network('fe80::/64%eth0')
    assert ScopedIPv6Network(net) == net
    assert ScopedIPv6Network(ScopedIPv6Address('fe80::1%eth0')) == ScopedIPv6Network('fe80::1%eth0')

    #   Excluded zones require the wildcard zone.
    with pytest.raises(ValueError):
        ScopedIPv6Network('fe80::/64', 'eth0', excluded_zones=['eth1'])
    with pytest.raises(AddrFormatError):
        ScopedIPv6Network('fe80::/64%eth0!eth1')

    #   IPv4 is rejected.
    with pytest.raises(AddrFormatError):
        ScopedIPv6Address('192.0.2.1')
    with pytest.raises(AddrFormatError):
        ScopedIPv6Network('192.0.2.0/24')


def test_pickle_round_trip():
    for obj in [
        Zone('eth0'),
        ANY_ZONE,
        ScopedIPv6Address('fe80::1%eth0'),
        ScopedIPv6Network('fe80::/64%*!eth0'),
    ]:
        assert pickle.loads(pickle.dumps(obj)) == obj
    assert pickle.loads(pickle.dumps(ANY_ZONE)) is ANY_ZONE

import pickle

import pytest

from netaddr import (
    ANY_ZONE,
    AddrFormatError,
    IPAddress,
    ScopedIPv6Address,
    ScopedIPv6Network,
    ScopedIPv6Set,
    ZoneFilter,
)


def test_same_link_local_address_on_different_interfaces_is_distinct():
    eth0 = ScopedIPv6Address('fe80::1%eth0')
    eth1 = ScopedIPv6Address('fe80::1%eth1')

    assert eth0 != eth1
    assert hash(eth0) != hash(eth1)
    assert eth0 == ScopedIPv6Address('fe80::1%eth0')
    assert hash(eth0) == hash(ScopedIPv6Address('fe80::1%eth0'))

    #   Same value, but a zoneless address is yet another identity.
    assert eth0 != ScopedIPv6Address('fe80::1')
    assert eth1 != ScopedIPv6Address('fe80::1')


def test_scoped_address_does_not_change_ipaddress_equality():
    plain = IPAddress('fe80::1')

    assert plain != ScopedIPv6Address('fe80::1%eth0')
    assert ScopedIPv6Address('fe80::1%eth0') != plain
    #   Even a zoneless scoped address is a different type of object.
    assert plain != ScopedIPv6Address('fe80::1')
    assert ScopedIPv6Address('fe80::1') != plain
    #   Existing scope-less rules are untouched.
    assert IPAddress('fe80::1') == IPAddress('fe80::1')


def test_zone_is_caller_provided_identifier_without_system_lookup():
    #   A zone that cannot exist on any system is accepted verbatim; no
    #   interface lookup (e.g. socket.if_nametoindex) is ever attempted.
    addr = ScopedIPv6Address('fe80::1%no-such-interface-0')
    assert addr.zone == 'no-such-interface-0'

    #   Numeric interface indexes are normalized to their string form.
    assert ScopedIPv6Address('fe80::1', zone=3).zone == '3'
    assert ScopedIPv6Address('fe80::1', zone=3) == ScopedIPv6Address('fe80::1%3')

    with pytest.raises(ValueError):
        ScopedIPv6Address('fe80::1', zone=-1)
    with pytest.raises(AddrFormatError):
        ScopedIPv6Address('fe80::1', zone='bad zone!')


def test_zones_only_allowed_on_link_local_and_multicast():
    assert ScopedIPv6Address('fe80::1%eth0').is_link_local()
    assert ScopedIPv6Address('ff02::1%eth0').is_multicast()
    assert ScopedIPv6Network('fe80::/10%eth0').zone == 'eth0'
    assert ScopedIPv6Network('ff00::/8%eth0').zone == 'eth0'

    #   Global unicast and loopback addresses must reject a zone.
    with pytest.raises(AddrFormatError):
        ScopedIPv6Address('2001:db8::1%eth0')
    with pytest.raises(AddrFormatError):
        ScopedIPv6Address('::1%eth0')
    with pytest.raises(AddrFormatError):
        ScopedIPv6Network('2001:db8::/32%eth0')
    #   A range only partially overlapping the link-local block too.
    with pytest.raises(AddrFormatError):
        ScopedIPv6Network('fe00::/9%eth0')

    #   Zoneless global addresses are fine.
    assert ScopedIPv6Address('2001:db8::1').zone is None


def test_wildcard_zone_is_explicit_only():
    wildcard = ScopedIPv6Address('fe80::1', zone=ANY_ZONE)
    assert wildcard.zone is ANY_ZONE
    assert str(wildcard) == 'fe80::1%*'
    assert ScopedIPv6Address('fe80::1%*').zone is ANY_ZONE

    #   The wildcard is a distinct identity, not a default.
    assert wildcard != ScopedIPv6Address('fe80::1')
    assert wildcard != ScopedIPv6Address('fe80::1%eth0')

    #   A zoneless element never matches all interfaces.
    zoneless_set = ScopedIPv6Set(['fe80::1'])
    assert ScopedIPv6Address('fe80::1') in zoneless_set
    assert ScopedIPv6Address('fe80::1%eth0') not in zoneless_set
    assert ScopedIPv6Address('fe80::1%*') not in zoneless_set


def test_address_text_round_trip():
    for text in ('fe80::1', 'fe80::1%eth0', 'fe80::1%*', 'ff02::1%eth1', '2001:db8::1'):
        addr = ScopedIPv6Address(text)
        assert ScopedIPv6Address(str(addr)) == addr
        assert eval(repr(addr), {'ScopedIPv6Address': ScopedIPv6Address}) == addr


def test_network_text_round_trip():
    for text in ('fe80::/10', 'fe80::/10%eth0', 'fe80::/64%*', 'fe80::1%eth0'):
        network = ScopedIPv6Network(text)
        assert ScopedIPv6Network(str(network)) == network
        assert str(network) == text


def test_address_sorting_matches_identity():
    zoneless = ScopedIPv6Address('fe80::1')
    eth0 = ScopedIPv6Address('fe80::1%eth0')
    eth1 = ScopedIPv6Address('fe80::1%eth1')
    wildcard = ScopedIPv6Address('fe80::1%*')
    lower = ScopedIPv6Address('fe80::%eth9')

    #   Order: address value, then no-zone < named zones < wildcard.
    assert sorted([wildcard, eth1, zoneless, eth0, lower]) == [
        lower, zoneless, eth0, eth1, wildcard,
    ]

    with pytest.raises(TypeError):
        eth0 < IPAddress('fe80::1')


def test_address_pickle_round_trip():
    for addr in (
        ScopedIPv6Address('fe80::1'),
        ScopedIPv6Address('fe80::1%eth0'),
        ScopedIPv6Address('fe80::1%*'),
    ):
        assert pickle.loads(pickle.dumps(addr)) == addr
    assert pickle.loads(pickle.dumps(ScopedIPv6Address('fe80::1%*'))).zone is ANY_ZONE


def test_zone_filter_algebra_is_closed():
    only_eth0 = ZoneFilter.only('eth0')
    any_zone = ZoneFilter.all_except()

    assert any_zone.is_wildcard
    assert not ZoneFilter.only().is_wildcard
    assert ZoneFilter.only().is_empty
    assert ZoneFilter.only(None).is_unscoped

    assert only_eth0 & ZoneFilter.all_except('eth1') == only_eth0
    assert only_eth0 & ZoneFilter.all_except('eth0') == ZoneFilter.only()
    assert only_eth0 | ZoneFilter.all_except('eth0') == any_zone
    assert ~only_eth0 == ZoneFilter.all_except('eth0')
    assert any_zone - only_eth0 == ZoneFilter.all_except('eth0')
    assert ZoneFilter.all_except('eth0') - ZoneFilter.all_except('eth0', 'eth1') == ZoneFilter.only(
        'eth1'
    )

    assert 'eth0' in only_eth0
    assert 'eth1' not in only_eth0
    assert 'anything' in ZoneFilter.all_except('eth0')
    assert 'eth0' not in ZoneFilter.all_except('eth0')
    #   The no-zone identity is just another identity in filters.
    assert None in ZoneFilter.all_except()
    assert None not in ZoneFilter.only('eth0')

    assert str(ZoneFilter.all_except()) == '*'
    assert str(ZoneFilter.all_except('eth0')) == '*!eth0'
    assert str(ZoneFilter.only('eth0')) == 'eth0'


def test_set_union_of_same_address_on_two_interfaces():
    combined = ScopedIPv6Set(['fe80::1%eth0']) | ScopedIPv6Set(['fe80::1%eth1'])

    assert combined == ScopedIPv6Set(['fe80::1%eth0', 'fe80::1%eth1'])
    assert combined.to_list() == ['fe80::1%eth0', 'fe80::1%eth1']
    assert ScopedIPv6Address('fe80::1%eth0') in combined
    assert ScopedIPv6Address('fe80::1%eth1') in combined
    assert ScopedIPv6Address('fe80::1%eth2') not in combined
    assert ScopedIPv6Address('fe80::1') not in combined


def test_set_intersection_of_wildcard_range_and_single_interface():
    wildcard = ScopedIPv6Set(['fe80::/10%*'])
    single = ScopedIPv6Set(['fe80::1%eth0'])

    assert wildcard & single == single
    assert wildcard & ScopedIPv6Set(['fe80::/64%eth0']) == ScopedIPv6Set(['fe80::/64%eth0'])
    #   Disjoint zones do not intersect.
    assert (single & ScopedIPv6Set(['fe80::/10%eth1'])).is_empty


def test_wildcard_set_minus_single_interface():
    wildcard = ScopedIPv6Set(['fe80::/10%*'])
    single = ScopedIPv6Set(['fe80::1%eth0'])

    remaining = wildcard - single

    #   The removed address is gone, everything else survives.
    assert ScopedIPv6Address('fe80::1%eth0') not in remaining
    assert ScopedIPv6Address('fe80::1%eth1') in remaining
    assert ScopedIPv6Address('fe80::2%eth0') in remaining
    assert ScopedIPv6Address('fe80::1%*') not in remaining

    #   The remainder is represented explicitly: the whole link-local
    #   block on "all zones except eth0", plus the rest of the block on
    #   eth0 itself.
    assert 'fe80::/10%*!eth0' in remaining.to_list()
    assert 'fe80::1%eth0' not in remaining.to_list()
    assert 'fe80::%eth0' in remaining.to_list()

    #   Text round trip and canonical equality.
    assert ScopedIPv6Set(remaining.to_list()) == remaining
    assert eval(repr(remaining), {'ScopedIPv6Set': ScopedIPv6Set}) == remaining

    #   Adding the removed address back restores the wildcard set exactly.
    assert remaining | single == wildcard
    #   Removing it twice changes nothing further.
    assert remaining - single == remaining


def test_set_algebra_with_global_ipv6_address():
    global_addr = ScopedIPv6Address('2001:db8::1')
    wildcard = ScopedIPv6Set(['fe80::/10%*'])
    global_set = ScopedIPv6Set([global_addr])

    #   A global address is disjoint from any link-local range.
    assert (wildcard & global_set).is_empty
    assert global_set - wildcard == global_set
    assert wildcard - global_set == wildcard

    combined = wildcard | global_set
    assert global_addr in combined
    assert ScopedIPv6Address('fe80::1%eth0') in combined
    assert combined != wildcard

    #   Zoneless link-local and global addresses coexist by zone identity.
    mixed = ScopedIPv6Set(['fe80::1', '2001:db8::1'])
    assert ScopedIPv6Address('fe80::1') in mixed
    assert ScopedIPv6Address('fe80::1%eth0') not in mixed


def test_set_equality_is_construction_independent():
    direct = ScopedIPv6Set(['fe80::/10%*'])
    rebuilt = (direct - ScopedIPv6Set(['fe80::1%eth0'])) | ScopedIPv6Set(['fe80::1%eth0'])
    assert rebuilt == direct
    assert hash(rebuilt) == hash(direct)

    #   Merging adjacent ranges across separate elements.
    assert ScopedIPv6Set(['fe80::2%eth0', 'fe80::3%eth0']) == ScopedIPv6Set(['fe80::2/127%eth0'])


def test_set_mutation_and_subset_relations():
    scoped_set = ScopedIPv6Set()
    assert scoped_set.is_empty
    assert not scoped_set

    scoped_set.add('fe80::1%eth0')
    scoped_set.add(ScopedIPv6Address('fe80::%eth0'))
    assert scoped_set == ScopedIPv6Set(['fe80::/127%eth0'])
    assert scoped_set.issubset(ScopedIPv6Set(['fe80::/10%*']))
    assert ScopedIPv6Set(['fe80::/10%*']).issuperset(scoped_set)

    scoped_set.discard('fe80::1%eth0')
    assert scoped_set == ScopedIPv6Set(['fe80::%eth0'])
    scoped_set.discard('fe80::1%eth0')  # absent: no-op
    assert scoped_set == ScopedIPv6Set(['fe80::%eth0'])

    assert pickle.loads(pickle.dumps(scoped_set)) == scoped_set


def test_set_symmetric_difference():
    first = ScopedIPv6Set(['fe80::/64%eth0'])
    second = ScopedIPv6Set(['fe80::1%eth0', 'fe80::1%eth1'])

    result = first ^ second
    assert result == (first - second) | (second - first)
    assert ScopedIPv6Address('fe80::1%eth0') not in result
    assert ScopedIPv6Address('fe80::1%eth1') in result
    assert ScopedIPv6Address('fe80::2%eth0') in result


def test_set_rejects_invalid_elements():
    with pytest.raises(AddrFormatError):
        ScopedIPv6Set(['2001:db8::1%eth0'])
    with pytest.raises(AddrFormatError):
        ScopedIPv6Set(['fe80::1%'])
    with pytest.raises(TypeError):
        ScopedIPv6Set([IPAddress('fe80::1')])
    with pytest.raises(AddrFormatError):
        ScopedIPv6Set(['not-an-address%eth0'])

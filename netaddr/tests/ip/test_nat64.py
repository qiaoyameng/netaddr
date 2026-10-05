import pytest

from netaddr import AddrConversionError, AddrFormatError, IPAddress, IPNetwork, IPSet
from netaddr.ip.nat64 import (
    RFC6052_PREFIX_LENGTHS,
    RFC6052IPSet,
    RFC6052Range,
    embed_ipv4,
    embed_ipv4_set,
    extract_ipv4,
    extract_ipv4_set,
)


PREFIXES = {
    32: ('2001:db8::/32', '2001:db8::c000:201:0:0'),
    40: ('2001:db8:100::/40', '2001:db8:100:0:c000:201::'),
    48: ('2001:db8:1::/48', '2001:db8:1:0:c000:201::'),
    56: ('2001:db8:1:200::/56', '2001:db8:1:200:c000:201::'),
    64: ('2001:db8:1:2::/64', '2001:db8:1:2:c000:201::'),
    96: ('64:ff9b::/96', '64:ff9b::c000:201'),
}


@pytest.mark.parametrize('prefixlen', RFC6052_PREFIX_LENGTHS)
def test_embed_extract_rfc_prefix_lengths(prefixlen):
    prefix, expected = PREFIXES[prefixlen]
    mapped = embed_ipv4(IPAddress('192.0.2.1'), prefix)
    assert mapped == IPAddress(expected)
    assert extract_ipv4(mapped, prefix) == IPAddress('192.0.2.1')


@pytest.mark.parametrize('ipv4', ['0.0.0.0', '198.51.100.73', '255.255.255.255'])
@pytest.mark.parametrize('prefixlen', RFC6052_PREFIX_LENGTHS)
def test_single_address_round_trip_boundaries(ipv4, prefixlen):
    prefix = PREFIXES[prefixlen][0]
    assert extract_ipv4(embed_ipv4(ipv4, prefix), prefix) == IPAddress(ipv4)


def test_default_well_known_prefix():
    assert embed_ipv4('192.0.2.1') == IPAddress('64:ff9b::192.0.2.1')
    assert extract_ipv4('64:ff9b::192.0.2.1') == IPAddress('192.0.2.1')


def test_invalid_prefix_length_and_host_bits():
    with pytest.raises(AddrFormatError, match='prefix length'):
        embed_ipv4('192.0.2.1', '64:ff9b::/65')

    with pytest.raises(AddrFormatError, match='host bits'):
        embed_ipv4('192.0.2.1', '64:ff9b::1/96')


def test_single_address_type_errors():
    with pytest.raises(AddrConversionError, match='IPv4'):
        embed_ipv4(IPAddress('::1'))

    with pytest.raises(AddrFormatError, match='IPv6'):
        extract_ipv4(IPAddress('192.0.2.1'))


@pytest.mark.parametrize(
    ('address', 'prefix', 'violation'),
    [
        ('2001:db9:1:200:c000:201::', '2001:db8:1:200::/56', 'prefix'),
        ('2001:db8:1:201:c000:201::', '2001:db8:1:200::/56', 'u bits'),
        ('2001:db8:1:200:c000:201::1', '2001:db8:1:200::/56', 'suffix'),
        ('2001:db9:1:2:c000:201::', '2001:db8:1:2::/64', 'prefix'),
        ('2001:db8:1:2:c000:201::1', '2001:db8:1:2::/64', 'suffix'),
        ('64:ff9b:1::c000:201', '64:ff9b::/96', 'prefix'),
    ],
)
def test_extraction_reports_violated_constraint(address, prefix, violation):
    with pytest.raises(AddrFormatError, match=violation):
        extract_ipv4(address, prefix)


def test_embed_ipv4_set_with_slash_96_returns_exact_ipset():
    source = IPSet(['10.0.0.128/25'])
    mapped = embed_ipv4_set(source, '64:ff9b::/96')

    assert isinstance(mapped, RFC6052IPSet)
    assert mapped.to_ipset() == IPSet(['64:ff9b::a00:80/121'])
    assert extract_ipv4_set(mapped, '64:ff9b::/96') == source
    assert IPAddress('64:ff9b::a00:80') in mapped
    assert IPAddress('64:ff9b::a00:7f') not in mapped
    assert IPAddress('64:ff9b::a01:80') not in mapped
    assert extract_ipv4_set(mapped.to_ipset(), '64:ff9b::/96') == source


def test_embed_ipv4_set_across_byte_boundary_is_lazy_and_exact():
    source = IPSet(['10.0.0.128/25'])
    mapped = embed_ipv4_set(source, '2001:db8:1:2::/64')

    assert isinstance(mapped, RFC6052IPSet)
    segment = next(mapped.iter_segments())
    assert isinstance(segment, RFC6052Range)
    assert segment.first_ipv4 == IPAddress('10.0.0.128')
    assert segment.last_ipv4 == IPAddress('10.0.0.255')
    assert segment.step == 1 << 32
    assert segment.first == IPAddress('2001:db8:1:2:a00:80::')
    assert segment.last == IPAddress('2001:db8:1:2:a00:ff::')
    assert mapped.size == 128
    assert IPAddress('2001:db8:1:2:a00:80::') in mapped
    assert IPAddress('2001:db8:1:2:a00:7f::') not in mapped
    assert IPAddress('2001:db8:1:2:1:a00:80::') not in mapped
    assert IPAddress('2001:db8:1:2:a00:80::1') not in mapped
    assert extract_ipv4_set(mapped) == source


def test_large_mapped_input_does_not_expand_addresses():
    source = IPSet(['0.0.0.0/0'])
    mapped = embed_ipv4_set(source, '2001:db8:1:2::/64')

    assert mapped.size == 1 << 32
    segment = next(mapped.iter_segments())
    assert segment.first == embed_ipv4('0.0.0.0', '2001:db8:1:2::/64')
    assert segment.last == embed_ipv4('255.255.255.255', '2001:db8:1:2::/64')
    assert extract_ipv4_set(mapped) == source


def test_extract_ipv4_set_rejects_ranges_crossing_reserved_fields():
    with pytest.raises(AddrFormatError, match='u bits'):
        extract_ipv4_set(IPSet(['2001:db8:1:200:0:c000::/63']), '2001:db8:1:200::/56')

    with pytest.raises(AddrFormatError, match='suffix'):
        extract_ipv4_set(IPSet(['2001:db8:1:2:c000:201::/127']), '2001:db8:1:2::/64')


def test_set_inputs_must_use_expected_version():
    with pytest.raises(TypeError, match='IPSet'):
        embed_ipv4_set(['192.0.2.0/24'])

    with pytest.raises(TypeError, match='IPv4'):
        embed_ipv4_set(IPSet(['::1/128']), '2001:db8:1:2::/64')

    with pytest.raises(TypeError, match='IPv6'):
        extract_ipv4_set(IPSet(['192.0.2.0/24']))


def test_slash_96_subnet_round_trip():
    mapped = IPSet(['64:ff9b::a00:80/121'])
    assert extract_ipv4_set(mapped) == IPSet(['10.0.0.128/25'])


def test_short_prefix_lazy_cidrs_are_host_route_exact():
    mapped = embed_ipv4_set(IPSet(['10.0.0.128/30']), '2001:db8:1:2::/64')
    assert list(mapped.iter_cidrs()) == [
        IPNetwork((embed_ipv4(ip, '2001:db8:1:2::/64')._value, 128), 6)
        for ip in ['10.0.0.128', '10.0.0.129', '10.0.0.130', '10.0.0.131']
    ]

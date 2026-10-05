import pickle
from itertools import islice

import pytest

from netaddr import (
    AddrFormatError,
    IPAddress,
    IPNetwork,
    IPRange,
    IPSet,
    RFC6052IPSet,
    RFC6052Segment,
    rfc6052_embed,
    rfc6052_embed_set,
    rfc6052_extract,
)


@pytest.mark.parametrize(
    ('prefix', 'expected'),
    [
        ('2001:db8::/32', '2001:db8:c000:221::'),
        ('2001:db8:6400::/40', '2001:db8:64c0:2:21::'),
        ('2001:db8:6400::/48', '2001:db8:6400:c000:2:2100::'),
        ('2001:db8:6400:c000::/56', '2001:db8:6400:c0c0:0:221::'),
        ('2001:db8:6400:c000::/64', '2001:db8:6400:c000:c0:2:2100:0'),
        ('64:ff9b::/96', '64:ff9b::c000:221'),
    ],
)
def test_rfc6052_example_addresses_roundtrip(prefix, expected):
    mapped = rfc6052_embed('192.0.2.33', prefix)
    assert mapped == IPAddress(expected)
    assert rfc6052_extract(mapped, prefix) == IPAddress('192.0.2.33')


@pytest.mark.parametrize(
    'prefix',
    [
        '2001:db8::/32',
        '2001:db8:6400::/40',
        '2001:db8:6400::/48',
        '2001:db8:6400:c000::/56',
        '2001:db8:6400:c000::/64',
        '64:ff9b::/96',
    ],
)
@pytest.mark.parametrize('ipv4_address', ['0.0.0.0', '255.255.255.255'])
def test_rfc6052_boundary_addresses_roundtrip(prefix, ipv4_address):
    mapped = rfc6052_embed(ipv4_address, prefix)
    assert rfc6052_extract(mapped, prefix) == IPAddress(ipv4_address)


def test_rfc6052_extraction_rejects_wrong_prefix():
    with pytest.raises(AddrFormatError, match='IPv6 prefix'):
        rfc6052_extract('2001:db8::1', '64:ff9b::/96')


@pytest.mark.parametrize(
    'prefix',
    [
        '2001:db8:6400::/40',
        '2001:db8:6400::/48',
        '2001:db8:6400:c000::/56',
        '2001:db8:6400:c000::/64',
    ],
)
def test_rfc6052_extraction_rejects_nonzero_reserved_u(prefix):
    invalid = int(rfc6052_embed('192.0.2.33', prefix)) + (1 << 56)

    with pytest.raises(AddrFormatError, match='u byte'):
        rfc6052_extract(IPAddress(invalid, 6), prefix)


@pytest.mark.parametrize(
    'prefix',
    [
        '2001:db8::/32',
        '2001:db8:6400::/40',
        '2001:db8:6400::/48',
        '2001:db8:6400:c000::/56',
        '2001:db8:6400:c000::/64',
    ],
)
def test_rfc6052_extraction_rejects_nonzero_suffix(prefix):
    invalid = int(rfc6052_embed('192.0.2.33', prefix)) + 1

    with pytest.raises(AddrFormatError, match='suffix'):
        rfc6052_extract(IPAddress(invalid, 6), prefix)


@pytest.mark.parametrize('prefix', ['64:ff9b::/31', '64:ff9b::/65', '64:ff9b::/128'])
def test_rfc6052_rejects_disallowed_prefix_lengths(prefix):
    with pytest.raises(AddrFormatError, match='prefix length'):
        rfc6052_embed('192.0.2.1', prefix)


def test_rfc6052_rejects_prefix_with_host_bits():
    with pytest.raises(AddrFormatError, match='host bits'):
        rfc6052_embed('192.0.2.1', '64:ff9b::1/96')


def test_rfc6052_rejects_single_address_networks():
    with pytest.raises(AddrFormatError, match='IP address'):
        rfc6052_embed(IPNetwork('192.0.2.1/32'), '64:ff9b::/96')

    with pytest.raises(AddrFormatError, match='IP address'):
        rfc6052_extract(IPNetwork('64:ff9b::192.0.2.1/128'), '64:ff9b::/96')


def test_rfc6052_slash_96_set_has_exact_cidr_representation():
    mapped = rfc6052_embed_set(IPSet(['192.0.2.0/23']), '64:ff9b::/96')

    assert isinstance(mapped, IPSet)
    assert mapped.iter_cidrs() == [IPNetwork('64:ff9b::192.0.2.0/119')]
    assert IPAddress('64:ff9b::192.0.2.255') in mapped
    assert IPAddress('64:ff9b::192.0.3.0') in mapped
    assert IPAddress('64:ff9b::192.0.4.0') not in mapped


def test_rfc6052_non_96_set_uses_lazy_exact_segmentation():
    source = IPSet(['192.0.2.0/23'])
    prefix = '2001:db8:6400::/40'
    mapped = rfc6052_embed_set(source, prefix)

    assert isinstance(mapped, RFC6052IPSet)
    segments = list(mapped.iter_segments())
    assert list(islice(mapped.iter_ipranges(), 2)) == [
        IPRange('2001:db8:64c0:2::', '2001:db8:64c0:2::'),
        IPRange('2001:db8:64c0:2:1::', '2001:db8:64c0:2:1::'),
    ]
    assert segments == [
        RFC6052Segment(
            IPNetwork('2001:db8:6400::/40')._value,
            40,
            IPNetwork('192.0.2.0/23').first,
            IPNetwork('192.0.2.0/23').last,
        )
    ]

    assert rfc6052_embed('192.0.2.255', prefix) in mapped
    assert rfc6052_embed('192.0.3.0', prefix) in mapped
    assert rfc6052_embed('192.0.3.255', prefix) in mapped
    assert rfc6052_embed('192.0.4.0', prefix) not in mapped

    reserved_u = int(rfc6052_embed('192.0.2.0', prefix)) + (1 << 56)
    suffix = int(rfc6052_embed('192.0.2.0', prefix)) + 1
    assert IPAddress(reserved_u, 6) not in mapped
    assert IPAddress(suffix, 6) not in mapped

    first_two = list(islice(mapped, 2))
    transition_start = 255
    transition = list(islice(mapped, transition_start, transition_start + 3))
    assert first_two == [
        rfc6052_embed('192.0.2.0', prefix),
        rfc6052_embed('192.0.2.1', prefix),
    ]
    assert transition == [
        rfc6052_embed('192.0.2.255', prefix),
        rfc6052_embed('192.0.3.0', prefix),
        rfc6052_embed('192.0.3.1', prefix),
    ]
    assert IPAddress(int(rfc6052_embed('192.0.2.255', prefix)) + 1, 6) not in mapped


def test_rfc6052_large_set_does_not_require_address_objects():
    mapped = rfc6052_embed_set(IPSet(['0.0.0.0/0']), '2001:db8:6400::/40')

    assert mapped.size == 2 ** 32
    assert len(list(mapped.iter_segments())) == 1
    assert rfc6052_embed('0.0.0.0', '2001:db8:6400::/40') in mapped
    assert rfc6052_embed('255.255.255.255', '2001:db8:6400::/40') in mapped

    first_two = list(islice(mapped, 2))
    assert first_two == [
        rfc6052_embed('0.0.0.0', '2001:db8:6400::/40'),
        rfc6052_embed('0.0.0.1', '2001:db8:6400::/40'),
    ]


def test_rfc6052_lazy_set_pickles():
    prefix = '2001:db8:6400::/40'
    mapped = rfc6052_embed_set(IPSet(['192.0.2.0/23']), prefix)

    restored = pickle.loads(pickle.dumps(mapped))

    assert restored == mapped
    assert rfc6052_embed('192.0.3.0', prefix) in restored


def test_rfc6052_set_embedding_requires_ipv4_ipset():
    with pytest.raises(TypeError):
        rfc6052_embed_set(['192.0.2.0/24'])

    with pytest.raises(AddrFormatError, match='IPv4 networks'):
        rfc6052_embed_set(IPSet(['2001:db8::/32']), '64:ff9b::/96')

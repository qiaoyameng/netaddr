# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""RFC 6052 IPv4/IPv6 address translation for NAT64."""

import itertools as _itertools
import sys as _sys

from netaddr.core import AddrFormatError
from netaddr.ip import IPAddress, IPNetwork, IPRange
from netaddr.ip.sets import IPSet

#: Prefix lengths permitted by RFC 6052 section 2.2.
RFC6052_ALLOWED_PREFIX_LENS = frozenset((32, 40, 48, 56, 64, 96))

#: The RFC 6052 well-known NAT64 prefix.
RFC6052_WELL_KNOWN_PREFIX = IPNetwork('64:ff9b::/96')
NAT64_WELL_KNOWN_PREFIX = RFC6052_WELL_KNOWN_PREFIX


def _parse_prefix(prefix):
    if isinstance(prefix, IPAddress):
        raise AddrFormatError('RFC 6052 prefix must include a prefix length')

    if isinstance(prefix, IPNetwork):
        network = IPNetwork(prefix)
    else:
        try:
            network = IPNetwork(prefix)
        except AddrFormatError:
            raise AddrFormatError('invalid RFC 6052 IPv6 prefix: %r' % (prefix,))

    if network.version != 6:
        raise AddrFormatError('RFC 6052 prefix must be an IPv6 network')

    if network.prefixlen not in RFC6052_ALLOWED_PREFIX_LENS:
        raise AddrFormatError(
            'RFC 6052 prefix length must be one of %s, not %d'
            % (
                sorted(RFC6052_ALLOWED_PREFIX_LENS),
                network.prefixlen,
            )
        )

    if network._value != network.first:
        raise AddrFormatError('RFC 6052 prefix has non-zero host bits: %s' % network)

    return network._value, network.prefixlen


def _ipv4_value(address):
    if hasattr(address, '_prefixlen'):
        raise AddrFormatError('RFC 6052 embedding expects an IP address, not a network')
    ip = address if isinstance(address, IPAddress) else IPAddress(address)
    if ip.version != 4:
        raise AddrFormatError('RFC 6052 embedding expects an IPv4 address')
    return ip._value


def _ipv6_value(address):
    if hasattr(address, '_prefixlen'):
        raise AddrFormatError('RFC 6052 extraction expects an IP address, not a network')
    ip = address if isinstance(address, IPAddress) else IPAddress(address)
    if ip.version != 6:
        raise AddrFormatError('RFC 6052 extraction expects an IPv6 address')
    return ip._value


def _suffix_length(prefixlen):
    if prefixlen == 96:
        return 0
    if prefixlen == 32:
        return 64
    return 128 - prefixlen - 40


def _embed_ipv4_value(ipv4_value, prefixlen):
    if prefixlen == 32:
        return ipv4_value << 64
    if prefixlen == 96:
        return ipv4_value

    low_len = prefixlen - 32
    suffix_len = _suffix_length(prefixlen)
    high = ipv4_value >> low_len
    low = ipv4_value & ((1 << low_len) - 1)
    return (high << 64) | (low << suffix_len)


def _extract_ipv4_value(value, prefix_value, prefixlen):
    prefix_mask = ((1 << prefixlen) - 1) << (128 - prefixlen)
    if value & prefix_mask != prefix_value:
        raise AddrFormatError(
            'RFC 6052 address does not match the configured IPv6 prefix'
        )

    remaining = value ^ prefix_value

    if prefixlen == 32:
        suffix = remaining & ((1 << 64) - 1)
        if suffix:
            raise AddrFormatError('RFC 6052 suffix must be zero')
        return remaining >> 64

    if prefixlen == 96:
        return remaining

    suffix_len = _suffix_length(prefixlen)
    suffix = remaining & ((1 << suffix_len) - 1)
    reserved_u = (remaining >> 56) & 0xFF
    low_len = prefixlen - 32
    high = remaining >> 64
    low = (remaining >> suffix_len) & ((1 << low_len) - 1)

    if reserved_u:
        raise AddrFormatError('RFC 6052 reserved u byte must be zero')
    if suffix:
        raise AddrFormatError('RFC 6052 suffix must be zero')

    return (high << low_len) | low


class RFC6052Segment(object):
    """
    A lazy, exact representation of mapped IPv4 addresses with a non-/96
    RFC 6052 prefix.

    Membership is validated structurally, so reserved u bytes and suffixes
    are not treated as members.
    """

    __slots__ = (
        '_prefix_value',
        '_prefixlen',
        '_ipv4_first',
        '_ipv4_last',
    )

    def __init__(self, prefix_value, prefixlen, ipv4_first, ipv4_last):
        self._prefix_value = prefix_value
        self._prefixlen = prefixlen
        self._ipv4_first = ipv4_first
        self._ipv4_last = ipv4_last

    def __getstate__(self):
        return self._prefix_value, self._prefixlen, self._ipv4_first, self._ipv4_last

    def __setstate__(self, state):
        (
            self._prefix_value,
            self._prefixlen,
            self._ipv4_first,
            self._ipv4_last,
        ) = state

    @property
    def prefix(self):
        """:return: the RFC 6052 IPv6 prefix as an :class:`IPNetwork`."""
        return IPNetwork((self._prefix_value, self._prefixlen), version=6)

    @property
    def start(self):
        """:return: the first mapped IPv6 address."""
        return self.mapped_address(self._ipv4_first)

    @property
    def stop(self):
        """:return: the last mapped IPv6 address."""
        return self.mapped_address(self._ipv4_last)

    @property
    def start_integer(self):
        """:return: the integer value of the first mapped IPv6 address."""
        return int(self.start)

    @property
    def stop_integer(self):
        """:return: the integer value of the last mapped IPv6 address."""
        return int(self.stop)

    @property
    def size(self):
        """:return: the number of mapped IPv4 addresses in this segment."""
        return self._ipv4_last - self._ipv4_first + 1

    def __contains__(self, address):
        try:
            ip = address if isinstance(address, IPAddress) else IPAddress(address)
        except AddrFormatError:
            return False

        if ip.version != 6:
            return False

        try:
            ipv4_value = _extract_ipv4_value(
                ip._value,
                self._prefix_value,
                self._prefixlen,
            )
        except AddrFormatError:
            return False

        return self._ipv4_first <= ipv4_value <= self._ipv4_last

    def iter_ipranges(self):
        """:return: exact one-address IPv6 ranges in this lazy segment."""
        for ipv4_value in range(self._ipv4_first, self._ipv4_last + 1):
            address = self.mapped_address(ipv4_value)
            yield IPRange(address, address)

    def mapped_address(self, ipv4_value):
        """:return: the mapped address for one IPv4 integer."""
        return IPAddress(
            self._prefix_value | _embed_ipv4_value(ipv4_value, self._prefixlen),
            6,
        )

    def __iter__(self):
        for ipv4_value in range(self._ipv4_first, self._ipv4_last + 1):
            yield self.mapped_address(ipv4_value)

    def __eq__(self, other):
        if not isinstance(other, RFC6052Segment):
            return NotImplemented
        return (
            self._prefix_value == other._prefix_value
            and self._prefixlen == other._prefixlen
            and self._ipv4_first == other._ipv4_first
            and self._ipv4_last == other._ipv4_last
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        raise TypeError('RFC 6052 segments are unhashable')

    def __repr__(self):
        return 'RFC6052Segment(%r, %r, %r)' % (
            str(self.prefix),
            str(self.start),
            str(self.stop),
        )


class RFC6052IPSet(object):
    """
    A lazy, exact representation of IPv4 addresses mapped under a non-/96
    RFC 6052 prefix.
    """

    __slots__ = ('_prefix_value', '_prefixlen', '_source')

    def __init__(self, prefix_value, prefixlen, source):
        self._prefix_value = prefix_value
        self._prefixlen = prefixlen
        self._source = IPSet(source.iter_cidrs())

    def __getstate__(self):
        return self._prefix_value, self._prefixlen, self._source

    def __setstate__(self, state):
        self._prefix_value, self._prefixlen, self._source = state

    @property
    def prefix(self):
        """:return: the RFC 6052 IPv6 prefix as an :class:`IPNetwork`."""
        return IPNetwork((self._prefix_value, self._prefixlen), version=6)

    @property
    def size(self):
        """:return: the number of mapped addresses."""
        return self._source.size

    def iter_segments(self):
        """:return: lazy :class:`RFC6052Segment` objects, one per source CIDR."""
        for cidr in self._source.iter_cidrs():
            yield RFC6052Segment(
                self._prefix_value,
                self._prefixlen,
                cidr.first,
                cidr.last,
            )

    def iter_ipranges(self):
        """:return: exact one-address IPv6 ranges in this lazy set."""
        for segment in self.iter_segments():
            for iprange in segment.iter_ipranges():
                yield iprange

    def __contains__(self, address):
        ip = address if isinstance(address, IPAddress) else IPAddress(address)
        if ip.version != 6:
            return False

        try:
            ipv4_value = _extract_ipv4_value(
                ip._value,
                self._prefix_value,
                self._prefixlen,
            )
        except AddrFormatError:
            return False

        return IPAddress(ipv4_value, 4) in self._source

    def __iter__(self):
        return _itertools.chain.from_iterable(self.iter_segments())

    def __bool__(self):
        return bool(self._source)

    def __len__(self):
        size = self.size
        if size > _sys.maxsize:
            raise IndexError('range contains more than sys.maxsize IP addresses')
        return size

    def __eq__(self, other):
        if not isinstance(other, RFC6052IPSet):
            return NotImplemented
        return (
            self._prefix_value == other._prefix_value
            and self._prefixlen == other._prefixlen
            and list(self._source.iter_cidrs()) == list(other._source.iter_cidrs())
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        raise TypeError('RFC 6052 IP sets are unhashable')

    def __repr__(self):
        return 'RFC6052IPSet(%r, %r)' % (
            [str(cidr) for cidr in self._source.iter_cidrs()],
            str(self.prefix),
        )


def embed(ipv4_address, prefix=RFC6052_WELL_KNOWN_PREFIX):
    """
    Embed an IPv4 address in an IPv6 address according to RFC 6052.

    :param ipv4_address: the IPv4 address to embed.
    :param prefix: an IPv6 network whose prefix length is 32, 40, 48, 56,
        64 or 96. The RFC 6052 well-known prefix is the default.
    :return: an IPv6 :class:`IPAddress`.
    """
    prefix_value, prefixlen = _parse_prefix(prefix)
    ipv4_value = _ipv4_value(ipv4_address)
    return IPAddress(
        prefix_value | _embed_ipv4_value(ipv4_value, prefixlen),
        6,
    )


def extract(ipv6_address, prefix=RFC6052_WELL_KNOWN_PREFIX):
    """
    Extract an IPv4 address from an RFC 6052 IPv6 address.

    :param ipv6_address: the synthetic IPv6 address.
    :param prefix: the RFC 6052 IPv6 prefix used for embedding.
    :return: an IPv4 :class:`IPAddress`.
    :raises AddrFormatError: if the prefix, reserved u byte or suffix does
        not satisfy RFC 6052.
    """
    prefix_value, prefixlen = _parse_prefix(prefix)
    ipv6_value = _ipv6_value(ipv6_address)
    ipv4_value = _extract_ipv4_value(ipv6_value, prefix_value, prefixlen)
    return IPAddress(ipv4_value, 4)


def embed_set(ipv4_set, prefix=RFC6052_WELL_KNOWN_PREFIX):
    """
    Embed every address in an IPv4 :class:`IPSet` using RFC 6052.

    A /96 prefix produces a compact IPv6 :class:`IPSet`. Other prefixes
    return a lazy :class:`RFC6052IPSet` so that suffix and reserved-u-byte
    holes are never represented as members.

    :param ipv4_set: an IPv4 :class:`IPSet`.
    :param prefix: a valid RFC 6052 IPv6 prefix.
    :return: an :class:`IPSet` for /96, otherwise an :class:`RFC6052IPSet`.
    """
    if not isinstance(ipv4_set, IPSet):
        raise TypeError('RFC 6052 set embedding expects an IPSet')

    prefix_value, prefixlen = _parse_prefix(prefix)

    for cidr in ipv4_set.iter_cidrs():
        if cidr.version != 4:
            raise AddrFormatError('RFC 6052 set embedding expects IPv4 networks')

    if prefixlen == 96:
        mapped = IPSet()
        mapped._cidrs = dict.fromkeys(
            (
                IPNetwork(
                    (prefix_value | cidr.first, prefixlen + cidr.prefixlen),
                    version=6,
                )
                for cidr in ipv4_set.iter_cidrs()
            ),
            True,
        )
        return mapped

    return RFC6052IPSet(prefix_value, prefixlen, ipv4_set)


rfc6052_embed = embed
rfc6052_extract = extract
rfc6052_embed_set = embed_set

nat64_embed = embed
nat64_extract = extract
nat64_embed_set = embed_set

embed_ipv4_address = embed
extract_ipv4_address = extract
embed_ipv4_set = embed_set

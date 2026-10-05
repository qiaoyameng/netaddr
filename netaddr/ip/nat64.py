"""RFC 6052 IPv4/IPv6 address translation helpers."""

import sys

from netaddr.core import AddrConversionError, AddrFormatError
from netaddr.ip import IPAddress, IPNetwork, IPRange, iprange_to_cidrs
from netaddr.ip.sets import IPSet


DEFAULT_NAT64_PREFIX = '64:ff9b::/96'
RFC6052_PREFIX_LENGTHS = (32, 40, 48, 56, 64, 96)

_IPV4_MASK = (1 << 32) - 1
_LOW_32_MASK = _IPV4_MASK


def _prefix_network(prefix):
    if prefix is None:
        prefix = DEFAULT_NAT64_PREFIX

    if isinstance(prefix, IPNetwork):
        network = prefix
    else:
        network = IPNetwork(prefix, version=6)

    if network.version != 6:
        raise AddrFormatError('RFC 6052 prefix must be an IPv6 network')

    if network.prefixlen not in RFC6052_PREFIX_LENGTHS:
        raise AddrFormatError(
            'RFC 6052 prefix length must be one of %s, not %d'
            % (RFC6052_PREFIX_LENGTHS, network.prefixlen)
        )

    if network._value != network.first:
        raise AddrFormatError('RFC 6052 prefix must not contain host bits: %s' % network)

    return network


def _ipv4_address(address):
    if isinstance(address, IPNetwork):
        raise TypeError('an IP address is required, not an IPNetwork')
    if isinstance(address, IPAddress):
        ip = address
    else:
        ip = IPAddress(address, version=4)

    if ip.version != 4:
        raise AddrConversionError('RFC 6052 embedding expected an IPv4 address, not %s' % ip)

    return ip


def _ipv6_address(address):
    if isinstance(address, IPNetwork):
        raise TypeError('an IP address is required, not an IPNetwork')
    if isinstance(address, IPAddress):
        ip = address
    else:
        ip = IPAddress(address, version=6)

    if ip.version != 6:
        raise AddrFormatError('RFC 6052 extraction expected an IPv6 address, not %s' % ip)

    return ip


def _reserved_mask(prefixlen):
    if prefixlen == 96:
        return 0

    u_mask = ((1 << (64 - prefixlen)) - 1) << 64
    return _LOW_32_MASK | u_mask


def _embedded_ipv4(value, prefixlen):
    if prefixlen == 96:
        return value & _IPV4_MASK
    return (value >> 32) & _IPV4_MASK


def _check_synthetic(value, prefix):
    prefix_mask = ((1 << prefix.prefixlen) - 1) << (128 - prefix.prefixlen)
    if value & prefix_mask != prefix._value:
        raise AddrFormatError(
            'RFC 6052 address does not match translation prefix %s' % prefix
        )

    reserved_value = value & _reserved_mask(prefix.prefixlen)
    if reserved_value:
        u_mask = _reserved_mask(prefix.prefixlen) & ~_LOW_32_MASK
        if value & u_mask:
            constraint = 'u bits'
        else:
            constraint = 'suffix'
        raise AddrFormatError('RFC 6052 %s must be zero' % constraint)


def embed_ipv4(address, prefix=None):
    """Embed ``address`` in an RFC 6052 IPv6 translation prefix.

    :param address: an IPv4 address.
    :param prefix: an IPv6 network with prefix length 32, 40, 48, 56, 64 or
        96. Defaults to the well-known prefix ``64:ff9b::/96``.
    :return: the synthetic IPv6 :class:`~netaddr.IPAddress`.
    """
    prefix_network = _prefix_network(prefix)
    ipv4 = _ipv4_address(address)

    if prefix_network.prefixlen == 96:
        value = prefix_network._value | int(ipv4)
    else:
        value = prefix_network._value | (int(ipv4) << 32)

    return IPAddress(value, 6)


def extract_ipv4(address, prefix=None):
    """Extract the embedded IPv4 address from an RFC 6052 IPv6 address.

    The prefix bits, reserved u bits and trailing suffix bits are validated.
    A failure message identifies which format constraint was violated.

    :param address: an RFC 6052 synthetic IPv6 address.
    :param prefix: the translation prefix used by ``address``.
    :return: the embedded IPv4 :class:`~netaddr.IPAddress`.
    """
    prefix_network = _prefix_network(prefix)
    ipv6 = _ipv6_address(address)

    _check_synthetic(int(ipv6), prefix_network)
    return IPAddress(_embedded_ipv4(int(ipv6), prefix_network.prefixlen), 4)


class RFC6052Range(object):
    """A lazy, potentially sparse range of RFC 6052 synthetic addresses."""

    __slots__ = ('_prefix', '_first', '_last')

    def __init__(self, prefix, first, last):
        self._prefix = prefix
        self._first = first
        self._last = last

    @property
    def prefix(self):
        """The RFC 6052 translation prefix for this segment."""
        return self._prefix

    @property
    def first_ipv4(self):
        """The first embedded IPv4 address in this segment."""
        return IPAddress(self._first, 4)

    @property
    def last_ipv4(self):
        """The last embedded IPv4 address in this segment."""
        return IPAddress(self._last, 4)

    @property
    def first(self):
        """The first synthetic IPv6 address in this segment."""
        return embed_ipv4(self._first, self._prefix)

    @property
    def last(self):
        """The last synthetic IPv6 address in this segment."""
        return embed_ipv4(self._last, self._prefix)

    @property
    def step(self):
        """The numeric distance between consecutive synthetic IPv6 values."""
        return 1 if self._prefix.prefixlen == 96 else 1 << 32

    @property
    def size(self):
        """The number of IPv4 addresses represented by this segment."""
        return self._last - self._first + 1

    def __len__(self):
        return self.size

    def __iter__(self):
        shift = 0 if self._prefix.prefixlen == 96 else 32
        base = self._prefix._value
        for ipv4 in range(self._first, self._last + 1):
            yield IPAddress(base | (ipv4 << shift), 6)

    def __contains__(self, address):
        try:
            ip = address if isinstance(address, IPAddress) else IPAddress(address)
        except AddrFormatError:
            return False

        if ip.version != 6:
            return False

        value = int(ip)
        try:
            _check_synthetic(value, self._prefix)
        except AddrFormatError:
            return False

        ipv4 = _embedded_ipv4(value, self._prefix.prefixlen)
        return self._first <= ipv4 <= self._last

    def iter_cidrs(self):
        """Yield exact CIDR blocks; short prefixes use lazy ``/128`` routes."""
        if self._prefix.prefixlen == 96:
            for ipv4_cidr in iprange_to_cidrs(self.first_ipv4, self.last_ipv4):
                yield IPNetwork(
                    (self._prefix._value | ipv4_cidr.first, ipv4_cidr.prefixlen + 96),
                    6,
                )
        else:
            for address in self:
                yield IPNetwork((address._value, 128), 6)

    def __eq__(self, other):
        if not isinstance(other, RFC6052Range):
            return NotImplemented
        return (
            self._prefix == other._prefix
            and self._first == other._first
            and self._last == other._last
        )

    def __repr__(self):
        return 'RFC6052Range(%r, %r, %r)' % (
            str(self._prefix),
            str(self.first_ipv4),
            str(self.last_ipv4),
        )


class RFC6052IPSet(object):
    """An exact, lazy RFC 6052 mapping of an IPv4 ``IPSet``."""

    __slots__ = ('_ipv4_set', '_prefix')

    def __init__(self, ipv4_set, prefix=None):
        if not isinstance(ipv4_set, IPSet):
            raise TypeError('IPSet expected, not %s' % type(ipv4_set).__name__)

        self._prefix = _prefix_network(prefix)
        self._ipv4_set = ipv4_set.copy()

        for cidr in self._ipv4_set.iter_cidrs():
            if cidr.version != 4:
                raise TypeError('RFC 6052 set embedding accepts IPv4 addresses only')

    @property
    def prefix(self):
        """The RFC 6052 translation prefix used by this mapping."""
        return self._prefix

    @property
    def ipv4_set(self):
        """A copied :class:`~netaddr.IPSet` containing the source IPv4 space."""
        return self._ipv4_set.copy()

    @property
    def size(self):
        """The number of IPv4 addresses in this mapping."""
        return self._ipv4_set.size

    def __len__(self):
        size = self.size
        if size > sys.maxsize:
            raise IndexError('range contains more than sys.maxsize IP addresses')
        return size

    def __bool__(self):
        return bool(self._ipv4_set)

    def __iter__(self):
        for mapped_range in self.iter_ranges():
            yield from mapped_range

    def __contains__(self, address):
        try:
            ip = address if isinstance(address, IPAddress) else IPAddress(address)
        except AddrFormatError:
            return False

        if ip.version != 6:
            return False

        value = int(ip)
        try:
            _check_synthetic(value, self._prefix)
        except AddrFormatError:
            return False

        return IPAddress(_embedded_ipv4(value, self._prefix.prefixlen), 4) in self._ipv4_set

    def iter_ranges(self):
        """Yield one sparse :class:`RFC6052Range` per compact source CIDR."""
        for cidr in self._ipv4_set.iter_cidrs():
            yield RFC6052Range(self._prefix, cidr.first, cidr.last)

    def iter_segments(self):
        """Alias for :meth:`iter_ranges`."""
        yield from self.iter_ranges()

    def iter_ipranges(self):
        return self.iter_ranges()

    def iter_cidrs(self):
        """Yield exact CIDR blocks without including mapping gaps."""
        for cidr in self._ipv4_set.iter_cidrs():
            if self._prefix.prefixlen == 96:
                yield IPNetwork(
                    (embed_ipv4(cidr.first, self._prefix)._value, cidr.prefixlen + 96),
                    6,
                )
            else:
                yield from RFC6052Range(self._prefix, cidr.first, cidr.last).iter_cidrs()

    def iprange(self):
        """Return the single contiguous synthetic range, when one exists."""
        source_range = self._ipv4_set.iprange()
        if source_range is None:
            return None
        if self._prefix.prefixlen != 96 and source_range.size > 1:
            raise ValueError('RFC 6052 mapped set is not contiguous')
        return IPRange(
            embed_ipv4(source_range[0], self._prefix),
            embed_ipv4(source_range[-1], self._prefix),
        )

    def to_ipset(self):
        """Materialize this exact mapping as a regular :class:`~netaddr.IPSet`."""
        if self._prefix.prefixlen == 96:
            return IPSet(
                [
                    IPNetwork(
                        (embed_ipv4(cidr.first, self._prefix)._value, cidr.prefixlen + 96),
                        6,
                    )
                    for cidr in self._ipv4_set.iter_cidrs()
                ]
            )
        return IPSet(self.iter_cidrs())

    def __eq__(self, other):
        if not isinstance(other, RFC6052IPSet):
            return NotImplemented
        return self._prefix == other._prefix and self._ipv4_set == other._ipv4_set

    def __repr__(self):
        return 'RFC6052IPSet(%r, %r)' % (self._ipv4_set, str(self._prefix))


def embed_ipv4_set(ip_set, prefix=None):
    """Return the exact lazy RFC 6052 mapping of an IPv4 :class:`~netaddr.IPSet`.

    Short-prefix mappings are sparse in IPv6 address space. The returned
    object represents each source CIDR as one segmented arithmetic range and
    never fills the gaps between synthetic addresses.
    """
    return RFC6052IPSet(ip_set, _prefix_network(prefix))


def _check_cidr_reserved(cidr, prefix_network):
    if cidr.prefixlen < prefix_network.prefixlen:
        raise AddrFormatError(
            'RFC 6052 network does not match translation prefix %s' % prefix_network
        )

    value = cidr.first
    prefix_mask = ((1 << prefix_network.prefixlen) - 1) << (
        128 - prefix_network.prefixlen
    )
    if value & prefix_mask != prefix_network._value:
        raise AddrFormatError(
            'RFC 6052 network does not match translation prefix %s' % prefix_network
        )

    host_mask = (1 << (128 - cidr.prefixlen)) - 1
    reserved_mask = _reserved_mask(prefix_network.prefixlen)
    if host_mask & reserved_mask:
        u_mask = reserved_mask & ~_LOW_32_MASK
        if host_mask & u_mask:
            constraint = 'u bits'
        else:
            constraint = 'suffix'
        raise AddrFormatError('RFC 6052 %s must be zero' % constraint)

    if value & reserved_mask:
        u_mask = reserved_mask & ~_LOW_32_MASK
        if value & u_mask:
            constraint = 'u bits'
        else:
            constraint = 'suffix'
        raise AddrFormatError('RFC 6052 %s must be zero' % constraint)


def extract_ipv4_set(ip_set, prefix=None):
    """Extract the exact IPv4 set represented by RFC 6052 synthetic addresses.

    Each input CIDR is checked as a whole before extracting any address, so
    a network crossing reserved u or suffix bits is rejected without partially
    expanding its addresses.
    """
    if isinstance(ip_set, RFC6052IPSet):
        if prefix is not None:
            requested = _prefix_network(prefix)
            if requested != ip_set.prefix:
                raise AddrFormatError(
                    'RFC 6052 address does not match translation prefix %s' % requested
                )
        return ip_set.ipv4_set

    if not isinstance(ip_set, IPSet):
        raise TypeError('IPSet expected, not %s' % type(ip_set).__name__)

    prefix_network = _prefix_network(prefix)
    result = IPSet()

    for cidr in ip_set.iter_cidrs():
        if cidr.version != 6:
            raise TypeError('RFC 6052 set extraction accepts IPv6 addresses only')

        _check_cidr_reserved(cidr, prefix_network)

        if prefix_network.prefixlen == 96:
            if cidr.prefixlen < 96:
                raise AddrFormatError('RFC 6052 address does not match translation prefix')
            first = cidr.first & _IPV4_MASK
            result.add(IPNetwork((first, cidr.prefixlen - 96), version=4))
        else:
            if cidr.prefixlen != 128:
                if cidr.prefixlen < 96:
                    raise AddrFormatError('RFC 6052 suffix must be zero')
                raise AddrFormatError('RFC 6052 suffix must be zero')
            result.add(IPAddress(_embedded_ipv4(cidr.first, prefix_network.prefixlen), 4))

    return result


rfc6052_embed_ipv4 = embed_ipv4
rfc6052_extract_ipv4 = extract_ipv4
rfc6052_embed_ipv4_set = embed_ipv4_set
rfc6052_extract_ipv4_set = extract_ipv4_set
nat64_embed_ipv4 = embed_ipv4
nat64_extract_ipv4 = extract_ipv4
nat64_embed_ipv4_set = embed_ipv4_set
nat64_extract_ipv4_set = extract_ipv4_set

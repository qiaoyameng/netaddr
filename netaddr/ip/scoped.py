# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""Scoped (zoned) IPv6 addresses and zone-aware set algebra.

Collectors that read several network interfaces at once routinely see the
*same* link-local address on different interfaces, for example ``fe80::1``
on both ``eth0`` and ``eth1``.  Those are distinct addresses and must not
be conflated.  This module provides:

* :class:`ScopedIPv6Address` - an IPv6 address with an optional zone
  (scope) identifier, e.g. ``fe80::1%eth0``.
* :class:`ScopedIPv6Network` - an IPv6 network range with an optional zone.
* :class:`ScopedIPv6Set` - a set of scoped addresses/ranges supporting
  intersection, union and difference across both network ranges and zones.
* :data:`ANY_ZONE` - the explicit wildcard zone object.
* :class:`ZoneFilter` - the zone membership expressions used inside sets.

Design rules:

* Zones are compared by the exact, caller-provided identifier string.  No
  system interface lookup (such as ``socket.if_nametoindex``) is ever
  performed while parsing or comparing.
* A zone is only meaningful on addresses whose scope is not global, so
  zones are restricted to link-local unicast (``fe80::/10``) and multicast
  (``ff00::/8``) addresses and ranges.
* A missing zone is just that: *no zone*.  It is a distinct identity and
  never silently matches "all interfaces".  Wildcard matching only happens
  through the explicit :data:`ANY_ZONE` object (spelled ``%*`` in text).
* Equality, hashing, ordering and the text representation all follow the
  same identity definition: the address value plus its zone.

Example:

>>> eth0 = ScopedIPv6Address('fe80::1%eth0')
>>> eth1 = ScopedIPv6Address('fe80::1%eth1')
>>> eth0 == eth1
False
>>> wildcard = ScopedIPv6Set(['fe80::/10%*'])
>>> remaining = wildcard - ScopedIPv6Set([eth0])
>>> eth0 in remaining
False
>>> eth1 in remaining
True
>>> ScopedIPv6Address('fe80::2%eth0') in remaining
True
>>> ScopedIPv6Set(remaining.to_list()) == remaining
True
"""

import re as _re

from netaddr.core import AddrFormatError
from netaddr.strategy import ipv6 as _ipv6
from netaddr.ip import IPAddress, IPNetwork, iprange_to_cidrs

__all__ = [
    'ANY_ZONE',
    'ZoneFilter',
    'ScopedIPv6Address',
    'ScopedIPv6Network',
    'ScopedIPv6Set',
]

#: Zone identifiers are interface-name-like tokens.  ``*``, ``!``, ``,``,
#: ``%``, ``/`` and ``~`` are deliberately excluded so they can serve as
#: syntax in text representations.
_ZONE_NAME_RE = _re.compile(r'[0-9A-Za-z_.-]+')

#: Text spelling of the "no zone" identity inside zone filter expressions.
_NO_ZONE_TOKEN = '~'

#: Address scopes on which a zone identifier is meaningful (RFC 4007):
#: link-local unicast (fe80::/10) and multicast (ff00::/8).
_LINK_LOCAL_FIRST = 0xFE80 << 112
_LINK_LOCAL_LAST = _LINK_LOCAL_FIRST + (1 << 118) - 1
_MULTICAST_FIRST = 0xFF00 << 112
_MULTICAST_LAST = _MULTICAST_FIRST + (1 << 120) - 1

_SCOPE_ERROR = (
    'a zone identifier is only meaningful on link-local (fe80::/10) '
    'or multicast (ff00::/8) IPv6 addresses'
)


class _AnyZone(object):
    """Type of the :data:`ANY_ZONE` wildcard zone singleton."""

    __slots__ = ()

    def __repr__(self):
        return 'ANY_ZONE'

    def __str__(self):
        return '*'

    def __reduce__(self):
        return 'ANY_ZONE'


#: The explicit wildcard zone.  Use it wherever "any interface" is meant;
#: a missing (``None``) zone never implies wildcard matching.
ANY_ZONE = _AnyZone()


def _normalize_zone(zone):
    """Validate and normalize a caller-provided zone identifier.

    Returns ``None``, a non-empty string, or :data:`ANY_ZONE`.
    """
    if zone is None or zone is ANY_ZONE:
        return zone
    if isinstance(zone, bool):
        raise TypeError('zone identifier must be a string, not %r' % (zone,))
    if isinstance(zone, int):
        if zone < 0:
            raise ValueError('numeric zone identifiers must be >= 0')
        return str(zone)
    if isinstance(zone, str):
        if _ZONE_NAME_RE.fullmatch(zone) is None:
            raise AddrFormatError('invalid zone identifier: %r' % (zone,))
        return zone
    raise TypeError('unsupported zone identifier type: %s' % type(zone))


def _normalize_filter_zone(zone):
    """Like :func:`_normalize_zone` but for zone filter members.

    Filter members are concrete identities: ``None`` (no zone) or a zone
    name.  The wildcard is expressed with ``ZoneFilter.all_except()``.
    """
    if zone is ANY_ZONE:
        raise TypeError('ANY_ZONE is not a zone identity; use ZoneFilter.all_except()')
    return _normalize_zone(zone)


def _zone_member_sort_key(zone):
    """Total ordering for zone identities: no-zone sorts before names."""
    return (0, '') if zone is None else (1, zone)


def _spell_zone_member(zone):
    """Text spelling of a zone identity inside a filter expression."""
    return _NO_ZONE_TOKEN if zone is None else zone


def _parse_zone_member(token):
    """Inverse of :func:`_spell_zone_member`."""
    if token == _NO_ZONE_TOKEN:
        return None
    return _normalize_zone(token)


def _zone_identity_key(zone):
    """Hashable, orderable identity key for a zone on an address/network."""
    if zone is None:
        return (0, '')
    if zone is ANY_ZONE:
        return (2, '')
    return (1, zone)


def _is_scopable(value):
    """``True`` if an IPv6 address value may carry a zone identifier."""
    return (_LINK_LOCAL_FIRST <= value <= _LINK_LOCAL_LAST) or (
        _MULTICAST_FIRST <= value <= _MULTICAST_LAST
    )


def _range_scopable(first, last):
    """``True`` if the whole inclusive range may carry a zone identifier."""
    return (_LINK_LOCAL_FIRST <= first and last <= _LINK_LOCAL_LAST) or (
        _MULTICAST_FIRST <= first and last <= _MULTICAST_LAST
    )


class ZoneFilter(object):
    """A closed algebra over zone identities used by :class:`ScopedIPv6Set`.

    A filter is either a finite set of zone identities
    (``ZoneFilter.only('eth0', 'eth1')``) or the complement of one
    (``ZoneFilter.all_except('eth0')`` meaning "every zone except eth0").
    ``ZoneFilter.all_except()`` with no arguments is the wildcard ``*``.

    Zone identities are zone name strings plus ``None`` for "no zone".
    The two forms are closed under union, intersection and complement, so
    set operations on :class:`ScopedIPv6Set` always produce filters of the
    same kind.

    >>> ZoneFilter.only('eth0') & ZoneFilter.all_except('eth1')
    ZoneFilter.only('eth0')
    >>> str(ZoneFilter.all_except('eth0'))
    '*!eth0'
    >>> str(ZoneFilter.all_except())
    '*'
    """

    __slots__ = ('_complement', '_zones', '__weakref__')

    def __init__(self, complement, zones):
        """Constructor.  Prefer :meth:`only` and :meth:`all_except`."""
        self._complement = bool(complement)
        self._zones = frozenset(zones)

    @classmethod
    def only(cls, *zones):
        """A filter matching exactly the given zone identities.

        ``ZoneFilter.only(None)`` matches zoneless addresses only.
        """
        return cls(False, [_normalize_filter_zone(zone) for zone in zones])

    @classmethod
    def all_except(cls, *zones):
        """A filter matching every zone identity except the given ones.

        With no arguments this is the wildcard filter (``*``).
        """
        return cls(True, [_normalize_filter_zone(zone) for zone in zones])

    @property
    def is_empty(self):
        """``True`` if this filter matches no zone identity at all."""
        return not self._complement and not self._zones

    @property
    def is_wildcard(self):
        """``True`` if this filter matches every zone identity."""
        return self._complement and not self._zones

    @property
    def is_unscoped(self):
        """``True`` if this filter matches only the no-zone identity."""
        return not self._complement and self._zones == frozenset([None])

    def __contains__(self, zone):
        """``True`` if the given zone identity is matched by this filter."""
        zone = _normalize_filter_zone(zone)
        if self._complement:
            return zone not in self._zones
        return zone in self._zones

    def issubset(self, other):
        """``True`` if every zone matched by this filter is in ``other``."""
        return (self - other).is_empty

    def __invert__(self):
        """The complement of this filter."""
        return ZoneFilter(not self._complement, self._zones)

    def __and__(self, other):
        if not isinstance(other, ZoneFilter):
            return NotImplemented
        if self._complement and other._complement:
            return ZoneFilter(True, self._zones | other._zones)
        if self._complement:
            return ZoneFilter(False, other._zones - self._zones)
        if other._complement:
            return ZoneFilter(False, self._zones - other._zones)
        return ZoneFilter(False, self._zones & other._zones)

    def __or__(self, other):
        if not isinstance(other, ZoneFilter):
            return NotImplemented
        if self._complement and other._complement:
            return ZoneFilter(True, self._zones & other._zones)
        if self._complement:
            return ZoneFilter(True, self._zones - other._zones)
        if other._complement:
            return ZoneFilter(True, other._zones - self._zones)
        return ZoneFilter(False, self._zones | other._zones)

    def __sub__(self, other):
        if not isinstance(other, ZoneFilter):
            return NotImplemented
        return self & ~other

    def sort_key(self):
        """A deterministic total ordering key for filters."""
        return (
            1 if self._complement else 0,
            tuple(sorted(_zone_member_sort_key(zone) for zone in self._zones)),
        )

    def __eq__(self, other):
        if not isinstance(other, ZoneFilter):
            return NotImplemented
        return self._complement == other._complement and self._zones == other._zones

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self._complement, self._zones))

    def __getstate__(self):
        return self._complement, self._zones

    def __setstate__(self, state):
        self._complement, self._zones = state

    def __str__(self):
        if self._complement:
            if not self._zones:
                return '*'
            members = sorted(self._zones, key=_zone_member_sort_key)
            return '*!' + ','.join(_spell_zone_member(zone) for zone in members)
        if not self._zones:
            return '(none)'
        members = sorted(self._zones, key=_zone_member_sort_key)
        return ','.join(_spell_zone_member(zone) for zone in members)

    def __repr__(self):
        members = ', '.join(
            repr(zone) for zone in sorted(self._zones, key=_zone_member_sort_key)
        )
        if self._complement:
            return 'ZoneFilter.all_except(%s)' % members
        return 'ZoneFilter.only(%s)' % members


def _parse_zone_filter(text):
    """Parse the zone filter syntax used in :class:`ScopedIPv6Set` elements.

    ``*`` is the wildcard, ``*!a,b`` excludes zones, ``a,b`` lists zones
    and ``~`` spells the no-zone identity.
    """
    if not text:
        raise AddrFormatError("missing zone identifier after '%'")
    if text == '*':
        return ZoneFilter.all_except()
    if text.startswith('*!'):
        return ZoneFilter.all_except(*[_parse_zone_member(t) for t in text[2:].split(',')])
    return ZoneFilter.only(*[_parse_zone_member(t) for t in text.split(',')])


def _parse_address_zone(text):
    """Parse the zone suffix of a single address or network."""
    if text == '*':
        return ANY_ZONE
    zone = _parse_zone_member(text)
    if zone is None:
        raise AddrFormatError(
            "'~' is not a valid zone on a single address; omit the "
            "'%' suffix for a zoneless address"
        )
    return zone


def _zone_to_filter(zone):
    """The singleton :class:`ZoneFilter` matching exactly ``zone``."""
    if zone is ANY_ZONE:
        return ZoneFilter.all_except()
    return ZoneFilter.only(zone)


class ScopedIPv6Address(object):
    """An individual IPv6 address with an optional zone (scope) identifier.

    The zone is the caller-provided stable identifier (typically an
    interface name such as ``eth0``) and is compared as an exact string;
    it is never resolved against system interfaces.  A zone is only
    accepted on link-local (``fe80::/10``) and multicast (``ff00::/8``)
    addresses.  The wildcard zone must be requested explicitly with
    :data:`ANY_ZONE` (text form ``%*``); a missing zone means "no zone"
    and does not match all interfaces.

    Identity, hashing, ordering and text form all follow the same rule:
    the address value plus the zone.

    >>> ScopedIPv6Address('fe80::1%eth0') == ScopedIPv6Address('fe80::1%eth1')
    False
    >>> ScopedIPv6Address('fe80::1%eth0') == ScopedIPv6Address('fe80::1')
    False
    >>> str(ScopedIPv6Address('fe80::1', zone=ANY_ZONE))
    'fe80::1%*'
    """

    __slots__ = ('_value', '_zone', '__weakref__')

    #: IP version of this address type.
    version = 6

    def __init__(self, addr, zone=None):
        """
        :param addr: an IPv6 address as a string (optionally with a
            ``%zone`` suffix), an unsigned integer, an `IPAddress` or
            another `ScopedIPv6Address` (copy construction).

        :param zone: (optional) a zone identifier string, a non-negative
            integer interface index, or :data:`ANY_ZONE` for the wildcard.
        """
        parsed_zone = None

        if isinstance(addr, ScopedIPv6Address):
            value = addr._value
            parsed_zone = addr._zone
        elif isinstance(addr, IPAddress):
            if addr.version != 6:
                raise ValueError('only IPv6 addresses can be scoped')
            value = int(addr)
        elif isinstance(addr, bool):
            raise TypeError('bool is not a valid IPv6 address')
        elif isinstance(addr, int):
            if not 0 <= addr <= _ipv6.max_int:
                raise AddrFormatError('value out of bounds for an IPv6 address!')
            value = addr
        elif isinstance(addr, str):
            addr_part, sep, zone_text = addr.partition('%')
            try:
                value = _ipv6.str_to_int(addr_part)
            except AddrFormatError:
                raise AddrFormatError('%r is not a valid IPv6 address string!' % (addr,))
            if sep:
                parsed_zone = _parse_address_zone(zone_text)
        else:
            raise TypeError('unsupported address type: %s' % type(addr))

        if zone is not None:
            zone = _normalize_zone(zone)
            if parsed_zone is not None:
                raise ValueError('zone specified both in address and zone argument')
        self._zone = zone if zone is not None else parsed_zone
        self._value = value

        if self._zone is not None and not _is_scopable(self._value):
            raise AddrFormatError(_SCOPE_ERROR)

    @property
    def value(self):
        """The unsigned integer value of this IPv6 address."""
        return self._value

    @property
    def zone(self):
        """The zone identifier: a string, :data:`ANY_ZONE`, or ``None``."""
        return self._zone

    @property
    def ip(self):
        """This address as a plain (zoneless) `IPAddress` object."""
        return IPAddress(self._value, 6)

    def is_link_local(self):
        """``True`` if this address is link-local (fe80::/10)."""
        return _LINK_LOCAL_FIRST <= self._value <= _LINK_LOCAL_LAST

    def is_multicast(self):
        """``True`` if this address is multicast (ff00::/8)."""
        return _MULTICAST_FIRST <= self._value <= _MULTICAST_LAST

    def key(self):
        """:return: a key tuple that uniquely identifies this address."""
        return (6, self._value, _zone_identity_key(self._zone))

    def sort_key(self):
        """:return: a key tuple used to compare and sort addresses.

        Ordering is by address value, then zone: no zone sorts before
        named zones (ordered by name), the wildcard zone sorts last.
        """
        return self.key()

    def __hash__(self):
        return hash(self.key())

    def __eq__(self, other):
        if not isinstance(other, ScopedIPv6Address):
            return NotImplemented
        return self.key() == other.key()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __lt__(self, other):
        if not isinstance(other, ScopedIPv6Address):
            return NotImplemented
        return self.sort_key() < other.sort_key()

    def __le__(self, other):
        if not isinstance(other, ScopedIPv6Address):
            return NotImplemented
        return self.sort_key() <= other.sort_key()

    def __gt__(self, other):
        if not isinstance(other, ScopedIPv6Address):
            return NotImplemented
        return self.sort_key() > other.sort_key()

    def __ge__(self, other):
        if not isinstance(other, ScopedIPv6Address):
            return NotImplemented
        return self.sort_key() >= other.sort_key()

    def __int__(self):
        return self._value

    def __index__(self):
        return self._value

    def __getstate__(self):
        return self._value, self._zone

    def __setstate__(self, state):
        self._value, self._zone = state

    def __str__(self):
        text = _ipv6.int_to_str(self._value)
        if self._zone is None:
            return text
        return '%s%%%s' % (text, self._zone)

    def __repr__(self):
        return "%s('%s')" % (self.__class__.__name__, self)


class ScopedIPv6Network(object):
    """An IPv6 network range with an optional zone (scope) identifier.

    The same zone rules as :class:`ScopedIPv6Address` apply: zones are
    caller-provided identifiers compared as strings, are only allowed
    when the whole range lies within ``fe80::/10`` or ``ff00::/8``, and
    the wildcard is only available via the explicit :data:`ANY_ZONE`
    object (text form ``%*``).

    >>> str(ScopedIPv6Network('fe80::/10%eth0'))
    'fe80::/10%eth0'
    >>> ScopedIPv6Network('fe80::/64', zone=ANY_ZONE).zone is ANY_ZONE
    True
    """

    __slots__ = ('_first', '_last', '_prefixlen', '_zone', '__weakref__')

    #: IP version of this network type.
    version = 6

    def __init__(self, addr, zone=None):
        """
        :param addr: an IPv6 network as a string (optionally with a
            ``%zone`` suffix) or a `ScopedIPv6Address` (a /128 network).

        :param zone: (optional) a zone identifier string, a non-negative
            integer interface index, or :data:`ANY_ZONE` for the wildcard.
        """
        parsed_zone = None

        if isinstance(addr, ScopedIPv6Address):
            first = last = addr._value
            prefixlen = 128
            parsed_zone = addr._zone
        elif isinstance(addr, str):
            addr_part, sep, zone_text = addr.partition('%')
            try:
                network = IPNetwork(addr_part, version=6)
            except AddrFormatError:
                raise AddrFormatError('%r is not a valid IPv6 network string!' % (addr,))
            first, last, prefixlen = network.first, network.last, network.prefixlen
            if sep:
                parsed_zone = _parse_address_zone(zone_text)
        else:
            raise TypeError('unsupported network type: %s' % type(addr))

        if zone is not None:
            zone = _normalize_zone(zone)
            if parsed_zone is not None:
                raise ValueError('zone specified both in address and zone argument')
        self._zone = zone if zone is not None else parsed_zone
        self._first = first
        self._last = last
        self._prefixlen = prefixlen

        if self._zone is not None and not _range_scopable(self._first, self._last):
            raise AddrFormatError(_SCOPE_ERROR)

    @property
    def first(self):
        """The integer value of the first address in this network."""
        return self._first

    @property
    def last(self):
        """The integer value of the last address in this network."""
        return self._last

    @property
    def prefixlen(self):
        """The CIDR prefix length of this network."""
        return self._prefixlen

    @property
    def zone(self):
        """The zone identifier: a string, :data:`ANY_ZONE`, or ``None``."""
        return self._zone

    def key(self):
        """:return: a key tuple that uniquely identifies this network."""
        return (6, self._first, self._prefixlen, _zone_identity_key(self._zone))

    def sort_key(self):
        """:return: a key tuple used to compare and sort networks."""
        return self.key()

    def __hash__(self):
        return hash(self.key())

    def __eq__(self, other):
        if not isinstance(other, ScopedIPv6Network):
            return NotImplemented
        return self.key() == other.key()

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __lt__(self, other):
        if not isinstance(other, ScopedIPv6Network):
            return NotImplemented
        return self.sort_key() < other.sort_key()

    def __le__(self, other):
        if not isinstance(other, ScopedIPv6Network):
            return NotImplemented
        return self.sort_key() <= other.sort_key()

    def __gt__(self, other):
        if not isinstance(other, ScopedIPv6Network):
            return NotImplemented
        return self.sort_key() > other.sort_key()

    def __ge__(self, other):
        if not isinstance(other, ScopedIPv6Network):
            return NotImplemented
        return self.sort_key() >= other.sort_key()

    def __getstate__(self):
        return self._first, self._last, self._prefixlen, self._zone

    def __setstate__(self, state):
        self._first, self._last, self._prefixlen, self._zone = state

    def __str__(self):
        text = _ipv6.int_to_str(self._first)
        if self._prefixlen != 128:
            text = '%s/%d' % (text, self._prefixlen)
        if self._zone is None:
            return text
        return '%s%%%s' % (text, self._zone)

    def __repr__(self):
        return "%s('%s')" % (self.__class__.__name__, self)


# -----------------------------------------------------------------------------
#   Internal helpers for sorted, disjoint, inclusive integer ranges.
# -----------------------------------------------------------------------------


def _normalize_ranges(ranges):
    """Sort and merge overlapping or adjacent (first, last) ranges."""
    merged = []
    for first, last in sorted(ranges):
        if merged and first <= merged[-1][1] + 1:
            if last > merged[-1][1]:
                merged[-1][1] = last
        else:
            merged.append([first, last])
    return tuple((first, last) for first, last in merged)


def _intersect_ranges(ranges_a, ranges_b):
    """Intersection of two normalized range tuples."""
    result = []
    idx_a = idx_b = 0
    while idx_a < len(ranges_a) and idx_b < len(ranges_b):
        first_a, last_a = ranges_a[idx_a]
        first_b, last_b = ranges_b[idx_b]
        low, high = max(first_a, first_b), min(last_a, last_b)
        if low <= high:
            result.append((low, high))
        if last_a < last_b:
            idx_a += 1
        else:
            idx_b += 1
    return tuple(result)


def _subtract_ranges(ranges_a, ranges_b):
    """``ranges_a`` minus ``ranges_b``, both normalized range tuples."""
    result = []
    for first, last in ranges_a:
        current = first
        for other_first, other_last in ranges_b:
            if other_last < current:
                continue
            if other_first > last:
                break
            if other_first > current:
                result.append((current, other_first - 1))
            current = other_last + 1
            if current > last:
                break
        if current <= last:
            result.append((current, last))
    return tuple(result)


def _ranges_contain(ranges, value):
    """``True`` if value lies within one of the normalized ranges."""
    for first, last in ranges:
        if first <= value <= last:
            return True
    return False


def _atomize(filters):
    """Split filters into a list of pairwise disjoint ZoneFilters.

    Every original filter is exactly covered by a subset of the returned
    atoms.
    """
    atoms = []
    for zone_filter in filters:
        remainder = zone_filter
        new_atoms = []
        for atom in atoms:
            intersection = atom & zone_filter
            if not intersection.is_empty:
                new_atoms.append(intersection)
            rest = atom - zone_filter
            if not rest.is_empty:
                new_atoms.append(rest)
            remainder = remainder - atom
        if not remainder.is_empty:
            new_atoms.append(remainder)
        atoms = new_atoms
    return atoms


def _ranges_covering(parts, atom):
    """Merged ranges of all parts whose filter covers the given atom."""
    ranges = []
    for zone_filter, part_ranges in parts:
        if atom.issubset(zone_filter):
            ranges.extend(part_ranges)
    return _normalize_ranges(ranges)


def _build_parts(filter_ranges):
    """Build the canonical parts tuple from (ZoneFilter, ranges) pairs.

    The canonical form is a tuple of (ZoneFilter, ranges) sorted by filter
    where the filters are pairwise disjoint and maximal: two entries never
    share both an overlapping zone and identical ranges.  Semantically
    equal sets therefore always reduce to the same canonical form, which
    is what equality, hashing and the text representation rely on.
    """
    entries = []
    for zone_filter, ranges in filter_ranges:
        normalized = _normalize_ranges(ranges)
        if zone_filter.is_empty or not normalized:
            continue
        entries.append((zone_filter, normalized))
    if not entries:
        return ()

    grouped = {}
    for atom in _atomize([zone_filter for zone_filter, _ in entries]):
        ranges = _ranges_covering(entries, atom)
        if ranges:
            grouped.setdefault(ranges, []).append(atom)

    parts = []
    for ranges, atoms in grouped.items():
        zone_filter = atoms[0]
        for atom in atoms[1:]:
            zone_filter = zone_filter | atom
        parts.append((zone_filter, ranges))
    parts.sort(key=lambda part: part[0].sort_key())
    return tuple(parts)


def _parse_set_element(item):
    """Normalize a set element to a (ZoneFilter, (first, last)) pair."""
    if isinstance(item, ScopedIPv6Address):
        zone_filter = _zone_to_filter(item._zone)
        first = last = item._value
    elif isinstance(item, ScopedIPv6Network):
        zone_filter = _zone_to_filter(item._zone)
        first, last = item._first, item._last
    elif isinstance(item, str):
        addr_part, sep, zone_text = item.partition('%')
        zone_filter = _parse_zone_filter(zone_text) if sep else ZoneFilter.only(None)
        if '/' in addr_part:
            try:
                network = IPNetwork(addr_part, version=6)
            except AddrFormatError:
                raise AddrFormatError('%r is not a valid IPv6 network string!' % (item,))
            first, last = network.first, network.last
        else:
            try:
                first = last = _ipv6.str_to_int(addr_part)
            except AddrFormatError:
                raise AddrFormatError('%r is not a valid IPv6 address string!' % (item,))
    else:
        raise TypeError('unsupported scoped set element type: %s' % type(item))

    if not zone_filter.is_unscoped and not _range_scopable(first, last):
        raise AddrFormatError(_SCOPE_ERROR)
    return zone_filter, (first, last)


def _filter_suffixes(zone_filter):
    """Text zone suffixes under which a range of a part is listed."""
    if zone_filter._complement:
        return ['%' + str(zone_filter)]
    return [
        '' if zone is None else '%' + zone
        for zone in sorted(zone_filter._zones, key=_zone_member_sort_key)
    ]


class ScopedIPv6Set(object):
    """A set of scoped IPv6 addresses and ranges with zone-aware algebra.

    Elements are :class:`ScopedIPv6Address` or :class:`ScopedIPv6Network`
    objects, or strings such as ``'fe80::1%eth0'``, ``'fe80::/10%*'`` or
    a plain (zoneless) ``'2001:db8::1'``.  Intersection, union and
    difference are computed over both the address ranges and the zones.

    The wildcard zone only ever comes from the explicit :data:`ANY_ZONE`
    object (text form ``%*``); a zoneless element matches only zoneless
    addresses.  Subtracting a concrete zone from a wildcard produces an
    explicit "all zones except ..." remainder, spelled ``%*!eth0``:

    >>> remaining = ScopedIPv6Set(['fe80::/10%*']) - ScopedIPv6Set(['fe80::1%eth0'])
    >>> 'fe80::/10%*!eth0' in remaining.to_list()
    True
    >>> ScopedIPv6Address('fe80::1%eth1') in remaining
    True
    >>> ScopedIPv6Address('fe80::1%eth0') in remaining
    False
    """

    __slots__ = ('_parts', '__weakref__')

    def __init__(self, iterable=None):
        """
        :param iterable: (optional) a single element or an iterable of
            elements: `ScopedIPv6Address`, `ScopedIPv6Network` or strings
            such as ``'fe80::1%eth0'``, ``'fe80::/10%*'`` or
            ``'2001:db8::1'``.  Another `ScopedIPv6Set` is copied.
        """
        if isinstance(iterable, ScopedIPv6Set):
            self._parts = iterable._parts
            return
        if iterable is None:
            items = []
        elif isinstance(iterable, (str, ScopedIPv6Address, ScopedIPv6Network)):
            items = [iterable]
        else:
            items = list(iterable)
        self._parts = _build_parts(
            [(zone_filter, [span]) for zone_filter, span in map(_parse_set_element, items)]
        )

    @classmethod
    def _from_parts(cls, parts):
        """Wrap an already canonical parts tuple without reprocessing."""
        instance = cls.__new__(cls)
        instance._parts = parts
        return instance

    def _combine(self, other, operation):
        if not isinstance(other, ScopedIPv6Set):
            return NotImplemented
        filters = [zone_filter for zone_filter, _ in self._parts + other._parts]
        combined = []
        for atom in _atomize(filters):
            ranges_a = _ranges_covering(self._parts, atom)
            ranges_b = _ranges_covering(other._parts, atom)
            if operation == 'union':
                ranges = _normalize_ranges(list(ranges_a) + list(ranges_b))
            elif operation == 'intersection':
                ranges = _intersect_ranges(ranges_a, ranges_b)
            else:
                ranges = _subtract_ranges(ranges_a, ranges_b)
            if ranges:
                combined.append((atom, ranges))
        return ScopedIPv6Set._from_parts(_build_parts(combined))

    def union(self, other):
        """All addresses and zones present in either set."""
        return self._combine(other, 'union')

    def intersection(self, other):
        """Only addresses and zones present in both sets."""
        return self._combine(other, 'intersection')

    def difference(self, other):
        """The addresses and zones of this set not present in ``other``."""
        return self._combine(other, 'difference')

    def symmetric_difference(self, other):
        """The addresses and zones present in exactly one of the sets."""
        return (self - other) | (other - self)

    __or__ = union
    __and__ = intersection
    __sub__ = difference
    __xor__ = symmetric_difference

    def issubset(self, other):
        """``True`` if every element of this set is also in ``other``."""
        return (self - other).is_empty

    def issuperset(self, other):
        """``True`` if every element of ``other`` is also in this set."""
        return (other - self).is_empty

    def add(self, item):
        """Add a single element to this set (in place)."""
        self._parts = (self | ScopedIPv6Set(item))._parts

    def discard(self, item):
        """Remove a single element from this set (in place) if present."""
        self._parts = (self - ScopedIPv6Set(item))._parts

    def copy(self):
        """Return a shallow copy of this set."""
        return ScopedIPv6Set(self)

    @property
    def is_empty(self):
        """``True`` if this set contains no addresses at all."""
        return not self._parts

    def __bool__(self):
        return not self.is_empty

    def __contains__(self, item):
        """``True`` if a scoped address is a member of this set.

        A wildcard-zoned address is a member only if the set covers its
        value for *every* zone.
        """
        if isinstance(item, str):
            item = ScopedIPv6Address(item)
        if not isinstance(item, ScopedIPv6Address):
            return False
        covering = None
        for zone_filter, ranges in self._parts:
            if _ranges_contain(ranges, item._value):
                covering = zone_filter if covering is None else covering | zone_filter
        if covering is None:
            return False
        if item._zone is ANY_ZONE:
            return covering.is_wildcard
        return item._zone in covering

    def to_list(self):
        """A sorted list of canonical text elements rebuilding this set.

        ``ScopedIPv6Set(s.to_list()) == s`` holds for every set.
        """
        elements = []
        for zone_filter, ranges in self._parts:
            for first, last in ranges:
                cidrs = iprange_to_cidrs(IPAddress(first, 6), IPAddress(last, 6))
                for cidr in cidrs:
                    base = _ipv6.int_to_str(cidr.first)
                    if cidr.prefixlen != 128:
                        base = '%s/%d' % (base, cidr.prefixlen)
                    for suffix in _filter_suffixes(zone_filter):
                        elements.append(base + suffix)
        return sorted(elements)

    def __eq__(self, other):
        if not isinstance(other, ScopedIPv6Set):
            return NotImplemented
        return self._parts == other._parts

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash(self._parts)

    def __getstate__(self):
        return (self._parts,)

    def __setstate__(self, state):
        (self._parts,) = state

    def __str__(self):
        return ', '.join(self.to_list())

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self.to_list())

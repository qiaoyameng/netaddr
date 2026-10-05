"""Scoped (zone-indexed) IPv6 addresses, networks and sets.

This module models IPv6 addresses that carry a *zone* (the ``%eth0``
suffix in ``fe80::1%eth0``, also known as a scope id) as first-class
values.  The motivating use case is a collector reading several
interfaces at once: ``fe80::1%eth0`` and ``fe80::1%eth1`` must not be
treated as the same address.  The new types are kept separate from
:class:`netaddr.IPAddress`, whose scope-less equality rules are left
unchanged.

Design rules:

-   A zone is identified by a caller-supplied, stable identifier string
    (for example an interface name such as ``'eth0'``).  Identifiers are
    compared as opaque strings; the library never resolves them against
    the operating system's interface list.
-   A wildcard zone (matching every interface) only exists when
    explicitly requested via the :data:`ANY_ZONE` singleton (text form
    ``*``).  An address or network without a zone is *unscoped* and does
    not implicitly match scoped addresses on any interface.
-   Zones are only permitted where they are meaningful: link-local
    unicast addresses (``fe80::/10``) and multicast addresses with
    interface-local or link-local scope (``ff01::/16`` and
    ``ff02::/16``).  Attaching a zone to any other address (for example
    a global unicast address) raises :class:`AddrFormatError`.
-   Equality, hashing, ordering and the text representation all follow
    the same identity: the address value combined with the zone.

>>> fe80_eth0 = ScopedIPv6Address('fe80::1%eth0')
>>> fe80_eth1 = ScopedIPv6Address('fe80::1%eth1')
>>> fe80_eth0 == fe80_eth1
False
>>> any_link = ScopedIPv6Network('fe80::/64%*')
>>> fe80_eth0 in any_link and fe80_eth1 in any_link
True
>>> rest = any_link - ScopedIPv6Network('fe80::/64%eth0')
>>> print(list(rest)[0])
fe80::/64%*!eth0
>>> fe80_eth0 in rest or fe80_eth1 not in rest
False
"""

from netaddr.core import AddrFormatError
from netaddr.ip import IPAddress, IPNetwork, cidr_exclude, cidr_merge

__all__ = [
    'ANY_ZONE',
    'ScopedIPSet',
    'ScopedIPv6Address',
    'ScopedIPv6Network',
    'Zone',
]


class Zone(object):
    """
    A concrete IPv6 zone identified by a caller-supplied stable string.

    The identifier is an opaque token (typically an interface name such
    as ``'eth0'``).  Zones are compared by identifier only; no attempt
    is made to resolve the identifier against system interfaces.
    """

    __slots__ = ('_identifier',)

    #: Characters that may not appear in a zone identifier because they
    #: are used as separators in the text representation.
    _RESERVED_CHARS = frozenset('%!/')

    def __init__(self, identifier):
        if not isinstance(identifier, str):
            raise TypeError(
                'zone identifier must be a string, not %s' % type(identifier).__name__
            )
        if not identifier:
            raise ValueError('zone identifier must not be empty')
        if identifier == '*':
            raise ValueError("'*' is reserved for the ANY_ZONE wildcard zone")
        invalid = self._RESERVED_CHARS.intersection(identifier)
        if invalid:
            raise ValueError(
                'zone identifier %r contains reserved character(s): %s'
                % (identifier, ', '.join(sorted(invalid)))
            )
        self._identifier = identifier

    @property
    def identifier(self):
        """The caller-supplied stable identifier string of this zone."""
        return self._identifier

    def key(self):
        """:return: a key tuple that uniquely identifies this zone."""
        return (2, self._identifier)

    def __hash__(self):
        return hash(self.key())

    def __eq__(self, other):
        if isinstance(other, Zone):
            return self._identifier == other._identifier
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __lt__(self, other):
        try:
            return self.key() < other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __le__(self, other):
        try:
            return self.key() <= other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __gt__(self, other):
        try:
            return self.key() > other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __ge__(self, other):
        try:
            return self.key() >= other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __str__(self):
        return self._identifier

    def __repr__(self):
        return 'Zone(%r)' % self._identifier


class _AnyZone(object):
    """Type of the :data:`ANY_ZONE` wildcard zone singleton."""

    __slots__ = ()

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(_AnyZone, cls).__new__(cls)
        return cls._instance

    def key(self):
        """:return: a key tuple that uniquely identifies the wildcard zone."""
        return (1,)

    def __hash__(self):
        return hash(self.key())

    def __eq__(self, other):
        if isinstance(other, _AnyZone):
            return True
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __lt__(self, other):
        try:
            return self.key() < other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __le__(self, other):
        try:
            return self.key() <= other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __gt__(self, other):
        try:
            return self.key() > other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __ge__(self, other):
        try:
            return self.key() >= other.key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __str__(self):
        return '*'

    def __repr__(self):
        return 'ANY_ZONE'

    def __reduce__(self):
        return (_get_any_zone, ())


#: The explicit wildcard zone.  A network carrying this zone matches
#: addresses on *every* interface.  It only ever comes into play when
#: spelled out explicitly (``ANY_ZONE`` or the ``*`` text form); an
#: absent (``None``) zone never widens to match all interfaces.
ANY_ZONE = _AnyZone()


def _get_any_zone():
    """Unpickling helper returning the :data:`ANY_ZONE` singleton."""
    return ANY_ZONE


def _coerce_zone(zone):
    """Convert ``zone`` to a :class:`Zone`, :data:`ANY_ZONE` or ``None``."""
    if zone is None or zone is ANY_ZONE:
        return zone
    if isinstance(zone, Zone):
        return zone
    if isinstance(zone, str):
        if zone == '*':
            return ANY_ZONE
        return Zone(zone)
    raise TypeError('invalid zone: %r' % (zone,))


def _zone_key(zone):
    """Sort/identity key for an optional zone (``None`` sorts lowest)."""
    if zone is None:
        return (0,)
    return zone.key()


def _parse_zone_text(text):
    """
    Parse the zone portion of the scoped text representation.

    :return: a ``(zone, excluded_zones)`` tuple where ``zone`` is a
        :class:`Zone` or :data:`ANY_ZONE` and ``excluded_zones`` is a
        frozenset of :class:`Zone` objects (only allowed alongside the
        wildcard zone).
    """
    parts = text.split('!')
    head = parts[0]
    zone = ANY_ZONE if head == '*' else Zone(head)
    excluded_names = parts[1:]
    excluded = frozenset(Zone(name) for name in excluded_names)
    if excluded:
        if zone is not ANY_ZONE:
            raise AddrFormatError('excluded zones require the wildcard zone: %r' % text)
        if len(excluded) != len(excluded_names):
            raise AddrFormatError('duplicate excluded zone in: %r' % text)
    return zone, excluded


#: link-local unicast block (fe80::/10), the primary zone-scoped space.
_LINK_LOCAL = IPNetwork('fe80::/10')

#: multicast scopes that may carry a zone: interface-local, link-local.
_ZONE_SCOPED_MULTICAST_SCOPES = frozenset((0x1, 0x2))


def _multicast_scope(value):
    """:return: the multicast scope nibble of an IPv6 value, or None."""
    if value >> 120 != 0xFF:
        return None
    return (value >> 112) & 0xF


def _address_allows_zone(value):
    """:return: True if an IPv6 address value may carry a zone."""
    if _LINK_LOCAL.first <= value <= _LINK_LOCAL.last:
        return True
    return _multicast_scope(value) in _ZONE_SCOPED_MULTICAST_SCOPES


def _network_allows_zone(network):
    """:return: True if every address of an IPv6 network may carry a zone."""
    if _LINK_LOCAL.first <= network.first and network.last <= _LINK_LOCAL.last:
        return True
    #   Multicast: the network must not straddle a scope boundary, so
    #   the top 16 bits (0xff + flags + scope) must be uniform.
    return (network.first >> 112) == (network.last >> 112) and _multicast_scope(
        network.first
    ) in _ZONE_SCOPED_MULTICAST_SCOPES


def _zone_set_contains(zone1, excluded1, zone2, excluded2):
    """
    :return: True if every zone matched by ``(zone2, excluded2)`` is
        also matched by ``(zone1, excluded1)``.
    """
    if zone1 is None:
        return zone2 is None
    if zone1 is ANY_ZONE:
        if zone2 is None:
            return False
        if zone2 is ANY_ZONE:
            return excluded1 <= excluded2
        return zone2 not in excluded1
    #   zone1 is a concrete zone.
    return zone2 == zone1


def _zone_intersection(zone1, excluded1, zone2, excluded2):
    """
    Intersect two zone sets.

    :return: a ``(zone, excluded_zones)`` tuple describing the shared
        zones, or None if the zone sets are disjoint.
    """
    if zone1 is None or zone2 is None:
        if zone1 is None and zone2 is None:
            return None, frozenset()
        return None
    if zone1 is ANY_ZONE and zone2 is ANY_ZONE:
        return ANY_ZONE, excluded1 | excluded2
    if zone1 is ANY_ZONE:
        if zone2 in excluded1:
            return None
        return zone2, frozenset()
    if zone2 is ANY_ZONE:
        if zone1 in excluded2:
            return None
        return zone1, frozenset()
    if zone1 == zone2:
        return zone1, frozenset()
    return None


class ScopedIPv6Address(object):
    """
    An IPv6 address combined with an optional zone.

    Identity (equality, hashing, ordering and text form) is the pair of
    the address value and the zone: ``fe80::1%eth0`` and ``fe80::1%eth1``
    are different addresses, and both differ from the unscoped
    ``fe80::1``.  A scoped address is never equal to a plain
    :class:`netaddr.IPAddress`.
    """

    __slots__ = ('_ip', '_zone')

    def __init__(self, addr, zone=None):
        """
        Constructor.

        :param addr: an IPv6 address, optionally with a ``%zone`` suffix
            (e.g. ``'fe80::1%eth0'`` or ``'fe80::1%*'``), an
            :class:`IPAddress` or another `ScopedIPv6Address` (copy
            construction).

        :param zone: (optional) the zone as a string identifier, a
            :class:`Zone`, :data:`ANY_ZONE` or None (unscoped, the
            default).  An absent zone never matches all interfaces.
        """
        if isinstance(addr, ScopedIPv6Address):
            if zone is None:
                self._ip = addr._ip
                self._zone = addr._zone
                return
            addr = addr._ip
        if isinstance(addr, str):
            addr_part, sep, zone_part = addr.partition('%')
            if sep:
                if zone is not None:
                    raise AddrFormatError('zone specified twice: %r' % addr)
                zone, excluded = _parse_zone_text(zone_part)
                if excluded:
                    raise AddrFormatError(
                        'excluded zones are not valid on a single address: %r' % addr
                    )
                addr = addr_part
        ip = addr if isinstance(addr, IPAddress) else IPAddress(addr, version=6)
        if ip.version != 6:
            raise AddrFormatError('not an IPv6 address: %r' % (addr,))
        zone = _coerce_zone(zone)
        if zone is not None and not _address_allows_zone(ip.value):
            raise AddrFormatError('zone not permitted on IPv6 address: %s' % ip)
        self._ip = ip
        self._zone = zone

    @property
    def ip(self):
        """The underlying unscoped :class:`netaddr.IPAddress`."""
        return self._ip

    @property
    def zone(self):
        """The zone: a :class:`Zone`, :data:`ANY_ZONE` or None."""
        return self._zone

    @property
    def is_scoped(self):
        """True if this address carries a zone (concrete or wildcard)."""
        return self._zone is not None

    @property
    def value(self):
        """The integer value of the underlying IPv6 address."""
        return self._ip.value

    version = 6

    def key(self):
        """:return: a key tuple that uniquely identifies this address."""
        return (6, self._ip.value, _zone_key(self._zone))

    def sort_key(self):
        """:return: a key tuple used to compare and sort this address."""
        return (6, self._ip.value, self._ip.value, _zone_key(self._zone), ())

    def __hash__(self):
        return hash(self.key())

    def __eq__(self, other):
        if isinstance(other, ScopedIPv6Address):
            return self.key() == other.key()
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __lt__(self, other):
        try:
            return self.sort_key() < other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __le__(self, other):
        try:
            return self.sort_key() <= other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __gt__(self, other):
        try:
            return self.sort_key() > other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __ge__(self, other):
        try:
            return self.sort_key() >= other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __int__(self):
        return self._ip.value

    def __str__(self):
        if self._zone is None:
            return str(self._ip)
        return '%s%%%s' % (self._ip, self._zone)

    def __repr__(self):
        return "%s('%s')" % (self.__class__.__name__, self)


class ScopedIPv6Network(object):
    """
    An IPv6 network combined with an optional zone.

    Besides a concrete zone or no zone, a network may carry the explicit
    :data:`ANY_ZONE` wildcard (text form ``*``), optionally with a set of
    *excluded zones* (text form ``fe80::/64%*!eth0``) which is how the
    remainder of "wildcard range minus one interface" is represented.
    """

    __slots__ = ('_network', '_zone', '_excluded_zones')

    def __init__(self, addr, zone=None, excluded_zones=()):
        """
        Constructor.

        :param addr: an IPv6 network, optionally with a ``%zone`` suffix
            (e.g. ``'fe80::/64%eth0'``, ``'fe80::/64%*'`` or
            ``'fe80::/64%*!eth0'``), an :class:`IPNetwork`, a
            `ScopedIPv6Address` (turned into a /128) or another
            `ScopedIPv6Network` (copy construction).

        :param zone: (optional) the zone as a string identifier, a
            :class:`Zone`, :data:`ANY_ZONE` or None (unscoped, the
            default).  An absent zone never matches all interfaces.

        :param excluded_zones: (optional) iterable of zones excluded
            from the wildcard zone; only valid together with
            :data:`ANY_ZONE`.
        """
        if isinstance(addr, ScopedIPv6Network):
            if zone is None and not excluded_zones:
                self._network = addr._network
                self._zone = addr._zone
                self._excluded_zones = addr._excluded_zones
                return
            addr = addr._network
        if isinstance(addr, ScopedIPv6Address):
            if zone is None:
                zone = addr.zone
            addr = IPNetwork('%s/128' % addr.ip)
        if isinstance(addr, str):
            net_part, sep, zone_part = addr.partition('%')
            if sep:
                if zone is not None:
                    raise AddrFormatError('zone specified twice: %r' % addr)
                zone, parsed_excluded = _parse_zone_text(zone_part)
                if excluded_zones:
                    raise AddrFormatError('excluded zones specified twice: %r' % addr)
                excluded_zones = parsed_excluded
                addr = net_part
        network = addr if isinstance(addr, IPNetwork) else IPNetwork(addr, version=6)
        if network.version != 6:
            raise AddrFormatError('not an IPv6 network: %r' % (addr,))
        zone = _coerce_zone(zone)
        excluded = frozenset(_coerce_zone(z) for z in excluded_zones)
        if excluded:
            if zone is not ANY_ZONE:
                raise ValueError('excluded zones require the ANY_ZONE wildcard zone')
            if ANY_ZONE in excluded:
                raise ValueError('the wildcard zone cannot be an excluded zone')
        if zone is not None and not _network_allows_zone(network):
            raise AddrFormatError('zone not permitted on IPv6 network: %s' % network)
        self._network = network
        self._zone = zone
        self._excluded_zones = excluded

    @property
    def network(self):
        """The underlying unscoped :class:`netaddr.IPNetwork`."""
        return self._network

    @property
    def zone(self):
        """The zone: a :class:`Zone`, :data:`ANY_ZONE` or None."""
        return self._zone

    @property
    def excluded_zones(self):
        """Frozenset of :class:`Zone` objects excluded from the wildcard."""
        return self._excluded_zones

    @property
    def is_scoped(self):
        """True if this network carries a zone (concrete or wildcard)."""
        return self._zone is not None

    @property
    def prefixlen(self):
        """The prefix length of the underlying network."""
        return self._network.prefixlen

    @property
    def first(self):
        """The integer value of the first address of the network."""
        return self._network.first

    @property
    def last(self):
        """The integer value of the last address of the network."""
        return self._network.last

    version = 6

    def key(self):
        """:return: a key tuple that uniquely identifies this network."""
        excluded = tuple(sorted(z.identifier for z in self._excluded_zones))
        return (6, self.first, self.last, _zone_key(self._zone), excluded)

    def sort_key(self):
        """:return: a key tuple used to compare and sort this network."""
        return self.key()

    def __hash__(self):
        return hash(self.key())

    def __eq__(self, other):
        if isinstance(other, ScopedIPv6Network):
            return self.key() == other.key()
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __lt__(self, other):
        try:
            return self.sort_key() < other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __le__(self, other):
        try:
            return self.sort_key() <= other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __gt__(self, other):
        try:
            return self.sort_key() > other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __ge__(self, other):
        try:
            return self.sort_key() >= other.sort_key()
        except (AttributeError, TypeError):
            return NotImplemented

    def __contains__(self, other):
        """
        :param other: a `ScopedIPv6Address`, `ScopedIPv6Network`, plain
            :class:`IPAddress`/:class:`IPNetwork` or a string.

        :return: True if ``other`` is contained in this network, taking
            zones into account.  Unscoped addresses are only contained
            in unscoped networks; an absent zone never matches scoped
            addresses.
        """
        if isinstance(other, str):
            other = (
                ScopedIPv6Network(other)
                if '/' in other
                else ScopedIPv6Address(other)
            )
        if isinstance(other, ScopedIPv6Address):
            if other.ip not in self._network:
                return False
            return _zone_set_contains(
                self._zone, self._excluded_zones, other.zone, frozenset()
            )
        if isinstance(other, ScopedIPv6Network):
            if other._network not in self._network:
                return False
            return _zone_set_contains(
                self._zone, self._excluded_zones, other.zone, other.excluded_zones
            )
        if isinstance(other, (IPAddress, IPNetwork)):
            if self._zone is not None:
                return False
            return other in self._network
        return False

    def _intersect(self, other):
        """
        :return: a `ScopedIPv6Network` describing the overlap with
            ``other``, or None if the two are disjoint.
        """
        zone_info = _zone_intersection(
            self._zone, self._excluded_zones, other._zone, other._excluded_zones
        )
        if zone_info is None:
            return None
        if self.first > other.last or other.first > self.last:
            return None
        #   Overlapping CIDR blocks: one contains the other.
        if self.prefixlen >= other.prefixlen:
            network = self._network
        else:
            network = other._network
        return ScopedIPv6Network(network, zone_info[0], zone_info[1])

    def _difference_members(self, other):
        """
        :return: a list of `ScopedIPv6Network` objects covering
            ``self - other``.
        """
        inter = self._intersect(other)
        if inter is None:
            return [self]
        members = []
        #   Remainder outside the overlapping address range keeps the
        #   zone set of self.
        for network in cidr_exclude(self._network, inter._network):
            members.append(
                ScopedIPv6Network(network, self._zone, self._excluded_zones)
            )
        #   Remainder inside the overlapping address range, on the zones
        #   covered by self but not by other.  Only possible when self
        #   carries the wildcard zone.
        if self._zone is ANY_ZONE:
            if other._zone is ANY_ZONE:
                #   Zones other does not cover (its excluded zones) stay
                #   alive inside the overlap as concrete-zone networks.
                for zone in sorted(
                    other._excluded_zones - self._excluded_zones,
                    key=lambda z: z.identifier,
                ):
                    members.append(ScopedIPv6Network(inter._network, zone))
            else:
                #   other is a single concrete zone: carve it out of the
                #   wildcard, e.g. fe80::/64%* - fe80::/64%eth0 becomes
                #   fe80::/64%*!eth0.
                members.append(
                    ScopedIPv6Network(
                        inter._network,
                        ANY_ZONE,
                        self._excluded_zones | {other._zone},
                    )
                )
        return members

    def intersection(self, other):
        """:return: a `ScopedIPSet` of the overlap with ``other``."""
        return ScopedIPSet([self]) & other

    def union(self, other):
        """:return: a `ScopedIPSet` combining this network and ``other``."""
        return ScopedIPSet([self]) | other

    def difference(self, other):
        """:return: a `ScopedIPSet` of this network minus ``other``."""
        return ScopedIPSet([self]) - other

    def symmetric_difference(self, other):
        """:return: a `ScopedIPSet` of the non-overlapping parts."""
        return ScopedIPSet([self]) ^ other

    __and__ = intersection
    __or__ = union
    __sub__ = difference
    __xor__ = symmetric_difference

    def __str__(self):
        text = str(self._network)
        if self._zone is None:
            return text
        text += '%' + str(self._zone)
        for zone in sorted(self._excluded_zones, key=lambda z: z.identifier):
            text += '!' + zone.identifier
        return text

    def __repr__(self):
        return "%s('%s')" % (self.__class__.__name__, self)


def _as_scoped_network(obj):
    """Coerce ``obj`` to a `ScopedIPv6Network`."""
    if isinstance(obj, ScopedIPv6Network):
        return obj
    if isinstance(obj, (ScopedIPv6Address, str, IPNetwork, IPAddress)):
        return ScopedIPv6Network(obj)
    raise TypeError('cannot interpret %r as a scoped IPv6 network' % (obj,))


def _as_scoped_set(obj):
    """Coerce ``obj`` to a `ScopedIPSet`."""
    if isinstance(obj, ScopedIPSet):
        return obj
    if isinstance(obj, (ScopedIPv6Network, ScopedIPv6Address, str, IPNetwork, IPAddress)):
        return ScopedIPSet([obj])
    try:
        return ScopedIPSet(obj)
    except TypeError:
        raise TypeError('cannot interpret %r as a scoped IPv6 set' % (obj,))


def _merge_group(networks):
    """Merge the IPNetworks of a same-zone group via cidr_merge."""
    return [ScopedIPv6Network(n, networks[0]._zone, networks[0]._excluded_zones)
            for n in cidr_merge([n._network for n in networks])]


def _normalize(networks):
    """
    Normalize a list of `ScopedIPv6Network` objects: merge adjacent or
    overlapping networks that share a zone set, and fold concrete-zone
    networks back into wildcard networks by shrinking their exclusion
    lists (``fe80::/64%*!eth0`` plus ``fe80::/64%eth0`` becomes
    ``fe80::/64%*``).
    """
    networks = list(networks)
    while True:
        groups = {}
        for net in networks:
            groups.setdefault((net._zone, net._excluded_zones), []).append(net)
        merged = []
        for group in groups.values():
            merged.extend(_merge_group(group))

        by_zone = {}
        for index, net in enumerate(merged):
            if isinstance(net._zone, Zone):
                by_zone.setdefault(net._zone, []).append(index)

        consumed = set()
        result = []
        changed = False
        for net in merged:
            if net._zone is ANY_ZONE and net._excluded_zones:
                remaining = set(net._excluded_zones)
                for zone in list(remaining):
                    for index in by_zone.get(zone, ()):
                        if index not in consumed and merged[index]._network == net._network:
                            consumed.add(index)
                            remaining.discard(zone)
                            changed = True
                            break
                result.append(
                    ScopedIPv6Network(net._network, ANY_ZONE, frozenset(remaining))
                )
            else:
                result.append(net)
        networks = [net for index, net in enumerate(result) if index not in consumed]
        if not changed:
            break
    networks.sort(key=lambda n: n.sort_key())
    return networks


class ScopedIPSet(object):
    """
    A set of scoped IPv6 networks.

    Members are `ScopedIPv6Network` objects, normalized on construction.
    Iterating the set yields its member networks (iterating individual
    addresses is not possible in general: a wildcard-zone network spans
    an unknown set of interfaces).
    """

    __slots__ = ('_networks',)

    def __init__(self, iterable=None):
        """
        Constructor.

        :param iterable: a single scoped object or string, or an
            iterable of `ScopedIPv6Network`, `ScopedIPv6Address`,
            :class:`IPNetwork`, :class:`IPAddress` or strings.  Plain
            IP objects are treated as unscoped.
        """
        if iterable is None:
            networks = []
        elif isinstance(iterable, ScopedIPSet):
            networks = list(iterable._networks)
        elif isinstance(
            iterable, (ScopedIPv6Network, ScopedIPv6Address, str, IPNetwork, IPAddress)
        ):
            networks = [_as_scoped_network(iterable)]
        else:
            networks = [_as_scoped_network(item) for item in iterable]
        self._networks = _normalize(networks)

    def __contains__(self, other):
        """
        :param other: a `ScopedIPv6Address`, `ScopedIPv6Network`, plain
            IP object or string.

        :return: True if ``other`` is contained in a single member
            network of this set (zones included).
        """
        if isinstance(other, str):
            other = (
                ScopedIPv6Network(other)
                if '/' in other
                else ScopedIPv6Address(other)
            )
        return any(other in net for net in self._networks)

    def __bool__(self):
        return bool(self._networks)

    def __len__(self):
        """:return: the number of member networks in this set."""
        return len(self._networks)

    def __iter__(self):
        """Iterate over the member `ScopedIPv6Network` objects."""
        return iter(self._networks)

    def __hash__(self):
        return hash(tuple(self._networks))

    def __eq__(self, other):
        if isinstance(other, ScopedIPSet):
            return self._networks == other._networks
        return NotImplemented

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def isdisjoint(self, other):
        """:return: True if this set has no overlap with ``other``."""
        other = _as_scoped_set(other)
        return all(
            left._intersect(right) is None
            for left in self._networks
            for right in other._networks
        )

    def issubset(self, other):
        """:return: True if this set is fully contained in ``other``."""
        return not (self - other)

    def issuperset(self, other):
        """:return: True if ``other`` is fully contained in this set."""
        return _as_scoped_set(other).issubset(self)

    def union(self, other):
        """:return: a new `ScopedIPSet` combining this set and ``other``."""
        other = _as_scoped_set(other)
        return ScopedIPSet(self._networks + other._networks)

    def intersection(self, other):
        """:return: a new `ScopedIPSet` of the overlap with ``other``."""
        other = _as_scoped_set(other)
        members = []
        for left in self._networks:
            for right in other._networks:
                inter = left._intersect(right)
                if inter is not None:
                    members.append(inter)
        return ScopedIPSet(members)

    def difference(self, other):
        """:return: a new `ScopedIPSet` of this set minus ``other``."""
        other = _as_scoped_set(other)
        members = list(self._networks)
        for right in other._networks:
            members = [
                member
                for left in members
                for member in left._difference_members(right)
            ]
        return ScopedIPSet(members)

    def symmetric_difference(self, other):
        """:return: a new `ScopedIPSet` of the non-overlapping parts."""
        other = _as_scoped_set(other)
        return (self - other) | (other - self)

    __or__ = union
    __and__ = intersection
    __sub__ = difference
    __xor__ = symmetric_difference

    def __repr__(self):
        return '%s([%s])' % (
            self.__class__.__name__,
            ', '.join(repr(str(net)) for net in self._networks),
        )

# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""In-memory IP routing tables with longest-prefix-match lookups.

Forwarding rules (applied in this order):

1.  The most specific (longest) matching prefix wins.
2.  Within the winning prefix, entries with the lowest metric win.
3.  Entries with the same lowest metric form an ECMP set of next hops.
    Blackhole entries only take effect when no regular next hop exists
    at the winning metric.

Routes are recorded per *source* (e.g. a routing protocol or peer), so a
prefix may carry multiple independent records. Removing a source only
withdraws that source's records and never touches equivalent routes
contributed by other sources.

IPv4 and IPv6 routes are kept in separate lookup tries, so a lookup only
ever walks the bits of the queried address instead of scanning the table.

Both :meth:`RoutingTable.add` and :meth:`RoutingTable.remove` return the
minimal list of CIDR blocks whose forwarding result actually changed,
allowing callers to refresh derived state incrementally.
"""

from netaddr.core import AddrFormatError
from netaddr.ip import IPAddress, IPNetwork
from netaddr.ip.sets import IPSet

#: Source tag assigned to routes added without an explicit one.
DEFAULT_SOURCE = 'static'

_NO_ROUTE = ('no-route',)
_BLACKHOLE = ('blackhole',)


class RouteResult(object):
    """The outcome of a routing table lookup for a single address."""

    def __init__(self, prefix, metric, nexthops):
        self._prefix = prefix
        self._metric = metric
        self._nexthops = nexthops

    @property
    def prefix(self):
        """The winning (longest matching) :class:`IPNetwork`."""
        return self._prefix

    @property
    def metric(self):
        """The metric of the winning route entries."""
        return self._metric

    @property
    def nexthops(self):
        """A frozenset of ECMP next-hop :class:`IPAddress` objects, or
        ``None`` when the winning route is a blackhole."""
        return self._nexthops

    @property
    def is_blackhole(self):
        """``True`` when matching traffic is discarded."""
        return self._nexthops is None

    def __eq__(self, other):
        if not isinstance(other, RouteResult):
            return NotImplemented
        return (
            self._prefix == other._prefix
            and self._metric == other._metric
            and self._nexthops == other._nexthops
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __repr__(self):
        if self.is_blackhole:
            target = 'blackhole'
        else:
            target = ','.join(str(nh) for nh in sorted(self._nexthops))
        return '%s(%s, metric=%s, %s)' % (
            self.__class__.__name__,
            self._prefix,
            self._metric,
            target,
        )


class _Node(object):
    """A single node in a binary prefix trie."""

    __slots__ = ('child', 'entries')

    def __init__(self):
        self.child = [None, None]
        # Maps (source, nexthop_value) -> metric. A nexthop value of
        # None marks a blackhole entry.
        self.entries = {}


def _resolve(entries):
    """Reduce the entries of one prefix to a forwarding outcome.

    :return: (metric, key, nexthop_values) where *key* is a hashable
        forwarding-result token and *nexthop_values* is a frozenset of
        next-hop integers, or None for a blackhole.
    """
    metric = min(entries.values())
    winners = [nh for (src, nh), m in entries.items() if m == metric]
    nexthops = frozenset(nh for nh in winners if nh is not None)
    if nexthops:
        return metric, ('nexthops', nexthops), nexthops
    return metric, _BLACKHOLE, None


class _Trie(object):
    """A binary prefix trie for a single address family."""

    def __init__(self, version, width):
        self.version = version
        self.width = width
        self.root = _Node()
        self.size = 0

    def _cidr(self, value, depth):
        network = IPNetwork(IPAddress(value, version=self.version))
        network.prefixlen = depth
        return network.cidr

    def _descend(self, value, prefixlen, create=False):
        node = self.root
        depth = 0
        while depth < prefixlen:
            bit = (value >> (self.width - 1 - depth)) & 1
            child = node.child[bit]
            if child is None:
                if not create:
                    return None
                child = node.child[bit] = _Node()
            node = child
            depth += 1
        return node

    def _inherited_key(self, value, prefixlen):
        """Forwarding-result token in effect just above the given prefix."""
        key = _NO_ROUTE
        node = self.root
        if node.entries:
            key = _resolve(node.entries)[1]
        depth = 0
        while depth < prefixlen:
            bit = (value >> (self.width - 1 - depth)) & 1
            node = node.child[bit]
            if node is None:
                break
            depth += 1
            if depth < prefixlen and node.entries:
                key = _resolve(node.entries)[1]
        return key

    def _segments(self, node, value, depth, inherited, out):
        """Partition the subtree below (value, depth) into maximal regions
        that share one forwarding result."""
        if node.entries:
            key = _resolve(node.entries)[1]
        else:
            key = inherited
        if depth == self.width:
            out.append((self._cidr(value, depth), key))
            return
        for bit in (0, 1):
            child = node.child[bit]
            child_value = value | (bit << (self.width - 1 - depth))
            if child is None:
                out.append((self._cidr(child_value, depth + 1), key))
            else:
                self._segments(child, child_value, depth + 1, key, out)

    def lookup(self, value):
        """Longest-prefix-match lookup for an integer address value.

        :return: (prefix, metric, nexthop_values) or None when no route
            matches. Runs in O(address bits), independent of table size.
        """
        node = self.root
        best = None
        if node.entries:
            best = (0, node)
        depth = 0
        while depth < self.width:
            bit = (value >> (self.width - 1 - depth)) & 1
            node = node.child[bit]
            if node is None:
                break
            depth += 1
            if node.entries:
                best = (depth, node)
        if best is None:
            return None
        depth, node = best
        metric, _, nexthops = _resolve(node.entries)
        return self._cidr(value, depth), metric, nexthops

    def update(self, network, mutate):
        """Apply *mutate* to the entries of *network* and return the minimal
        list of CIDR blocks whose forwarding result changed."""
        network = network.cidr
        value = network.network.value
        prefixlen = network.prefixlen
        inherited = self._inherited_key(value, prefixlen)
        node = self._descend(value, prefixlen, create=True)
        before = []
        self._segments(node, value, prefixlen, inherited, before)
        entries_before = len(node.entries)
        mutate(node)
        self.size += len(node.entries) - entries_before
        after = []
        self._segments(node, value, prefixlen, inherited, after)
        return _changed_cidrs(before, after)


def _changed_cidrs(before, after):
    """Diff two (cidr, result-token) segmentations of the same address
    space and return the changed region as a minimal list of CIDRs."""

    def group(segments):
        grouped = {}
        for network, key in segments:
            grouped.setdefault(key, IPSet()).add(network)
        return grouped

    before_map = group(before)
    after_map = group(after)
    changed = IPSet()
    for key in set(before_map) | set(after_map):
        old = before_map.get(key, IPSet())
        new = after_map.get(key, IPSet())
        changed = changed | (old ^ new)
    return list(changed.iter_cidrs())


class RoutingTable(object):
    """An in-memory IPv4/IPv6 routing table.

    Routes for the two address families are stored independently; lookups
    are dispatched on the version of the queried address.
    """

    def __init__(self):
        self._tries = {
            4: _Trie(4, 32),
            6: _Trie(6, 128),
        }

    def __len__(self):
        """The total number of route entries in the table."""
        return sum(trie.size for trie in self._tries.values())

    def __contains__(self, ip):
        return self.lookup(ip) is not None

    def add(self, prefix, nexthop=None, metric=0, source=DEFAULT_SOURCE):
        """Add a route entry and return the minimal list of CIDR blocks
        whose forwarding result changed (empty when the new entry is
        shadowed by better routes).

        :param prefix: an :class:`IPNetwork` or CIDR string. Host bits are
            normalised away.
        :param nexthop: an :class:`IPAddress` or string, or ``None`` to
            install a blackhole route.
        :param metric: route metric; lower wins within the same prefix.
        :param source: tag identifying the origin of this record, used by
            :meth:`remove` to withdraw records selectively.
        """
        network = IPNetwork(prefix)
        if nexthop is None:
            nexthop_value = None
        else:
            nexthop = IPAddress(nexthop)
            if nexthop.version != network.version:
                raise AddrFormatError(
                    'nexthop %r does not match the address family of %r'
                    % (str(nexthop), str(network))
                )
            nexthop_value = nexthop.value
        trie = self._tries[network.version]

        def mutate(node):
            node.entries[(source, nexthop_value)] = metric

        return trie.update(network, mutate)

    def remove(self, prefix, source=DEFAULT_SOURCE, nexthop=None):
        """Withdraw route records of *source* at *prefix* and return the
        minimal list of CIDR blocks whose forwarding result changed.

        Records of other sources at the same prefix are left untouched.

        :param prefix: an :class:`IPNetwork` or CIDR string.
        :param source: only records with this source tag are removed.
        :param nexthop: when given, only the record for this specific next
            hop is removed; otherwise all records of *source* at *prefix*
            (including blackholes) are removed.
        :raises KeyError: if no matching record exists.
        """
        network = IPNetwork(prefix)
        if nexthop is None:
            nexthop_value = ...
        else:
            nexthop_value = IPAddress(nexthop).value
        trie = self._tries[network.version]

        def mutate(node):
            keys = [
                key
                for key in node.entries
                if key[0] == source
                and (nexthop_value is ... or key[1] == nexthop_value)
            ]
            if not keys:
                raise KeyError(
                    'no route from source %r at %s' % (source, network)
                )
            for key in keys:
                del node.entries[key]

        return trie.update(network, mutate)

    def lookup(self, ip):
        """Look up the forwarding result for a single address.

        :param ip: an :class:`IPAddress` or string.
        :return: a :class:`RouteResult`, or ``None`` when no route matches.
        """
        address = IPAddress(ip)
        found = self._tries[address.version].lookup(address.value)
        if found is None:
            return None
        prefix, metric, nexthop_values = found
        if nexthop_values is None:
            nexthops = None
        else:
            nexthops = frozenset(
                IPAddress(value, version=address.version)
                for value in nexthop_values
            )
        return RouteResult(prefix, metric, nexthops)

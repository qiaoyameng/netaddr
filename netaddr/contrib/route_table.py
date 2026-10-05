# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""
An in-memory routing-table view.

Routes are keyed by destination CIDR prefix and a free-form ``source``
identifier (for example the name of the routing protocol or peer that
advertised them).  Forwarding decisions are computed using standard rules:

1. **Longest prefix match** -- the most specific prefix containing the
   destination address wins.
2. **Lowest metric** -- within the winning prefix, only entries with the
   smallest metric value are retained.
3. **ECMP** -- when several entries share the smallest metric, all of their
   next hops are returned together.

IPv4 and IPv6 are kept in independent tables, so an address is only ever
looked up against routes of its own family.  Address lookups walk a binary
radix trie (at most 32 or 128 steps); they never scan the whole table.

Every mutating call returns the minimal set of CIDR blocks whose forwarding
result actually changed, which lets a caller incrementally refresh only the
affected part of a cached forwarding view.
"""

from typing import NamedTuple

from netaddr.ip import IPAddress, IPNetwork
from netaddr.ip.sets import IPSet


class _Blackhole(object):
    """Sentinel next hop marking a route that drops (blackholes) traffic."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(_Blackhole, cls).__new__(cls)
        return cls._instance

    def __repr__(self):
        return 'BLACKHOLE'

    def __reduce__(self):
        return (_Blackhole, ())


#: Next-hop sentinel for routes that discard matched traffic.
BLACKHOLE = _Blackhole()


class RouteEntry(NamedTuple):
    """A single routing record advertised by one ``source``."""

    cidr: IPNetwork
    nexthop: object
    metric: int
    source: object

    @property
    def is_blackhole(self):
        """:return: ``True`` if this entry blackholes matched traffic."""
        return self.nexthop is BLACKHOLE


class ForwardingDecision(NamedTuple):
    """
    The forwarding result computed for an address.

    ``nexthops`` is the stable, de-duplicated tuple of ECMP next hops.  For a
    blackhole decision it is the single-element tuple ``(BLACKHOLE,)``.
    """

    prefix: IPNetwork
    is_blackhole: bool
    nexthops: tuple
    metric: int


def _resolve(entries):
    """
    :param entries: iterable of :class:`RouteEntry` at one prefix node.

    :return: a ``(decision, metric)`` tuple where ``decision`` is
        ``(is_blackhole, nexthops_tuple)`` or ``None`` when there are no
        usable entries.  Ties on metric are broken with blackholes first,
        then de-duplicated, deterministically ordered next hops.
    """
    if not entries:
        return None, None
    best_metric = min(entry.metric for entry in entries)
    winners = [entry for entry in entries if entry.metric == best_metric]
    if any(entry.nexthop is BLACKHOLE for entry in winners):
        decision = (True, (BLACKHOLE,))
    else:
        nexthops = sorted(
            {entry.nexthop for entry in winners},
            key=lambda hop: hop.value,
        )
        decision = (False, tuple(nexthops))
    return decision, best_metric


class _TrieNode(object):
    """A single node of the binary prefix trie (one bit per level)."""

    __slots__ = ('zero', 'one', 'parent', 'parent_bit', 'entries')

    def __init__(self):
        self.zero = None
        self.one = None
        self.parent = None
        self.parent_bit = None
        # source -> RouteEntry
        self.entries = {}


class _FamilyTable(object):
    """A per-address-family radix trie holding source-keyed route entries."""

    __slots__ = ('version', 'max_prefixlen', 'root', 'entry_count')

    def __init__(self, version):
        self.version = version
        self.max_prefixlen = 32 if version == 4 else 128
        self.root = _TrieNode()
        self.entry_count = 0

    def _make_node(self, parent, bit):
        node = _TrieNode()
        node.parent = parent
        node.parent_bit = bit
        return node

    def insert(self, network, nexthop, metric, source):
        node = self.root
        for depth in range(network.prefixlen):
            bit = (network.value >> (self.max_prefixlen - 1 - depth)) & 1
            if bit:
                if node.one is None:
                    node.one = self._make_node(node, 1)
                node = node.one
            else:
                if node.zero is None:
                    node.zero = self._make_node(node, 0)
                node = node.zero
        existed = source in node.entries
        node.entries[source] = RouteEntry(network, nexthop, metric, source)
        if not existed:
            self.entry_count += 1
        return node, existed

    def find(self, prefixlen, address):
        """:return: the exact node for a prefix, or ``None``."""
        node = self.root
        for depth in range(prefixlen):
            bit = (address >> (self.max_prefixlen - 1 - depth)) & 1
            node = node.one if bit else node.zero
            if node is None:
                return None
        return node

    def delete(self, network, source):
        node = self.find(network.prefixlen, network.value)
        if node is None or source not in node.entries:
            return None
        entry = node.entries.pop(source)
        self.entry_count -= 1
        while (
            node is not self.root
            and not node.entries
            and node.zero is None
            and node.one is None
        ):
            parent = node.parent
            if node.parent_bit:
                parent.one = None
            else:
                parent.zero = None
            node = parent
        return entry

    def lookup_node(self, address):
        """Longest-prefix match: return the deepest node with entries."""
        node = self.root
        result = self.root if self.root.entries else None
        for depth in range(self.max_prefixlen):
            bit = (address >> (self.max_prefixlen - 1 - depth)) & 1
            node = node.one if bit else node.zero
            if node is None:
                break
            if node.entries:
                result = node
        return result

    @staticmethod
    def node_prefixlen(root, node):
        prefixlen = 0
        current = node
        while current is not root:
            prefixlen += 1
            current = current.parent
        return prefixlen

    def decision_above(self, node):
        """
        :return: ``(ancestor, decision, metric)`` where ``ancestor`` is the
            nearest entry-bearing ancestor of ``node`` (excluding ``node``
            itself), or ``(None, None, None)`` when there is none.
        """
        ancestor = node.parent
        while ancestor is not None:
            if ancestor.entries:
                decision, metric = _resolve(list(ancestor.entries.values()))
                return ancestor, decision, metric
            ancestor = ancestor.parent
        return None, None, None

    def iter_prefixes(self):
        """Yield ``(node, prefixlen)`` for every node that holds entries."""
        stack = [(self.root, 0)]
        while stack:
            node, depth = stack.pop()
            if node.entries:
                yield node, depth
            if node.one is not None:
                stack.append((node.one, depth + 1))
            if node.zero is not None:
                stack.append((node.zero, depth + 1))

    def exclusive_cidrs(self, network):
        """
        :return: a tuple of CIDRs covering the part of ``network`` that is not
            shadowed by a more specific stored prefix -- the region where
            ``network`` itself provides the forwarding decision.
        """
        prefixlen = network.prefixlen
        prefix_bits = network.value >> (self.max_prefixlen - prefixlen) if prefixlen else 0
        covered = IPSet()

        def walk(node, depth, bits):
            if node is None:
                return
            if depth > prefixlen and node.entries:
                covered.add(
                    IPNetwork(
                        (bits << (self.max_prefixlen - depth), depth),
                        version=self.version,
                    )
                )
                return
            if depth < self.max_prefixlen:
                if depth < prefixlen:
                    bit = (prefix_bits >> (prefixlen - 1 - depth)) & 1
                    branches = ((bit, node.one if bit else node.zero),)
                else:
                    branches = ((0, node.zero), (1, node.one))
                for bit, child in branches:
                    walk(child, depth + 1, (bits << 1) | bit)

        walk(self.root, 0, 0)
        return tuple((IPSet([network]) - covered).iter_cidrs())


class RouteTable(object):
    """
    An in-memory routing-table view with independent IPv4 and IPv6 spaces.

    Entries are added and removed per ``source`` so that equivalent (ECMP)
    records advertised by other sources are left untouched.

        >>> table = RouteTable()
        >>> table.add('0.0.0.0/0', '203.0.113.1', 100, source='default')
        (IPNetwork('0.0.0.0/0'),)
        >>> table.add('10.0.0.0/8', '198.51.100.1', 50, source='static')
        (IPNetwork('10.0.0.0/8'),)
        >>> decision = table.lookup('10.1.2.3')
        >>> decision.prefix
        IPNetwork('10.0.0.0/8')
        >>> decision.metric
        50
        >>> decision.nexthops
        (IPAddress('198.51.100.1'),)
        >>> decision.is_blackhole
        False
        >>> table.add('10.1.0.0/16', BLACKHOLE, 10, source='rtbh')
        (IPNetwork('10.1.0.0/16'),)
        >>> table.lookup('10.1.2.3').is_blackhole
        True
        >>> table.delete('10.1.0.0/16', 'rtbh')
        (IPNetwork('10.1.0.0/16'),)
        >>> table.lookup('10.1.2.3').nexthops
        (IPAddress('198.51.100.1'),)
    """

    __slots__ = ('_v4', '_v6')

    def __init__(self):
        self._v4 = _FamilyTable(4)
        self._v6 = _FamilyTable(6)

    def _family(self, version):
        return self._v4 if version == 4 else self._v6

    def add(self, cidr, nexthop, metric, source):
        """
        Add or replace the record advertised by ``source`` for ``cidr``.

        :param cidr: destination prefix (string or :class:`IPNetwork`); host
            bits are normalised to the network address.
        :param nexthop: next hop (string/:class:`IPAddress`) or
            :data:`BLACKHOLE`.
        :param metric: non-negative routing metric; lower is preferred.
        :param source: hashable identifier of the record's origin.  Re-adding
            with the same ``(cidr, source)`` replaces the existing record.

        :return: a tuple of :class:`IPNetwork` blocks -- the minimal region
            whose forwarding result actually changed (empty when nothing
            changed).
        """
        network = IPNetwork(cidr)
        if nexthop is not BLACKHOLE:
            nexthop = IPAddress(nexthop)
            if nexthop.version != network.version:
                raise ValueError('next hop address family does not match route prefix')
        self._check_metric(metric)
        self._check_source(source)

        family = self._family(network.version)
        node = family.find(network.prefixlen, network.value)
        old_entries = list(node.entries.values()) if node is not None else []
        if old_entries:
            before = self._node_decision(network, family, old_entries)
        else:
            # No entries of our own: the region's decision comes from the
            # nearest entry-bearing ancestor (the anchor node when the exact
            # node has not been created yet).
            anchor = node if node is not None else self._anchor_node(
                family, network.prefixlen, network.value
            )
            before = self._ancestor_decision(family, network, anchor)
        new_entries = [entry for entry in old_entries if entry.source != source]
        new_entries.append(RouteEntry(network, nexthop, metric, source))
        after = self._node_decision(network, family, new_entries)

        family.insert(network, nexthop, metric, source)

        if before == after:
            return ()
        return family.exclusive_cidrs(network)

    def delete(self, cidr, source):
        """
        Remove exactly the record advertised by ``source`` for ``cidr``.

        Other equivalent records for the same prefix (including other ECMP
        next hops) are preserved; forwarding may fall back to a less specific
        route.

        :return: a tuple of :class:`IPNetwork` blocks whose forwarding result
            actually changed (empty when the removed record was shadowed by a
            lower metric one).

        :raises KeyError: if no record with that ``(cidr, source)`` exists.
        """
        network = IPNetwork(cidr)
        family = self._family(network.version)
        node = family.find(network.prefixlen, network.value)
        if node is None or source not in node.entries:
            raise KeyError((str(network), source))

        old_entries = list(node.entries.values())
        before = self._node_decision(network, family, old_entries)
        remaining = [entry for entry in old_entries if entry.source != source]
        if remaining:
            after = self._node_decision(network, family, remaining)
        else:
            after = self._ancestor_decision(family, network, node)

        changed = family.exclusive_cidrs(network)
        family.delete(network, source)

        if before == after:
            return ()
        return changed

    def lookup(self, address):
        """
        Resolve the forwarding decision for ``address``.

        :return: a :class:`ForwardingDecision`, or ``None`` when no route
            (including a default route) matches.
        """
        target = IPAddress(address)
        family = self._family(target.version)
        node = family.lookup_node(target.value)
        if node is None:
            return None
        prefixlen = family.node_prefixlen(family.root, node)
        (is_blackhole, nexthops), metric = _resolve(list(node.entries.values()))
        network_value = (target.value >> (family.max_prefixlen - prefixlen)) << (
            family.max_prefixlen - prefixlen
        )
        prefix = IPNetwork((network_value, prefixlen), version=target.version)
        return ForwardingDecision(prefix, is_blackhole, nexthops, metric)

    @staticmethod
    def _node_decision(network, family, entries):
        """
        Build the full forwarding result (matched prefix, blackhole flag,
        next hops, metric) supplied by the target prefix itself.  Returns
        ``None`` when the prefix has no usable entries.
        """
        resolved, metric = _resolve(entries)
        if resolved is None:
            return None
        is_blackhole, nexthops = resolved
        return network, is_blackhole, nexthops, metric

    @staticmethod
    def _ancestor_decision(family, network, node):
        """Full decision for ``network``'s region inherited from an ancestor."""
        ancestor, resolved, metric = family.decision_above(node)
        if ancestor is None:
            return None
        prefixlen = family.node_prefixlen(family.root, ancestor)
        network_value = (network.value >> (family.max_prefixlen - prefixlen)) << (
            family.max_prefixlen - prefixlen
        )
        prefix = IPNetwork((network_value, prefixlen), version=family.version)
        is_blackhole, nexthops = resolved
        return prefix, is_blackhole, nexthops, metric

    @staticmethod
    def _anchor_node(family, prefixlen, address):
        """Deepest existing node on the path to ``(prefixlen, address)``."""
        node = family.root
        for depth in range(prefixlen):
            bit = (address >> (family.max_prefixlen - 1 - depth)) & 1
            child = node.one if bit else node.zero
            if child is None:
                break
            node = child
        return node

    def routes(self, family=None):
        """
        :param family: restrict to ``4``, ``6`` or ``None`` for both.

        :return: all stored :class:`RouteEntry` records in a stable order
            (sorted by family, network value, prefix length, metric, source).
        """
        tables = (self._v4, self._v6) if family is None else (self._family(family),)
        entries = []
        for table in tables:
            for node, prefixlen in table.iter_prefixes():
                entries.extend(node.entries.values())
        entries.sort(
            key=lambda entry: (
                entry.cidr.version,
                entry.cidr.value,
                entry.cidr.prefixlen,
                entry.metric,
                repr(entry.source),
            )
        )
        return entries

    @staticmethod
    def _check_metric(metric):
        if not isinstance(metric, int) or isinstance(metric, bool):
            raise TypeError('metric must be an integer')
        if metric < 0:
            raise ValueError('metric must be non-negative')

    @staticmethod
    def _check_source(source):
        try:
            hash(source)
        except TypeError:
            raise TypeError('source must be hashable')

    def __len__(self):
        """:return: the total number of stored route records."""
        return self._v4.entry_count + self._v6.entry_count

    def __contains__(self, cidr):
        """:return: ``True`` if at least one record exists for ``cidr``."""
        network = IPNetwork(cidr)
        family = self._family(network.version)
        node = family.find(network.prefixlen, network.value)
        return node is not None and bool(node.entries)

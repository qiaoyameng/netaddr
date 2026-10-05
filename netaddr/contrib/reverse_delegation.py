# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""Reverse DNS delegation planning (RFC 2317 for IPv4, nibble zones for IPv6).

The :class:`ReverseDNSDelegationPlanner` turns a set of addresses and
networks into the concrete records that the parent zone and each delegated
child zone have to publish.  No DNS traffic is ever generated.

Two different questions are answered separately:

* does an *address* get an owner name that can carry a PTR record, and
* can a *network* itself be delegated as a zone.

For IPv4, reverse zones only branch on octet (8 bit) boundaries.  A prefix
whose length is not a multiple of eight (for example a ``/28``) therefore
cannot be delegated as a zone named after its first three octets.  Instead the
classless scheme from RFC 2317 is used: the parent zone keeps one CNAME
record per covered address pointing into a synthetic tagged zone name, and
delegates that synthetic name with NS records.  Network and broadcast
addresses are included like any other address; nothing is dropped.

For IPv6, the ``ip6.arpa`` tree branches every nibble (4 bits).  Networks
that are nibble aligned (prefix length divisible by four) are delegated
directly; every other range is first broken into nibble aligned blocks.

Example::

    >>> from netaddr.contrib.reverse_delegation import (
    ...     ReverseDNSDelegationPlanner)
    >>> planner = ReverseDNSDelegationPlanner(
    ...     ['192.0.2.16/28'], nameservers=['ns1.example.com.'])
    >>> plan = planner.plan()
    >>> sorted(zone.name for zone in plan.zones)
    ['16-31.2.0.192.in-addr.arpa.', '2.0.192.in-addr.arpa.']

All covered addresses -- the network address ``.16`` and the broadcast
address ``.31`` included -- chain into the delegated zone::

    >>> name = plan.resolve_ptr_name('192.0.2.31')
    >>> name
    '31.16-31.2.0.192.in-addr.arpa.'
"""

from dataclasses import dataclass, field

from netaddr import IPAddress, IPNetwork, IPSet, IPRange, iter_iprange

__all__ = [
    'DNSRecord',
    'ReverseZone',
    'DelegationPlan',
    'RFC2317LabelRule',
    'DashRangeLabelRule',
    'CIDRLabelRule',
    'ReverseDNSDelegationPlanner',
    'PTRBudgetExceeded',
    'plan_reverse_delegation',
]


class PTRBudgetExceeded(RuntimeError):
    """Raised when materialising a plan would emit more PTR records than the
    caller budgeted for.

    Use :meth:`DelegationPlan.iter_records` (or
    :meth:`ReverseDNSDelegationPlanner.iter_ptr_names`) to stream records
    without any upper bound instead.
    """


@dataclass(frozen=True)
class DNSRecord:
    """A single piece of zone data needed to realise the delegation.

    Only the record types that are relevant to reverse delegation are
    produced: ``PTR``, ``CNAME`` (RFC 2317 aliasing) and ``NS`` (zone cuts).
    SOA records are intentionally not generated; every real zone already has
    its own SOA and the planner cannot know its timing parameters.

    Attributes:
        zone: fully qualified name of the zone the record belongs to.
        owner: fully qualified owner name of the record.
        rtype: ``'PTR'``, ``'CNAME'`` or ``'NS'``.
        value: record rdata (a fully qualified name), or ``None`` for a PTR
            record whose target the caller has not provided.
        ttl: time to live in seconds.
    """

    zone: str
    owner: str
    rtype: str
    value: object = None
    ttl: int = 3600

    def __str__(self):
        return '%s %d IN %s %s' % (
            self.owner,
            self.ttl,
            self.rtype,
            '' if self.value is None else self.value,
        )


@dataclass
class ReverseZone:
    """A zone involved in a delegation plan and the records it must publish.

    Attributes:
        name: fully qualified zone name (trailing dot included).
        kind: ``'parent'`` for zones operated by the upstream provider or
            ``'child'`` for zones that are delegated away.
        coverage: the address space that PTR records emitted by this zone
            account for, as an :class:`~netaddr.IPSet`.  For RFC 2317 child
            zones this is only the classless slice, never the surrounding
            ``/24``.
        rfc2317: ``True`` for synthetic RFC 2317 tagged child zones.
        ns_records, cname_records, bare_ptr_records: eagerly materialised
            records.  The potentially numerous PTR records owned by child
            zones are streamed lazily via :meth:`iter_ptr_records`.
    """

    name: str
    kind: str
    coverage: IPSet
    rfc2317: bool = False
    ns_records: list = field(default_factory=list)
    cname_records: list = field(default_factory=list)
    bare_ptr_records: list = field(default_factory=list)
    _ptr_ranges: list = field(default_factory=list)
    _targets: object = None
    _ttl: int = 3600

    @property
    def records(self):
        """All eagerly built records (this never streams child PTR data)."""
        return list(self.ns_records) + list(self.cname_records) + list(
            self.bare_ptr_records
        )

    def iter_ptr_records(self):
        """Yield every PTR record this zone is responsible for, one address
        at a time.  ``value`` is ``None`` unless a target was supplied."""
        for start, end in self._ptr_ranges:
            for address in iter_iprange(start, end):
                yield DNSRecord(
                    self.name,
                    self._ptr_owner(address),
                    'PTR',
                    self._lookup_target(address),
                    self._ttl,
                )

    def _ptr_owner(self, address):
        arpa = IPAddress(address).reverse_dns
        if self.rfc2317:
            # 'd.c.b.a.in-addr.arpa.' -> 'd.<tag>.c.b.a.in-addr.arpa.'
            head = arpa.split('.', 1)[0]
            return '%s.%s' % (head, self.name)
        return arpa

    def _lookup_target(self, address):
        if self._targets is None:
            return None
        target = self._targets(IPAddress(address))
        return target

    def owns_address(self, address):
        """``True`` if ``address`` is inside this zone's PTR coverage."""
        return address in self.coverage

    def ptr_record(self, address):
        """The single terminal PTR record this zone serves for ``address``.

        Callers must first check :meth:`owns_address`.  Building one record
        this way is constant time even for very large zones, unlike
        consuming all of :meth:`iter_ptr_records`.
        """
        address = IPAddress(address)
        return DNSRecord(
            self.name, self._ptr_owner(address), 'PTR',
            self._lookup_target(address), self._ttl)

    def iter_all_records(self):
        """Yield every record that must appear in the zone (NS/CNAME/bare PTR
        first, then the lazily generated PTR records)."""
        for record in self.ns_records:
            yield record
        for record in self.cname_records:
            yield record
        for record in self.bare_ptr_records:
            yield record
        for record in self.iter_ptr_records():
            yield record


class DelegationPlan(tuple):
    """The records that must be published to realise a reverse delegation.

    A plan is an immutable tuple of :class:`ReverseZone` objects ordered by
    zone name (parent and child zones are all present).  Zones with the same
    name are merged, so a parent zone that holds several cuts appears only
    once.
    """

    def __new__(cls, zones=()):
        merged = {}
        for zone in zones:
            existing = merged.get(zone.name)
            if existing is None:
                merged[zone.name] = zone
                continue
            existing.coverage = IPSet(list(existing.coverage.iter_cidrs()) +
                                      list(zone.coverage.iter_cidrs()))
            existing.ns_records.extend(zone.ns_records)
            existing.cname_records.extend(zone.cname_records)
            existing.bare_ptr_records.extend(zone.bare_ptr_records)
            existing._ptr_ranges.extend(zone._ptr_ranges)
            if existing.kind != zone.kind:
                raise ValueError(
                    'zone %r cannot be both parent and child' % zone.name)
        return tuple.__new__(cls, [merged[name] for name in sorted(merged)])

    @property
    def zones(self):
        """The tuple of :class:`ReverseZone` objects in the plan."""
        return tuple(self)

    def zone(self, name):
        """Return the zone with the given fully qualified ``name``.

        :raises KeyError: if no such zone is part of the plan.
        """
        for zone in self:
            if zone.name == _fqdn(name):
                return zone
        raise KeyError(name)

    @property
    def parent_zones(self):
        """Zones that stay with the upstream operator."""
        return tuple(zone for zone in self if zone.kind == 'parent')

    @property
    def child_zones(self):
        """Zones that are delegated to the caller's name servers."""
        return tuple(zone for zone in self if zone.kind == 'child')

    def coverage(self):
        """Union of every address accounted for by the plan."""
        covered = IPSet()
        for zone in self:
            covered = IPSet(list(covered.iter_cidrs()) +
                            list(zone.coverage.iter_cidrs()))
        return covered

    def iter_records(self):
        """Stream **every** record in the plan (including potentially huge
        numbers of PTR records) in a deterministic order."""
        ordered = tuple(sorted(self, key=lambda z: (z.kind != 'parent', z.name)))
        for zone in ordered:
            for record in zone.iter_all_records():
                yield record

    def records(self, ptr_budget=None):
        """Materialise the whole plan into a flat list of records.

        :param ptr_budget: if given, the maximum number of PTR records that
            may be generated.  NS, CNAME and bare-PTR records are never
            counted against this budget.
        :raises PTRBudgetExceeded: if generating the PTR records would
            exceed ``ptr_budget``.
        """
        records = []
        ptr_count = 0
        for zone in self:
            records.extend(zone.ns_records)
            records.extend(zone.cname_records)
            records.extend(zone.bare_ptr_records)
            for start, end in zone._ptr_ranges:
                ptr_count += int(end) - int(start) + 1
                if ptr_budget is not None and ptr_count > ptr_budget:
                    raise PTRBudgetExceeded(
                        'plan requires at least %d PTR records, budget is %d'
                        % (ptr_count, ptr_budget))
            records.extend(zone.iter_ptr_records())
        return records

    def ptr_chain(self, address):
        """Return the list of records a resolver follows to reach the PTR
        owner name for ``address``.

        The list starts with the CNAME chain (zero or one entries) and ends
        with the terminal ``PTR`` record stub.  The PTR record's ``value`` is
        ``None`` unless the caller supplied a target.
        """
        address = IPAddress(address)
        chain = []
        for zone in self:
            if zone.kind == 'parent':
                for record in zone.cname_records:
                    if record.owner == address.reverse_dns:
                        chain.append(record)
        final_owner = chain[-1].value if chain else address.reverse_dns
        terminal = None
        for zone in self.child_zones:
            if zone.owns_address(address):
                terminal = zone.ptr_record(address)
                break
        if terminal is None:
            #   No child delegation owns it -- look for a bare parent PTR.
            for zone in self:
                for record in zone.bare_ptr_records:
                    if record.owner == address.reverse_dns:
                        terminal = record
                        break
                if terminal is not None:
                    break
        if terminal is None:
            raise KeyError('address %s is not covered by the plan' % address)
        chain.append(terminal)
        return chain

    def resolve_ptr_name(self, address):
        """Return the final owner name that carries the PTR record for
        ``address``, following any RFC 2317 CNAME."""
        return self.ptr_chain(address)[-1].owner


def _fqdn(name):
    """Normalise ``name`` to an absolute (trailing dot) lower-case FQDN."""
    if not isinstance(name, str) or not name.strip():
        raise ValueError('invalid DNS name: %r' % (name,))
    name = name.strip().lower()
    if not name.endswith('.'):
        name += '.'
    return name


class RFC2317LabelRule(object):
    """Base class for rules that name RFC 2317 tagged zones.

    Subclasses implement :meth:`label`.  The returned string must be a single
    DNS label (no dots) that, together with the enclosing reverse zone, makes
    a unique zone name.
    """

    def label(self, ip_range):
        """Return the tag label for the addresses in ``ip_range``.

        :param ip_range: an :class:`~netaddr.IPRange` describing the exact
            contiguous slice within one ``/24`` being delegated.
        """
        raise NotImplementedError  # pragma: no cover

    def __call__(self, ip_range):
        label = self.label(ip_range)
        self._validate(label, ip_range)
        return label

    @staticmethod
    def _validate(label, ip_range):
        if not isinstance(label, str) or not label or '.' in label:
            raise ValueError(
                'RFC 2317 label %r for %s must be a non-empty single DNS '
                'label (no dots)' % (label, ip_range))
        if label.endswith('.') or len(label) > 63:
            raise ValueError(
                'RFC 2317 label %r for %s is not a valid single DNS label'
                % (label, ip_range))


class DashRangeLabelRule(RFC2317LabelRule):
    """Name tagged zones ``first-last`` (the common ``16-31`` style).

    This rule works for any contiguous slice, even when it does not line up
    with a single CIDR block.
    """

    def label(self, ip_range):
        return '%d-%d' % (
            IPAddress(ip_range[0]).value & 0xFF,
            IPAddress(ip_range[-1]).value & 0xFF,
        )


class CIDRLabelRule(RFC2317LabelRule):
    """Name tagged zones after a CIDR block (``16/28`` style).

    Only suitable when each delegated slice is exactly one CIDR block.  A
    :class:`ValueError` is raised for a range that cannot be expressed as a
    single CIDR.
    """

    def label(self, ip_range):
        cidrs = IPRange(ip_range[0], ip_range[-1]).cidrs()
        if len(cidrs) != 1:
            raise ValueError(
                'range %s is not a single CIDR block; use '
                'DashRangeLabelRule instead' % ip_range)
        cidr = cidrs[0]
        return '%d/%d' % (cidr.ip.value & 0xFF, cidr.prefixlen)


_DASH_RULE = DashRangeLabelRule()


class ReverseDNSDelegationPlanner(object):
    """Plan reverse DNS delegations for a set of addresses and networks.

    :param addresses: an iterable of anything netaddr understands.  Plain
        addresses (``'192.0.2.1'``, an :class:`~netaddr.IPAddress` or an
        integer) only receive a PTR owner name in the parent zone and are not
        delegated.  Networks (:class:`~netaddr.IPNetwork`, ``'10.0.0.0/28'``)
        and :class:`~netaddr.IPRange` objects are delegated as zones where
        possible.
    :param nameservers: non-empty list of name server host names that will
        serve every delegated child zone.
    :param label_rule: an :class:`RFC2317LabelRule` (or any callable taking
        an :class:`~netaddr.IPRange`) used to name RFC 2317 tagged zones.
        Defaults to :class:`DashRangeLabelRule`.
    :param parent_zone: optional fully qualified reverse zone in which every
        cut must be published.  By default the natural enclosing octet zone
        (IPv4) or nibble zone (IPv6) is used.  Use this when the parent is
        itself a non-default zone; a :class:`ValueError` is raised if it does
        not match the addresses.
    :param ptr_targets: optional callable mapping an
        :class:`~netaddr.IPAddress` to the fully qualified name its PTR
        record should point to (return ``None`` to leave a record stub).
        May also be a mapping keyed by address string.
    :param ttl: TTL in seconds placed on every generated record.
    """

    def __init__(
        self,
        addresses,
        nameservers,
        label_rule=None,
        parent_zone=None,
        ptr_targets=None,
        ttl=3600,
    ):
        self._hosts = IPSet()
        self._networks = IPSet()
        for item in addresses:
            if isinstance(item, IPRange):
                self._networks.add(item)
            elif isinstance(item, IPNetwork):
                self._networks.add(item.cidr)
            elif isinstance(item, IPAddress):
                self._hosts.add(IPNetwork(item))
            elif isinstance(item, str) and '/' in item:
                self._networks.add(IPNetwork(item).cidr)
            else:
                self._hosts.add(IPNetwork(IPAddress(item)))

        if not self._hosts and not self._networks:
            raise ValueError('at least one address or network is required')

        if self._hosts and self._networks:
            #   Hosts already covered by a delegated network are not bare.
            self._hosts -= self._networks

        self._nameservers = self._check_nameservers(nameservers)
        self._label_rule = label_rule if label_rule is not None else _DASH_RULE
        if not callable(self._label_rule):
            raise TypeError('label_rule must be callable')
        self._parent_override = None if parent_zone is None else _fqdn(
            parent_zone)
        self._ttl = int(ttl)
        if self._ttl < 0:
            raise ValueError('ttl must not be negative')
        self._targets = self._coerce_targets(ptr_targets)
        self._versions = self._check_versions()

    @staticmethod
    def _check_nameservers(nameservers):
        names = list(nameservers)
        if not names:
            raise ValueError('at least one name server is required')
        return [_fqdn(name) for name in names]

    @staticmethod
    def _coerce_targets(ptr_targets):
        if ptr_targets is None:
            return None
        if callable(ptr_targets):
            return lambda address: _optional_fqdn(ptr_targets(address))
        mapping = dict(ptr_targets)
        return lambda address: _optional_fqdn(
            mapping.get(str(address), mapping.get(address, None)))

    def _check_versions(self):
        versions = set()
        for cidr in self._networks.iter_cidrs():
            versions.add(cidr.version)
        for cidr in self._hosts.iter_cidrs():
            versions.add(cidr.version)
        if self._parent_override is not None and len(versions) > 1:
            raise ValueError(
                'a single parent_zone cannot cover both IPv4 and IPv6; '
                'plan them separately')
        return versions

    # -- name helpers ------------------------------------------------------
    @staticmethod
    def _reverse_zone_for_network(network):
        """Natural reverse zone delegated for a nibble/octet aligned block."""
        if network.version == 4:
            octets = network.network.words
            depth = network.prefixlen // 8
            return '.'.join(
                ['%d' % octets[i] for i in reversed(range(depth))] +
                ['in-addr', 'arpa', ''])
        nibbles = list('%032x' % int(network.network))
        depth = network.prefixlen // 4
        return '.'.join(
            [nibbles[i] for i in reversed(range(depth))] +
            ['ip6', 'arpa', ''])

    @staticmethod
    def _parent_zone_for(address, cut_depth, version):
        if version == 4:
            octets = IPAddress(address).words
            depth = cut_depth
            return '.'.join(
                ['%d' % octets[i] for i in reversed(range(depth))] +
                ['in-addr', 'arpa', ''])
        nibbles = list('%032x' % int(address))
        return '.'.join(
            [nibbles[i] for i in reversed(range(cut_depth))] +
            ['ip6', 'arpa', ''])

    def _check_parent_override(self, expected):
        if self._parent_override is not None and expected != self._parent_override:
            raise ValueError(
                'parent_zone %r does not match the enclosing reverse zone %r '
                'for the requested addresses'
                % (self._parent_override, expected))

    def _make_tag(self, ip_range):
        """Invoke the label rule and validate its result as a single label."""
        rule = self._label_rule
        if isinstance(rule, RFC2317LabelRule):
            return rule(ip_range)
        tag = rule(ip_range)
        RFC2317LabelRule._validate(tag, ip_range)
        return tag

    # -- block decomposition ----------------------------------------------
    @staticmethod
    def _decompose_network(network):
        """Split one network CIDR into ``(natural, rfc2317)`` block lists.

        ``natural`` holds octet aligned (IPv4) or nibble aligned (IPv6)
        blocks that can be delegated at a genuine reverse-tree cut.  For
        IPv4, ``rfc2317`` holds the classless ``/25``..``/31`` slices that
        sit inside a ``/24`` and must use the tagged-zone scheme.
        """
        if network.version == 6:
            if network.prefixlen % 4 == 0:
                return [network.cidr], []
            cut = ((network.prefixlen // 4) + 1) * 4
            return [child.cidr for child in network.subnet(cut)], []

        #   IPv4.  Reverse zones branch every 8 bits; every level between
        #   two octet boundaries is pushed down to the next octet cut, and
        #   partial blocks at /24 become RFC 2317 slices.
        prefix = network.prefixlen
        if prefix % 8 == 0:
            #   /8, /16, /24 and /32 are genuine reverse-tree cuts.
            return [network.cidr], []
        if prefix > 24:
            #   /25../31: the whole network is one classless slice.
            return [], [network.cidr]
        #   Non-aligned prefix up to /24: push down to the next octet cut.
        #   Every resulting child is a fully covered aligned block, so there
        #   are never any RFC 2317 tails (a /23 yields exactly two /24s and
        #   so on).
        cut = ((prefix // 8) + 1) * 8
        return [child.cidr for child in network.subnet(cut)], []

    # -- plan construction -------------------------------------------------
    def plan(self, ptr_budget=None):
        """Build the :class:`DelegationPlan`.

        :param ptr_budget: optional maximum number of child PTR records.
        :raises PTRBudgetExceeded: when the budget would be exceeded.
        """
        zones = {}

        def get_zone(name, kind, coverage, rfc2317=False):
            zone = zones.get(name)
            if zone is None:
                zone = ReverseZone(
                    name=name, kind=kind, coverage=IPSet(),
                    rfc2317=rfc2317, _targets=self._targets,
                    _ttl=self._ttl)
                zones[name] = zone
            elif zone.kind != kind or zone.rfc2317 != rfc2317:
                raise ValueError('conflicting roles for zone %r' % name)
            zone.coverage = IPSet(
                list(zone.coverage.iter_cidrs()) +
                list(coverage.iter_cidrs()))
            return zone

        #   Delegatable networks.
        rfc_slices = []   # (parent /24 zone name, IPNetwork marked slice)
        for network in self._networks.iter_cidrs():
            natural, classless = self._decompose_network(network)
            for block in natural:
                self._add_natural_cut(block, get_zone)
            for block in classless:
                parent = self._parent_zone_for(
                    block.network, 3, 4)
                rfc_slices.append((parent, block))

        #   Merge adjacent RFC 2317 slices that share a parent /24 into one
        #   tagged zone, keeping non-adjacent slices separate.
        rfc_slices.sort(key=lambda item: (item[0], item[1].first))
        groups = []
        for parent, block in rfc_slices:
            if groups:
                last_parent, last_blocks = groups[-1]
                if last_parent == parent and \
                        last_blocks[-1].last + 1 == block.first:
                    last_blocks.append(block)
                    continue
            groups.append((parent, [block]))
        for parent_name, blocks in groups:
            start = blocks[0].network
            end = IPAddress(blocks[-1].last, 4)
            ip_range = IPRange(start, end)
            tag = self._make_tag(ip_range)
            self._add_rfc2317_cut(
                parent_name, tag, ip_range, blocks, get_zone)

        #   Leftover bare hosts (not inside any delegated network).
        self._add_bare_hosts(get_zone)

        plan = DelegationPlan(zones.values())
        if ptr_budget is not None:
            count = 0
            for zone in plan:
                for first, last in zone._ptr_ranges:
                    count += int(last) - int(first) + 1
            if count > ptr_budget:
                raise PTRBudgetExceeded(
                    'plan requires at least %d PTR records, budget is %d'
                    % (count, ptr_budget))
        return plan

    def _add_natural_cut(self, block, get_zone):
        child_name = self._reverse_zone_for_network(block)
        if block.version == 4:
            depth = block.prefixlen // 8
            parent_name = self._parent_zone_for(block.network, depth - 1, 4)
        else:
            depth = block.prefixlen // 4
            parent_name = self._parent_zone_for(block.network, depth - 1, 6)
        self._check_parent_override(parent_name)
        parent = get_zone(parent_name, 'parent', IPSet())
        for server in self._nameservers:
            parent.ns_records.append(
                DNSRecord(parent_name, child_name, 'NS', server, self._ttl))
        child = get_zone(child_name, 'child', IPSet([block.cidr]))
        child._ptr_ranges.append(
            (IPAddress(block.first, block.version),
             IPAddress(block.last, block.version)))

    def _add_rfc2317_cut(self, parent_name, tag, ip_range, blocks, get_zone):
        self._check_parent_override(parent_name)
        child_name = '%s.%s' % (tag, parent_name)
        coverage = IPSet([block.cidr for block in blocks])
        parent = get_zone(parent_name, 'parent', IPSet())
        for server in self._nameservers:
            parent.ns_records.append(
                DNSRecord(parent_name, child_name, 'NS', server, self._ttl))
        for block in blocks:
            for value in range(int(block.first), int(block.last) + 1):
                address = IPAddress(value, 4)
                arpa = address.reverse_dns
                owner_head = arpa.split('.', 1)[0]
                target_name = '%s.%s' % (owner_head, child_name)
                parent.cname_records.append(
                    DNSRecord(parent_name, arpa, 'CNAME', target_name,
                              self._ttl))
        child = get_zone(child_name, 'child', coverage, rfc2317=True)
        child._ptr_ranges.append((ip_range[0], ip_range[-1]))

    def _add_bare_hosts(self, get_zone):
        for cidr in self._hosts.iter_cidrs():
            #   iter_cidrs of a host set yields maximal merged CIDRs, but a
            #   bare PTR only makes sense per individual address.
            for address in cidr:
                if address.version == 4:
                    parent_name = self._parent_zone_for(address, 3, 4)
                else:
                    parent_name = self._parent_zone_for(address, 31, 6)
                self._check_parent_override(parent_name)
                zone = get_zone(parent_name, 'parent', IPSet([IPNetwork(address)]))
                target = self._targets(address) if self._targets else None
                zone.bare_ptr_records.append(
                    DNSRecord(parent_name, address.reverse_dns, 'PTR',
                              target, self._ttl))

    def iter_ptr_names(self):
        """Stream the final PTR owner name for every delegated address
        without building record objects or applying any budget.  Only
        addresses inside delegated networks are yielded (bare hosts do not
        live in a child zone)."""
        for zone in self.plan().child_zones:
            for start, end in zone._ptr_ranges:
                for address in iter_iprange(start, end):
                    yield zone._ptr_owner(address)


def _optional_fqdn(value):
    if value is None:
        return None
    return _fqdn(value)


def plan_reverse_delegation(
        addresses, nameservers, ptr_budget=None, **kwargs):
    """Convenience wrapper around :class:`ReverseDNSDelegationPlanner`.

    :return: the materialised list of :class:`DNSRecord` objects (subject to
        ``ptr_budget``).
    """
    planner = ReverseDNSDelegationPlanner(addresses, nameservers, **kwargs)
    return planner.plan(ptr_budget=ptr_budget).records()

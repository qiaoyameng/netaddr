"""Offline reverse DNS delegation planning."""

from collections import namedtuple

from netaddr.ip import IPAddress, IPNetwork, cidr_merge
from netaddr.ip.sets import IPSet


NSRecord = namedtuple('NSRecord', ('name', 'nameserver'))
CNAMERecord = namedtuple('CNAMERecord', ('name', 'target'))
PTRRecord = namedtuple('PTRRecord', ('name', 'target'))


class ReverseDNSDelegation(object):
    """A single non-overlapping reverse DNS delegation."""

    __slots__ = ('network', 'parent_zone', 'child_zone', 'classless')

    def __init__(self, network, parent_zone, child_zone, classless):
        self.network = network
        self.parent_zone = parent_zone
        self.child_zone = child_zone
        self.classless = classless

    @property
    def address_count(self):
        """The number of IP addresses represented by this delegation."""
        return self.network.size

    def addresses(self):
        """Yield every address in this delegation, including boundary addresses."""
        for address in self.network:
            yield address

    def ptr_name(self, address):
        """Return the PTR owner name used inside the delegated zone."""
        address = IPAddress(address)
        if address not in self.network:
            raise ValueError('%s is not part of %s' % (address, self.network))

        if self.network.version == 4 and self.classless:
            return '%d.%s' % (address.words[3], self.child_zone)
        return address.reverse_dns

    def cname_records(self):
        """Yield RFC 2317 CNAME records required in the parent zone."""
        if not self.classless:
            return

        for address in self.network:
            yield CNAMERecord(address.reverse_dns, self.ptr_name(address))

    def ns_records(self, nameservers):
        """Yield delegation NS records for the supplied nameserver FQDNs."""
        for nameserver in nameservers:
            yield NSRecord(self.child_zone, nameserver)

    def parent_records(self, nameservers):
        """Yield NS and RFC 2317 CNAME records required in the parent zone."""
        for record in self.ns_records(nameservers):
            yield record
        for record in self.cname_records():
            yield record

    def child_records(self, nameservers, ptr_targets):
        """Yield apex NS records and requested PTR records for this child zone."""
        for record in self.ns_records(nameservers):
            yield record
        for address in self.network:
            target = ptr_targets.get((address.version, int(address)))
            if target is not None:
                yield PTRRecord(self.ptr_name(address), target)

    def __repr__(self):
        return (
            'ReverseDNSDelegation(%r, parent_zone=%r, child_zone=%r, classless=%r)'
            % (self.network, self.parent_zone, self.child_zone, self.classless)
        )

    def __eq__(self, other):
        if not isinstance(other, ReverseDNSDelegation):
            return NotImplemented
        return (
            self.network == other.network
            and self.parent_zone == other.parent_zone
            and self.child_zone == other.child_zone
            and self.classless == other.classless
        )

    def __ne__(self, other):
        result = self.__eq__(other)
        if result is NotImplemented:
            return result
        return not result

    def __hash__(self):
        return hash((self.network, self.parent_zone, self.child_zone, self.classless))


class ReverseDNSPlan(object):
    """Parent- and child-zone records for a collection of delegations."""

    __slots__ = ('delegations', '_ptr_targets', '_nameservers')

    def __init__(self, delegations, ptr_targets, nameservers):
        self.delegations = list(delegations)
        self._ptr_targets = dict(ptr_targets)
        self._nameservers = tuple(nameservers)

    @property
    def nameservers(self):
        """Nameserver FQDNs used by every delegation in this plan."""
        return self._nameservers

    @property
    def parent_ns_records(self):
        """NS records that delegate each child zone from its parent zone."""
        return list(self._iter_ns_records())

    @property
    def child_ns_records(self):
        """Apex NS records required in each child zone."""
        return list(self.parent_ns_records)

    def cname_records(self):
        """Yield all address-level RFC 2317 CNAME records."""
        for delegation in self.delegations:
            for record in delegation.cname_records():
                yield record

    def ptr_names(self):
        """Yield the final PTR owner name for every delegated address."""
        for delegation in self.delegations:
            for address in delegation.network:
                yield delegation.ptr_name(address)

    def ptr_records(self):
        """Yield PTR records for addresses supplied with a PTR target."""
        for delegation in self.delegations:
            for record in delegation.child_records(self._nameservers, self._ptr_targets):
                if isinstance(record, PTRRecord):
                    yield record

    def parent_records(self):
        """Yield all records required in parent zones."""
        for delegation in self.delegations:
            for record in delegation.parent_records(self._nameservers):
                yield record

    def _iter_ns_records(self):
        for delegation in self.delegations:
            for record in delegation.ns_records(self._nameservers):
                yield record

    def child_records(self):
        """Yield all records required in child zones."""
        for delegation in self.delegations:
            for record in delegation.child_records(self._nameservers, self._ptr_targets):
                yield record


class ReverseDNSPlanner(object):
    """
    Create offline reverse DNS delegation plans without making DNS queries.

    :param parent_zone: an FQDN of the zone that will contain each delegation
        record, or a callable receiving an :class:`IPNetwork` and its natural
        parent zone. When omitted, the natural parent zone is used.

    :param nameservers: one or more nameserver FQDNs.

    :param label_rule: an RFC 2317 zone label, or a callable receiving an
        :class:`IPNetwork` and returning a label. The default uses the
        inclusive fourth-octet range, for example ``0-15``.
    """

    def __init__(self, parent_zone=None, nameservers=(), label_rule=None):
        self._fixed_parent_zone = None
        self._parent_zone_rule = None

        if parent_zone is None:
            self._parent_zone_rule = lambda network, natural: natural
        elif callable(parent_zone):
            self._parent_zone_rule = parent_zone
        elif isinstance(parent_zone, str):
            self._fixed_parent_zone = _fqdn(parent_zone)
            self._parent_zone_rule = lambda network, natural: self._fixed_parent_zone
        else:
            raise TypeError('parent_zone must be a string or callable')

        self._nameservers = tuple(_fqdn(server) for server in nameservers)
        if not self._nameservers:
            raise ValueError('at least one nameserver is required')

        if label_rule is None:
            self._label_rule = _default_rfc2317_label
        elif callable(label_rule):
            self._label_rule = label_rule
        elif isinstance(label_rule, str):
            _dns_label(label_rule)
            self._label_rule = lambda network: label_rule
        else:
            raise TypeError('label_rule must be a string or callable')

    def plan(self, addresses, ptr_targets=None, record_budget=None):
        """
        Plan delegations for addresses, networks, ranges, or an iterable of them.

        Overlapping and adjacent input ranges are summarized first. Each plan
        is then split into reverse zones that do not cover any address outside
        the requested address space.

        :param ptr_targets: optional mapping of addresses to PTR target FQDNs.

        :param record_budget: optional maximum number of concrete NS, CNAME and
            PTR records. Address-level records remain available as iterators
            when this limit is not supplied.

        :return: a :class:`ReverseDNSPlan`.
        """
        if isinstance(addresses, (str,)) or hasattr(addresses, '_module'):
            addresses = [addresses]

        networks = cidr_merge(addresses)
        if not networks:
            raise ValueError('at least one address or network is required')

        covered = IPSet(networks)
        targets = _normalize_ptr_targets(ptr_targets, covered)

        delegations = []
        for network in networks:
            for child_network in _delegation_networks(network):
                natural_parent, child_zone = _zones(child_network, self._label_rule)
                parent_zone = _fqdn(
                    self._parent_zone_rule(child_network.cidr, natural_parent)
                )
                _ensure_parent_zone(parent_zone, child_zone)
                classless = child_network.version == 4 and child_network.prefixlen > 24
                delegations.append(
                    ReverseDNSDelegation(
                        child_network.cidr,
                        parent_zone,
                        child_zone,
                        classless,
                    )
                )

        if record_budget is not None:
            if not isinstance(record_budget, int) or isinstance(record_budget, bool):
                raise TypeError('record_budget must be an integer')
            if record_budget < 0:
                raise ValueError('record_budget cannot be negative')

            ns_records = len(delegations) * len(self._nameservers)
            cname_records = sum(
                delegation.address_count
                for delegation in delegations
                if delegation.classless
            )
            total = 2 * ns_records + cname_records + len(targets)
            if total > record_budget:
                raise ValueError(
                    'planned %d records, exceeding record_budget %d'
                    % (total, record_budget)
                )

        return ReverseDNSPlan(delegations, targets, self._nameservers)


def plan_reverse_dns_delegation(
    addresses,
    parent_zone=None,
    nameservers=(),
    label_rule=None,
    ptr_targets=None,
    record_budget=None,
):
    """Convenience wrapper around :class:`ReverseDNSPlanner`."""
    return ReverseDNSPlanner(
        parent_zone=parent_zone,
        nameservers=nameservers,
        label_rule=label_rule,
    ).plan(addresses, ptr_targets=ptr_targets, record_budget=record_budget)


def _delegation_networks(network):
    network = network.cidr

    if network.version == 4:
        if network.prefixlen <= 8:
            boundary = 8
        elif network.prefixlen <= 16:
            boundary = 16
        elif network.prefixlen <= 24:
            boundary = 24
        else:
            return [network]
    else:
        boundary = ((network.prefixlen + 3) // 4) * 4

    return list(network.subnet(boundary))


def _zones(network, label_rule):
    if network.version == 4:
        if network.prefixlen > 24:
            parent = IPNetwork((network.first & 0xFFFFFF00, 24), version=4)
            parent_zone = _ipv4_zone(parent)
            label = _dns_label(label_rule(network.cidr))
            child_zone = label + '.' + parent_zone
            return parent_zone, child_zone

        child_zone = _ipv4_zone(network)
        parent_prefix = network.prefixlen - 8
        parent_network = IPNetwork((network.first, parent_prefix), version=4)
        parent_zone = _ipv4_zone(parent_network)
        return parent_zone, child_zone

    child_zone = _ipv6_zone(network)
    if network.prefixlen == 0:
        parent_zone = '.'
    else:
        parent_prefix = network.prefixlen - 4
        parent_network = IPNetwork((network.first, parent_prefix), version=6)
        parent_zone = _ipv6_zone(parent_network)
    return parent_zone, child_zone


def _ipv4_zone(network):
    octet_count = network.prefixlen // 8
    labels = [str(octet) for octet in reversed(network.network.words[:octet_count])]
    return '.'.join(labels + ['in-addr', 'arpa']) + '.'


def _ipv6_zone(network):
    nibble_count = network.prefixlen // 4
    nibbles = '%032x' % network.network.value
    labels = list(reversed(nibbles[:nibble_count]))
    return '.'.join(labels + ['ip6', 'arpa']) + '.'


def _default_rfc2317_label(network):
    first = network.first & 255
    last = network.last & 255
    return '%d-%d' % (first, last)


def _normalize_ptr_targets(ptr_targets, covered):
    if ptr_targets is None:
        return {}
    if not hasattr(ptr_targets, 'items'):
        raise TypeError('ptr_targets must be a mapping of addresses to targets')

    targets = {}
    for key, target in ptr_targets.items():
        address = key if isinstance(key, IPAddress) else IPAddress(key)
        if address not in covered:
            raise ValueError('PTR target for %s is outside delegated address space' % address)
        targets[(address.version, int(address))] = _fqdn(target)
    return targets


def _fqdn(value):
    if not isinstance(value, str) or not value:
        raise ValueError('FQDN expected, got %r' % (value,))

    if value == '.':
        return '.'

    name = value.rstrip('.').lower()
    labels = name.split('.')
    if not labels or any(not label or len(label) > 63 for label in labels):
        raise ValueError('invalid DNS name: %r' % (value,))
    if len(name) > 253:
        raise ValueError('DNS name is too long: %r' % (value,))
    return name + '.'


def _dns_label(label):
    if not isinstance(label, str) or not label or '.' in label or len(label) > 63:
        raise ValueError('invalid DNS label: %r' % (label,))
    return label.lower()


def _ensure_parent_zone(parent_zone, child_zone):
    if parent_zone == '.':
        return

    parent_labels = parent_zone[:-1].split('.')
    child_labels = child_zone[:-1].split('.')
    if (
        len(child_labels) <= len(parent_labels)
        or child_labels[-len(parent_labels):] != parent_labels
    ):
        raise ValueError('%r is not a parent zone of %r' % (parent_zone, child_zone))

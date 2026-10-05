# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""Set based operations for IP addresses and subnets."""

import itertools as _itertools
import sys as _sys

from netaddr.ip import IPNetwork, IPAddress, IPRange, cidr_merge, cidr_exclude, iprange_to_cidrs


def _subtract(supernet, subnets, subnet_idx, ranges):
    """Calculate IPSet([supernet]) - IPSet(subnets).

    Assumptions: subnets is sorted, subnet_idx points to the first
    element in subnets that is a subnet of supernet.

    Results are appended to the ranges parameter as tuples of in format
    (version, first, last). Return value is the first subnet_idx that
    does not point to a subnet of supernet (or len(subnets) if all
    subsequents items are a subnet of supernet).
    """
    version = supernet._module.version
    subnet = subnets[subnet_idx]
    if subnet.first > supernet.first:
        ranges.append((version, supernet.first, subnet.first - 1))

    subnet_idx += 1
    prev_subnet = subnet
    while subnet_idx < len(subnets):
        cur_subnet = subnets[subnet_idx]

        if cur_subnet not in supernet:
            break
        if prev_subnet.last + 1 == cur_subnet.first:
            # two adjacent, non-mergable IPNetworks
            pass
        else:
            ranges.append((version, prev_subnet.last + 1, cur_subnet.first - 1))

        subnet_idx += 1
        prev_subnet = cur_subnet

    first = prev_subnet.last + 1
    last = supernet.last
    if first <= last:
        ranges.append((version, first, last))

    return subnet_idx


def _iter_merged_ranges(sorted_ranges):
    """Iterate over sorted_ranges, merging where possible

    Sorted ranges must be a sorted iterable of (version, first, last) tuples.
    Merging occurs for pairs like [(4, 10, 42), (4, 43, 100)] which is merged
    into (4, 10, 100), and leads to return value
    ( IPAddress(10, 4), IPAddress(100, 4) ), which is suitable input for the
    iprange_to_cidrs function.
    """
    if not sorted_ranges:
        return

    current_version, current_start, current_stop = sorted_ranges[0]

    for next_version, next_start, next_stop in sorted_ranges[1:]:
        if next_start == current_stop + 1 and next_version == current_version:
            # Can be merged.
            current_stop = next_stop
            continue
        # Cannot be merged.
        yield (IPAddress(current_start, current_version), IPAddress(current_stop, current_version))
        current_start = next_start
        current_stop = next_stop
        current_version = next_version
    yield (IPAddress(current_start, current_version), IPAddress(current_stop, current_version))


class _CIDRFamilySummary(object):
    __slots__ = (
        'version',
        'feasible',
        'reason',
        'cidrs',
        'rules_used',
        'minimum_rules',
        'target_addresses',
        'extra_addresses',
        'extra_ranges',
    )

    def __init__(
        self,
        version,
        feasible,
        reason=None,
        cidrs=None,
        rules_used=0,
        minimum_rules=None,
        target_addresses=0,
        extra_addresses=0,
        extra_ranges=None,
    ):
        self.version = version
        self.feasible = feasible
        self.reason = reason
        self.cidrs = [] if cidrs is None else cidrs
        self.rules_used = rules_used
        self.minimum_rules = minimum_rules
        self.target_addresses = target_addresses
        self.extra_addresses = extra_addresses
        self.extra_ranges = [] if extra_ranges is None else extra_ranges


class CIDRSummary(object):
    """
    Result of a bounded CIDR summarization.

    IPv4 and IPv6 rules are optimized separately while sharing one total rule
    budget. The combined ``cidrs`` sequence is sorted with IPv4 networks
    before IPv6 networks.
    """

    __slots__ = (
        'max_rules',
        'feasible',
        'reason',
        'cidrs',
        'rules_used',
        'target_addresses',
        'extra_addresses',
        'extra_ranges',
        'minimum_rules',
        'ipv4',
        'ipv6',
    )

    def __init__(self, max_rules, ipv4, ipv6, overall_feasible=None):
        self.max_rules = max_rules
        self.ipv4 = ipv4
        self.ipv6 = ipv6
        if overall_feasible is None:
            self.feasible = ipv4.feasible and ipv6.feasible
        else:
            self.feasible = overall_feasible
        self.minimum_rules = (ipv4.minimum_rules, ipv6.minimum_rules)

        if self.feasible:
            self.reason = None
            self.cidrs = sorted(_itertools.chain(ipv4.cidrs, ipv6.cidrs))
            self.rules_used = ipv4.rules_used + ipv6.rules_used
            self.target_addresses = ipv4.target_addresses + ipv6.target_addresses
            self.extra_addresses = ipv4.extra_addresses + ipv6.extra_addresses
            self.extra_ranges = list(
                _itertools.chain(ipv4.extra_ranges, ipv6.extra_ranges)
            )
        else:
            overlapping = not ipv4.feasible and ipv4.reason == 'target and forbidden sets overlap'
            overlapping = overlapping or (
                not ipv6.feasible and ipv6.reason == 'target and forbidden sets overlap'
            )
            if overlapping:
                self.reason = 'target and forbidden sets overlap'
            else:
                self.reason = 'rule limit is too small'
            self.cidrs = []
            self.rules_used = 0
            self.target_addresses = ipv4.target_addresses + ipv6.target_addresses
            self.extra_addresses = 0
            self.extra_ranges = []

    def __repr__(self):
        if self.feasible:
            return (
                'CIDRSummary(feasible=True, rules_used=%r, extra_addresses=%r, cidrs=%r)'
                % (self.rules_used, self.extra_addresses, [str(cidr) for cidr in self.cidrs])
            )
        return 'CIDRSummary(feasible=False, reason=%r)' % self.reason


class _PrefixNode(object):
    __slots__ = (
        'depth',
        'value',
        'children',
        'is_target',
        'is_forbidden',
        'has_target',
        'has_forbidden',
        'size',
        'target_size',
        'minimum_rules',
        'costs',
    )

    def __init__(self, depth, value, size):
        self.depth = depth
        self.value = value
        self.children = {}
        self.is_target = False
        self.is_forbidden = False
        self.has_target = False
        self.has_forbidden = False
        self.size = size
        self.target_size = 0
        self.minimum_rules = 0
        self.costs = {}


def _validate_rule_limit(max_rules):
    if isinstance(max_rules, bool) or not isinstance(max_rules, int):
        raise TypeError('max_rules must be a non-negative integer')
    if max_rules < 0:
        raise ValueError('max_rules must be a non-negative integer')


def _split_ip_set(ip_set):
    families = {4: IPSet(), 6: IPSet()}
    for cidr in ip_set.iter_cidrs():
        families[cidr.version]._cidrs[cidr] = True
    return families


def _build_prefix_tree(version, target, forbidden):
    width = version == 4 and 32 or 128
    root = _PrefixNode(0, 0, 1 << width)

    for ip_set, attribute in ((target, 'is_target'), (forbidden, 'is_forbidden')):
        for cidr in ip_set.iter_cidrs():
            node = root
            value = cidr._value
            for depth in range(cidr.prefixlen):
                bit = (value >> (width - depth - 1)) & 1
                try:
                    node = node.children[bit]
                except KeyError:
                    child_depth = depth + 1
                    child = _PrefixNode(
                        child_depth,
                        value & (-(1 << (width - child_depth))),
                        1 << (width - child_depth),
                    )
                    node.children[bit] = child
                    node = child
            setattr(node, attribute, True)

    return root


def _empty_child_state(node):
    if node is None:
        return {0: 0}
    return node.costs


def _calculate_prefix_costs(root, max_rules):
    stack = [(root, False)]
    while stack:
        node, visited = stack.pop()
        if not visited:
            stack.append((node, True))
            if 1 in node.children:
                stack.append((node.children[1], False))
            if 0 in node.children:
                stack.append((node.children[0], False))
            continue

        node.has_target = node.is_target
        node.has_forbidden = node.is_forbidden
        node.target_size = node.size if node.is_target else 0

        for child in node.children.values():
            node.has_target = node.has_target or child.has_target
            node.has_forbidden = node.has_forbidden or child.has_forbidden
            node.target_size += child.target_size

        if not node.has_target:
            node.minimum_rules = 0
            node.costs = {0: 0}
            continue

        if node.is_target:
            node.minimum_rules = 1
            if max_rules:
                node.costs = {1: 0}
            continue

        if node.has_forbidden:
            node.minimum_rules = sum(
                child.minimum_rules for child in node.children.values() if child.has_target
            )
        else:
            node.minimum_rules = 1

        if node.minimum_rules > max_rules:
            continue

        costs = {}
        if not node.has_forbidden:
            costs[1] = node.size - node.target_size

        left = node.children.get(0)
        right = node.children.get(1)
        left_costs = _empty_child_state(left)
        right_costs = _empty_child_state(right)

        for left_rules, left_cost in left_costs.items():
            for right_rules, right_cost in right_costs.items():
                rules = left_rules + right_rules
                if rules > max_rules:
                    continue
                cost = left_cost + right_cost
                if rules not in costs or cost < costs[rules]:
                    costs[rules] = cost

        node.costs = costs


def _network_for_node(node, version):
    return IPNetwork((node.value, node.depth), version=version)


def _recover_cidrs(root, rules, version):
    chosen = {}

    def recover(node, rule_count):
        if rule_count == 0:
            return ()

        key = (node, rule_count)
        if key in chosen:
            return chosen[key]

        if node.is_target:
            result = (_network_for_node(node, version),)
            chosen[key] = result
            return result

        best = None
        if not node.has_forbidden and rule_count == 1:
            self_cost = node.size - node.target_size
            if node.costs.get(1) == self_cost:
                best = (_network_for_node(node, version),)

        left = node.children.get(0)
        right = node.children.get(1)
        left_costs = _empty_child_state(left)
        right_costs = _empty_child_state(right)

        for left_rules in sorted(left_costs):
            right_rules = rule_count - left_rules
            if right_rules not in right_costs:
                continue
            candidate_cost = left_costs[left_rules] + right_costs[right_rules]
            if candidate_cost != node.costs[rule_count]:
                continue
            candidate = (
                recover(left, left_rules) if left is not None else ()
            ) + (recover(right, right_rules) if right is not None else ())
            if best is None or candidate < best:
                best = candidate

        chosen[key] = best
        return best

    return recover(root, rules)


def _family_solution(version, target, cidrs, minimum_rules, target_size):
    covered = IPSet(cidrs)
    extra_set = covered.difference(target)
    return _CIDRFamilySummary(
        version,
        True,
        cidrs=list(cidrs),
        rules_used=len(cidrs),
        minimum_rules=minimum_rules,
        target_addresses=target_size,
        extra_addresses=extra_set.size,
        extra_ranges=list(extra_set.iter_ipranges()),
    )


def _summarize_sets(target, forbidden, max_rules):
    target_families = _split_ip_set(target)
    forbidden_families = _split_ip_set(forbidden)
    family_data = []

    for version in (4, 6):
        target_family = target_families[version]
        forbidden_family = forbidden_families[version]
        target_size = target_family.size

        if not target_family._cidrs:
            family_data.append(
                (
                    version,
                    target_family,
                    0,
                    {0: 0},
                    {0: ()},
                    None,
                    target_size,
                )
            )
            continue

        if target_family.intersection(forbidden_family):
            if version == 4:
                ipv4 = _CIDRFamilySummary(
                    4,
                    False,
                    reason='target and forbidden sets overlap',
                    target_addresses=target_families[4].size,
                )
                ipv6 = _CIDRFamilySummary(6, True, minimum_rules=0)
            else:
                ipv4 = _CIDRFamilySummary(4, True, minimum_rules=0)
                ipv6 = _CIDRFamilySummary(
                    6,
                    False,
                    reason='target and forbidden sets overlap',
                    target_addresses=target_families[6].size,
                )
            return CIDRSummary(
                max_rules,
                ipv4,
                ipv6,
            )

        root = _build_prefix_tree(version, target_family, forbidden_family)
        _calculate_prefix_costs(root, max_rules)
        family_data.append(
            (
                version,
                target_family,
                root.minimum_rules,
                root.costs,
                None,
                root,
                target_size,
            )
        )

    best = None
    for ipv4_rules, ipv4_cost in family_data[0][3].items():
        for ipv6_rules, ipv6_cost in family_data[1][3].items():
            rules_used = ipv4_rules + ipv6_rules
            if rules_used > max_rules:
                continue

            selected = []
            for item, rule_count in zip(family_data, (ipv4_rules, ipv6_rules)):
                (
                    version,
                    target_family,
                    _minimum_rules,
                    _costs,
                    cached_cidrs,
                    root,
                    _target_size,
                ) = item
                if cached_cidrs is not None:
                    family_cidrs = cached_cidrs[rule_count]
                else:
                    family_cidrs = _recover_cidrs(root, rule_count, version)
                selected.append(family_cidrs)

            candidate_key = (
                ipv4_cost + ipv6_cost,
                rules_used,
                selected[0],
                selected[1],
            )
            if best is None or candidate_key < best[0]:
                best = (candidate_key, selected)

    if best is not None:
        family_results = []
        for item, family_cidrs in zip(family_data, best[1]):
            (
                version,
                target_family,
                minimum_rules,
                _costs,
                _cached_cidrs,
                _root,
                _target_size,
            ) = item
            family_results.append(
                _family_solution(
                    version,
                    target_family,
                    family_cidrs,
                    minimum_rules,
                    item[6],
                )
            )
        return CIDRSummary(max_rules, family_results[0], family_results[1])

    family_results = []
    for item in family_data:
        (
            version,
            target_family,
            minimum_rules,
            costs,
            cached_cidrs,
            root,
            target_size,
        ) = item
        if not costs:
            family_results.append(
                _CIDRFamilySummary(
                    version,
                    False,
                    reason='rule limit is too small',
                    minimum_rules=minimum_rules,
                    target_addresses=target_size,
                )
            )
        else:
            rules = min(costs, key=lambda count: (costs[count], count))
            if cached_cidrs is not None:
                family_cidrs = cached_cidrs[rules]
            else:
                family_cidrs = _recover_cidrs(root, rules, version)
            family_results.append(
                _family_solution(
                    version,
                    target_family,
                    family_cidrs,
                    minimum_rules,
                    target_size,
                )
            )
    return CIDRSummary(
        max_rules, family_results[0], family_results[1], overall_feasible=False
    )


def cidr_summarize(target, forbidden, max_rules):
    """
    Find CIDRs covering every target address without including a forbidden
    address.

    The optimizer works on the binary CIDR prefix tree. It never iterates over
    individual addresses, so IPv6 block sizes are represented as exact Python
    integers rather than expanded.

    Among feasible combinations, this minimizes covered addresses outside the
    target set. Ties use the smaller rule count, then the lexicographically
    smaller sorted CIDR list. IPv4 and IPv6 use separate prefix trees and
    share ``max_rules`` as one total rule budget.

    :param target: an :class:`IPSet`, or an iterable accepted by
        ``IPSet(...)``, containing every address that must be covered.

    :param forbidden: an :class:`IPSet` or iterable containing addresses that
        no returned CIDR may contain.

    :param max_rules: maximum total number of CIDR rules.

    :return: a :class:`CIDRSummary`. Its ``feasible`` attribute is ``False``
        when target and forbidden overlap or more rules are required.
    """
    _validate_rule_limit(max_rules)
    if not isinstance(target, IPSet):
        target = IPSet(target)
    if not isinstance(forbidden, IPSet):
        forbidden = IPSet(forbidden)

    return _summarize_sets(target, forbidden, max_rules)


class IPSet(object):
    """
    Represents an unordered collection (set) of unique IP addresses and
    subnets.

    """

    __slots__ = ('_cidrs', '__weakref__')

    def __init__(self, iterable=None, flags=0):
        """
        Constructor.

        :param iterable: (optional) an iterable containing IP addresses,
            subnets or ranges.

        :param flags: decides which rules are applied to the interpretation
            of the addr value. See the :class:`IPAddress` documentation
            for supported constant values.

        """
        if isinstance(iterable, IPNetwork):
            self._cidrs = {iterable.cidr: True}
        elif isinstance(iterable, IPRange):
            self._cidrs = dict.fromkeys(iprange_to_cidrs(iterable[0], iterable[-1]), True)
        elif isinstance(iterable, IPSet):
            self._cidrs = dict.fromkeys(iterable.iter_cidrs(), True)
        else:
            self._cidrs = {}
            if iterable is not None:
                mergeable = []
                for addr in iterable:
                    if isinstance(addr, int):
                        addr = IPAddress(addr, flags=flags)
                    mergeable.append(addr)

                for cidr in cidr_merge(mergeable):
                    self._cidrs[cidr] = True

    def __getstate__(self):
        """:return: Pickled state of an ``IPSet`` object."""
        return tuple([cidr.__getstate__() for cidr in self._cidrs])

    def __setstate__(self, state):
        """
        :param state: data used to unpickle a pickled ``IPSet`` object.

        """
        self._cidrs = dict.fromkeys(
            (IPNetwork((value, prefixlen), version=version) for value, prefixlen, version in state),
            True,
        )

    def _compact_single_network(self, added_network):
        """
        Same as compact(), but assume that added_network is the only change and
        that this IPSet was properly compacted before added_network was added.
        This allows to perform compaction much faster. added_network must
        already be present in self._cidrs.
        """
        added_first = added_network.first
        added_last = added_network.last
        added_version = added_network.version

        # Check for supernets and subnets of added_network.
        if added_network._prefixlen == added_network._module.width:
            # This is a single IP address, i.e. /32 for IPv4 or /128 for IPv6.
            # It does not have any subnets, so we only need to check for its
            # potential supernets.
            for potential_supernet in added_network.supernet():
                if potential_supernet in self._cidrs:
                    del self._cidrs[added_network]
                    return
        else:
            # IPNetworks from self._cidrs that are subnets of added_network.
            to_remove = []
            for cidr in self._cidrs:
                if cidr._module.version != added_version or cidr == added_network:
                    # We found added_network or some network of a different version.
                    continue
                first = cidr.first
                last = cidr.last
                if first >= added_first and last <= added_last:
                    # cidr is a subnet of added_network. Remember to remove it.
                    to_remove.append(cidr)
                elif first <= added_first and last >= added_last:
                    # cidr is a supernet of added_network. Remove added_network.
                    del self._cidrs[added_network]
                    # This IPSet was properly compacted before. Since added_network
                    # is removed now, it must again be properly compacted -> done.
                    assert not to_remove
                    return
            for item in to_remove:
                del self._cidrs[item]

        # Check if added_network can be merged with another network.

        # Note that merging can only happen between networks of the same
        # prefixlen. This just leaves 2 candidates: The IPNetworks just before
        # and just after the added_network.
        # This can be reduced to 1 candidate: 10.0.0.0/24 and 10.0.1.0/24 can
        # be merged into into 10.0.0.0/23. But 10.0.1.0/24 and 10.0.2.0/24
        # cannot be merged. With only 1 candidate, we might as well make a
        # dictionary lookup.
        shift_width = added_network._module.width - added_network.prefixlen
        while added_network.prefixlen != 0:
            # figure out if the least significant bit of the network part is 0 or 1.
            the_bit = (added_network._value >> shift_width) & 1
            if the_bit:
                candidate = added_network.previous()
            else:
                candidate = added_network.next()

            if candidate not in self._cidrs:
                # The only possible merge does not work -> merge done
                return
            # Remove added_network&candidate, add merged network.
            del self._cidrs[candidate]
            del self._cidrs[added_network]
            added_network.prefixlen -= 1
            # Be sure that we set the host bits to 0 when we move the prefixlen.
            # Otherwise, adding 255.255.255.255/32 will result in a merged
            # 255.255.255.255/24 network, but we want 255.255.255.0/24.
            shift_width += 1
            added_network._value = (added_network._value >> shift_width) << shift_width
            self._cidrs[added_network] = True

    def compact(self):
        """
        Compact internal list of `IPNetwork` objects using a CIDR merge.
        """
        cidrs = cidr_merge(self._cidrs)
        self._cidrs = dict.fromkeys(cidrs, True)

    def __hash__(self):
        """
        Raises ``TypeError`` if this method is called.

        .. note:: IPSet objects are not hashable and cannot be used as \
            dictionary keys or as members of other sets. \
        """
        raise TypeError('IP sets are unhashable!')

    def __contains__(self, ip):
        """
        :param ip: An IP address or subnet.

        :return: ``True`` if IP address or subnet is a member of this IP set.
        """
        # Iterating over self._cidrs is an O(n) operation: 1000 items in
        # self._cidrs would mean 1000 loops. Iterating over all possible
        # supernets loops at most 32 times for IPv4 or 128 times for IPv6,
        # no matter how many CIDRs this object contains.
        supernet = IPNetwork(ip)
        if supernet in self._cidrs:
            return True
        while supernet._prefixlen:
            supernet._prefixlen -= 1
            if supernet in self._cidrs:
                return True
        return False

    def __bool__(self):
        """Return True if IPSet contains at least one IP, else False"""
        return bool(self._cidrs)

    def __iter__(self):
        """
        :return: an iterator over the IP addresses within this IP set.
        """
        return _itertools.chain(*sorted(self._cidrs))

    def iter_cidrs(self):
        """
        :return: an iterator over individual IP subnets within this IP set.
        """
        return sorted(self._cidrs)

    def add(self, addr, flags=0):
        """
        Adds an IP address or subnet or IPRange to this IP set. Has no effect if
        it is already present.

        Note that where possible the IP address or subnet is merged with other
        members of the set to form more concise CIDR blocks.

        :param addr: An IP address or subnet in either string or object form, or
            an IPRange object.

        :param flags: decides which rules are applied to the interpretation
            of the addr value. See the :class:`IPAddress` documentation
            for supported constant values.

        """
        if isinstance(addr, IPRange):
            new_cidrs = dict.fromkeys(iprange_to_cidrs(addr[0], addr[-1]), True)
            self._cidrs.update(new_cidrs)
            self.compact()
            return
        if isinstance(addr, IPNetwork):
            # Networks like 10.1.2.3/8 need to be normalized to 10.0.0.0/8
            addr = addr.cidr
        elif isinstance(addr, int):
            addr = IPNetwork(IPAddress(addr, flags=flags))
        else:
            addr = IPNetwork(addr)

        self._cidrs[addr] = True
        self._compact_single_network(addr)

    def remove(self, addr, flags=0):
        """
        Removes an IP address or subnet or IPRange from this IP set. Does
        nothing if it is not already a member.

        Note that this method behaves more like discard() found in regular
        Python sets because it doesn't raise KeyError exceptions if the
        IP address or subnet is question does not exist. It doesn't make sense
        to fully emulate that behaviour here as IP sets contain groups of
        individual IP addresses as individual set members using IPNetwork
        objects.

        :param addr: An IP address or subnet, or an IPRange.

        :param flags: decides which rules are applied to the interpretation
            of the addr value. See the :class:`IPAddress` documentation
            for supported constant values.

        """
        if isinstance(addr, IPRange):
            cidrs = iprange_to_cidrs(addr[0], addr[-1])
            for cidr in cidrs:
                self.remove(cidr)
            return

        if isinstance(addr, int):
            addr = IPAddress(addr, flags=flags)
        else:
            addr = IPNetwork(addr)

        #   This add() is required for address blocks provided that are larger
        #   than blocks found within the set but have overlaps. e.g. :-
        #
        #   >>> IPSet(['192.0.2.0/24']).remove('192.0.2.0/23')
        #   IPSet([])
        #
        self.add(addr)

        remainder = None
        matching_cidr = None

        #   Search for a matching CIDR and exclude IP from it.
        for cidr in self._cidrs:
            if addr in cidr:
                remainder = cidr_exclude(cidr, addr)
                matching_cidr = cidr
                break

        #   Replace matching CIDR with remaining CIDR elements.
        if remainder is not None:
            del self._cidrs[matching_cidr]
            for cidr in remainder:
                self._cidrs[cidr] = True
                # No call to self.compact() is needed. Removing an IPNetwork cannot
                # create mergeable networks.

    def pop(self):
        """
        Removes and returns an arbitrary IP address or subnet from this IP
        set.

        :return: An IP address or subnet.
        """
        return self._cidrs.popitem()[0]

    def isdisjoint(self, other):
        """
        :param other: an IP set.

        :return: ``True`` if this IP set has no elements (IP addresses
            or subnets) in common with other. Intersection *must* be an
            empty set.
        """
        result = self.intersection(other)
        return not result

    def copy(self):
        """:return: a shallow copy of this IP set."""
        obj_copy = self.__class__()
        obj_copy._cidrs.update(self._cidrs)
        return obj_copy

    def update(self, iterable, flags=0):
        """
        Update the contents of this IP set with the union of itself and
        other IP set.

        :param iterable: an iterable containing IP addresses, subnets or ranges.

        :param flags: decides which rules are applied to the interpretation
            of the addr value. See the :class:`IPAddress` documentation
            for supported constant values.

        """
        if isinstance(iterable, IPSet):
            self._cidrs = dict.fromkeys(
                (
                    ip
                    for ip in cidr_merge(
                        _itertools.chain(self._cidrs.keys(), iterable._cidrs.keys())
                    )
                ),
                True,
            )
            return
        elif isinstance(iterable, (IPNetwork, IPRange)):
            self.add(iterable)
            return

        if not hasattr(iterable, '__iter__'):
            raise TypeError('an iterable was expected!')
        #   An iterable containing IP addresses or subnets.
        mergeable = []
        for addr in iterable:
            if isinstance(addr, int):
                addr = IPAddress(addr, flags=flags)
            mergeable.append(addr)

        for cidr in cidr_merge(_itertools.chain(self._cidrs.keys(), mergeable)):
            self._cidrs[cidr] = True

        self.compact()

    def clear(self):
        """Remove all IP addresses and subnets from this IP set."""
        self._cidrs = {}

    def __eq__(self, other):
        """
        :param other: an IP set

        :return: ``True`` if this IP set is equivalent to the ``other`` IP set,
            ``False`` otherwise.
        """
        try:
            return self._cidrs == other._cidrs
        except AttributeError:
            return NotImplemented

    def __ne__(self, other):
        """
        :param other: an IP set

        :return: ``False`` if this IP set is equivalent to the ``other`` IP set,
            ``True`` otherwise.
        """
        try:
            return self._cidrs != other._cidrs
        except AttributeError:
            return NotImplemented

    def __lt__(self, other):
        """
        :param other: an IP set

        :return: ``True`` if this IP set is less than the ``other`` IP set,
            ``False`` otherwise.
        """
        if not hasattr(other, '_cidrs'):
            return NotImplemented

        return self.size < other.size and self.issubset(other)

    def issubset(self, other):
        """
        :param other: an IP set.

        :return: ``True`` if every IP address and subnet in this IP set
            is found within ``other``.
        """
        for cidr in self._cidrs:
            if cidr not in other:
                return False
        return True

    __le__ = issubset

    def __gt__(self, other):
        """
        :param other: an IP set.

        :return: ``True`` if this IP set is greater than the ``other`` IP set,
            ``False`` otherwise.
        """
        if not hasattr(other, '_cidrs'):
            return NotImplemented

        return self.size > other.size and self.issuperset(other)

    def issuperset(self, other):
        """
        :param other: an IP set.

        :return: ``True`` if every IP address and subnet in other IP set
            is found within this one.
        """
        if not hasattr(other, '_cidrs'):
            return NotImplemented

        for cidr in other._cidrs:
            if cidr not in self:
                return False
        return True

    __ge__ = issuperset

    def union(self, other):
        """
        :param other: an IP set.

        :return: the union of this IP set and another as a new IP set
            (combines IP addresses and subnets from both sets).
        """
        ip_set = self.copy()
        ip_set.update(other)
        return ip_set

    __or__ = union

    def intersection(self, other):
        """
        :param other: an IP set.

        :return: the intersection of this IP set and another as a new IP set.
            (IP addresses and subnets common to both sets).
        """
        result_cidrs = {}

        own_nets = sorted(self._cidrs)
        other_nets = sorted(other._cidrs)
        own_idx = 0
        other_idx = 0
        own_len = len(own_nets)
        other_len = len(other_nets)
        while own_idx < own_len and other_idx < other_len:
            own_cur = own_nets[own_idx]
            other_cur = other_nets[other_idx]

            if own_cur == other_cur:
                result_cidrs[own_cur] = True
                own_idx += 1
                other_idx += 1
            elif own_cur in other_cur:
                result_cidrs[own_cur] = True
                own_idx += 1
            elif other_cur in own_cur:
                result_cidrs[other_cur] = True
                other_idx += 1
            else:
                # own_cur and other_cur have nothing in common
                if own_cur < other_cur:
                    own_idx += 1
                else:
                    other_idx += 1

        # We ran out of networks in own_nets or other_nets. Either way, there
        # can be no further result_cidrs.
        result = IPSet()
        result._cidrs = result_cidrs
        return result

    __and__ = intersection

    def symmetric_difference(self, other):
        """
        :param other: an IP set.

        :return: the symmetric difference of this IP set and another as a new
            IP set (all IP addresses and subnets that are in exactly one
            of the sets).
        """
        # In contrast to intersection() and difference(), we cannot construct
        # the result_cidrs easily. Some cidrs may have to be merged, e.g. for
        # IPSet(["10.0.0.0/32"]).symmetric_difference(IPSet(["10.0.0.1/32"])).
        result_ranges = []

        own_nets = sorted(self._cidrs)
        other_nets = sorted(other._cidrs)
        own_idx = 0
        other_idx = 0
        own_len = len(own_nets)
        other_len = len(other_nets)
        while own_idx < own_len and other_idx < other_len:
            own_cur = own_nets[own_idx]
            other_cur = other_nets[other_idx]

            if own_cur == other_cur:
                own_idx += 1
                other_idx += 1
            elif own_cur in other_cur:
                own_idx = _subtract(other_cur, own_nets, own_idx, result_ranges)
                other_idx += 1
            elif other_cur in own_cur:
                other_idx = _subtract(own_cur, other_nets, other_idx, result_ranges)
                own_idx += 1
            else:
                # own_cur and other_cur have nothing in common
                if own_cur < other_cur:
                    result_ranges.append((own_cur._module.version, own_cur.first, own_cur.last))
                    own_idx += 1
                else:
                    result_ranges.append(
                        (other_cur._module.version, other_cur.first, other_cur.last)
                    )
                    other_idx += 1

        # If the above loop terminated because it processed all cidrs of
        # "other", then any remaining cidrs in self must be part of the result.
        while own_idx < own_len:
            own_cur = own_nets[own_idx]
            result_ranges.append((own_cur._module.version, own_cur.first, own_cur.last))
            own_idx += 1

        # If the above loop terminated because it processed all cidrs of
        # self, then any remaining cidrs in "other" must be part of the result.
        while other_idx < other_len:
            other_cur = other_nets[other_idx]
            result_ranges.append((other_cur._module.version, other_cur.first, other_cur.last))
            other_idx += 1

        result = IPSet()
        for start, stop in _iter_merged_ranges(result_ranges):
            cidrs = iprange_to_cidrs(start, stop)
            for cidr in cidrs:
                result._cidrs[cidr] = True
        return result

    __xor__ = symmetric_difference

    def difference(self, other):
        """
        :param other: an IP set.

        :return: the difference between this IP set and another as a new IP
            set (all IP addresses and subnets that are in this IP set but
            not found in the other.)
        """
        result_ranges = []
        result_cidrs = {}

        own_nets = sorted(self._cidrs)
        other_nets = sorted(other._cidrs)
        own_idx = 0
        other_idx = 0
        own_len = len(own_nets)
        other_len = len(other_nets)
        while own_idx < own_len and other_idx < other_len:
            own_cur = own_nets[own_idx]
            other_cur = other_nets[other_idx]

            if own_cur == other_cur:
                own_idx += 1
                other_idx += 1
            elif own_cur in other_cur:
                own_idx += 1
            elif other_cur in own_cur:
                other_idx = _subtract(own_cur, other_nets, other_idx, result_ranges)
                own_idx += 1
            else:
                # own_cur and other_cur have nothing in common
                if own_cur < other_cur:
                    result_cidrs[own_cur] = True
                    own_idx += 1
                else:
                    other_idx += 1

        # If the above loop terminated because it processed all cidrs of
        # "other", then any remaining cidrs in self must be part of the result.
        while own_idx < own_len:
            result_cidrs[own_nets[own_idx]] = True
            own_idx += 1

        for start, stop in _iter_merged_ranges(result_ranges):
            for cidr in iprange_to_cidrs(start, stop):
                result_cidrs[cidr] = True

        result = IPSet()
        result._cidrs = result_cidrs
        return result

    __sub__ = difference

    def __len__(self):
        """
        :return: the cardinality of this IP set (i.e. sum of individual IP \
            addresses). Raises ``IndexError`` if size > maxsize (a Python \
            limitation). Use the .size property for subnets of any size.
        """
        size = self.size
        if size > _sys.maxsize:
            raise IndexError(
                'range contains more than %d (sys.maxsize) IP addresses!'
                'Use the .size property instead.' % _sys.maxsize
            )
        return size

    @property
    def size(self):
        """
        The cardinality of this IP set (based on the number of individual IP
        addresses including those implicitly defined in subnets).
        """
        return sum([cidr.size for cidr in self._cidrs])

    def __repr__(self):
        """:return: Python statement to create an equivalent object"""
        return 'IPSet(%r)' % [str(c) for c in sorted(self._cidrs)]

    __str__ = __repr__

    def iscontiguous(self):
        """
        Returns True if the members of the set form a contiguous IP
        address range (with no gaps), False otherwise.

        :return: ``True`` if the ``IPSet`` object is contiguous.
        """
        cidrs = self.iter_cidrs()
        if len(cidrs) > 1:
            previous = cidrs[0][0]
            for cidr in cidrs:
                if cidr[0] != previous:
                    return False
                previous = cidr[-1] + 1
        return True

    def iprange(self):
        """
        Generates an IPRange for this IPSet, if all its members
        form a single contiguous sequence.

        Raises ``ValueError`` if the set is not contiguous.

        :return: An ``IPRange`` for all IPs in the IPSet.
        """
        if self.iscontiguous():
            cidrs = self.iter_cidrs()
            if not cidrs:
                return None
            return IPRange(cidrs[0][0], cidrs[-1][-1])
        else:
            raise ValueError('IPSet is not contiguous')

    def iter_ipranges(self):
        """Generate the merged IPRanges for this IPSet.

        In contrast to self.iprange(), this will work even when the IPSet is
        not contiguous. Adjacent IPRanges will be merged together, so you
        get the minimal number of IPRanges.
        """
        sorted_ranges = [
            (cidr._module.version, cidr.first, cidr.last) for cidr in self.iter_cidrs()
        ]

        for start, stop in _iter_merged_ranges(sorted_ranges):
            yield IPRange(start, stop)

    def summarize_cidrs(self, forbidden, max_rules):
        """
        Summarize this IP set into at most ``max_rules`` CIDRs while avoiding
        every address in ``forbidden``.

        See :func:`cidr_summarize` for the optimization and tie-breaking
        rules.

        :param forbidden: an :class:`IPSet` or iterable of addresses and
            networks that may not be covered.

        :param max_rules: maximum total number of CIDRs.

        :return: a :class:`CIDRSummary`.
        """
        return cidr_summarize(self, forbidden, max_rules)

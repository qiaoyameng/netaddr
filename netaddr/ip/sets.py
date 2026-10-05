# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""Set based operations for IP addresses and subnets."""

import itertools as _itertools
import operator as _operator
import sys as _sys
from bisect import bisect_right as _bisect_right

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

    def ordinal_view(self):
        """
        :return: an immutable :class:`IPSetOrdinalView` of the individual IP
            addresses in this IP set. The view snapshots the current set
            contents, so later changes to this IP set do not affect it.
        """
        return IPSetOrdinalView(self)

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


def _slice_length(start, stop, step):
    """Number of elements produced by a normalized (start, stop, step) triple.

    Computed arithmetically so it works for values exceeding sys.maxsize,
    where len(range(start, stop, step)) would raise OverflowError.
    """
    if step > 0:
        if stop <= start:
            return 0
        return (stop - start + step - 1) // step
    if start <= stop:
        return 0
    return (start - stop - step - 1) // (-step)


class IPSetOrdinalView(object):
    """
    An immutable, indexable view of the individual IP addresses of an IP set.

    Addresses are ordered numerically, with all IPv4 addresses sorting before
    all IPv6 addresses. The view snapshots the set's CIDR blocks when it is
    created, so subsequent changes to the source IP set do not affect it.

    Indexing, ranking and slicing are computed arithmetically from CIDR
    boundaries in O(log n) time (where n is the number of CIDR blocks), so
    the view works even for sets far too large to enumerate and whose size
    does not fit into a platform integer (use the ``size`` property rather
    than ``len()`` for such sets).
    """

    __slots__ = ('_runs', '_starts', '_offsets', '_size')

    def __init__(self, ipset):
        """
        Constructor.

        :param ipset: the IP set to snapshot.
        """
        runs = []
        starts = []
        offsets = [0]
        total = 0
        for cidr in ipset.iter_cidrs():
            version = cidr.version
            first = cidr.first
            last = cidr.last
            runs.append((version, first, last))
            starts.append((version, first))
            total += last - first + 1
            offsets.append(total)
        self._runs = tuple(runs)
        self._starts = tuple(starts)
        self._offsets = tuple(offsets)
        self._size = total

    @property
    def size(self):
        """The number of individual IP addresses in this view."""
        return self._size

    def __len__(self):
        size = self._size
        if size > _sys.maxsize:
            raise IndexError(
                'view contains more than %d (sys.maxsize) IP addresses!'
                'Use the .size property instead.' % _sys.maxsize
            )
        return size

    def _address_at(self, ordinal):
        """Address at non-negative ordinal, without bounds checking."""
        run_idx = _bisect_right(self._offsets, ordinal) - 1
        version, first, _ = self._runs[run_idx]
        return IPAddress(first + (ordinal - self._offsets[run_idx]), version)

    def __getitem__(self, index):
        """
        :param index: an integer index (negative indices count back from the
            end) or a slice. Slices may use any non-zero step, in either
            direction, and are returned as lazy views that do not
            materialize their addresses up front.

        :return: an ``IPAddress`` for integer indexes, or a lazy slice view
            for slices.
        """
        if isinstance(index, slice):
            start, stop, step = index.indices(self._size)
            return _OrdinalSlice(self, start, stop, step)
        index = _operator.index(index)
        if index < 0:
            index += self._size
        if not 0 <= index < self._size:
            raise IndexError('IP set ordinal view index out of range')
        return self._address_at(index)

    def __iter__(self):
        """
        :return: an iterator over the IP addresses in this view, in order.
        """
        return iter(_OrdinalSlice(self, 0, self._size, 1))

    def __contains__(self, ip):
        """
        :param ip: an IP address.

        :return: ``True`` if the IP address is a member of this view.
        """
        try:
            self.rank(ip)
            return True
        except ValueError:
            return False

    def rank(self, ip):
        """
        The ordinal position of a member IP address within this view.

        :param ip: an IP address that is a member of the viewed set.

        :return: the zero-based index of the address in the view's ordering.

        :raises ValueError: if the address is not a member of the viewed set.
        """
        ip = IPAddress(ip)
        run_idx = _bisect_right(self._starts, (ip.version, ip.value)) - 1
        if run_idx >= 0:
            version, first, last = self._runs[run_idx]
            if version == ip.version and first <= ip.value <= last:
                return self._offsets[run_idx] + (ip.value - first)
        raise ValueError('%r is not a member of this IP set view' % (ip,))

    def insertion_index(self, ip):
        """
        The number of members of this view that sort before the given IP
        address. For a member this equals its rank; for a non-member it is
        the index at which the address would be inserted to keep the view
        ordered (``bisect_left`` semantics). The address does not need to be
        a member of the viewed set.

        :param ip: an IP address.

        :return: the count of members strictly less than the address.
        """
        ip = IPAddress(ip)
        run_idx = _bisect_right(self._starts, (ip.version, ip.value)) - 1
        if run_idx < 0:
            return 0
        version, first, last = self._runs[run_idx]
        if version != ip.version:
            # All runs up to and including run_idx belong to an earlier IP
            # version, so every one of their members sorts before ip.
            return self._offsets[run_idx + 1]
        if ip.value <= first:
            return self._offsets[run_idx]
        if ip.value > last:
            return self._offsets[run_idx + 1]
        return self._offsets[run_idx] + (ip.value - first)

    def __repr__(self):
        return '%s(%r)' % (self.__class__.__name__, self._runs)


class _OrdinalSlice(object):
    """
    A lazy, immutable stepped view over an :class:`IPSetOrdinalView`.

    Created by slicing an ordinal view (or another slice); addresses are
    produced on demand and never materialized up front.
    """

    __slots__ = ('_view', '_start', '_stop', '_step', '_size')

    def __init__(self, view, start, stop, step):
        self._view = view
        self._start = start
        self._stop = stop
        self._step = step
        self._size = _slice_length(start, stop, step)

    @property
    def size(self):
        """The number of individual IP addresses in this slice."""
        return self._size

    def __len__(self):
        size = self._size
        if size > _sys.maxsize:
            raise IndexError(
                'slice contains more than %d (sys.maxsize) IP addresses!'
                'Use the .size property instead.' % _sys.maxsize
            )
        return size

    def __getitem__(self, index):
        if isinstance(index, slice):
            start, stop, step = index.indices(self._size)
            return _OrdinalSlice(
                self._view,
                self._start + start * self._step,
                self._start + stop * self._step,
                self._step * step,
            )
        index = _operator.index(index)
        if index < 0:
            index += self._size
        if not 0 <= index < self._size:
            raise IndexError('IP set ordinal slice index out of range')
        return self._view._address_at(self._start + index * self._step)

    def __iter__(self):
        runs = self._view._runs
        offsets = self._view._offsets
        step = self._step
        stop = self._stop
        pos = self._start
        if step > 0:
            run_indices = range(len(runs))
        else:
            run_indices = range(len(runs) - 1, -1, -1)
        for run_idx in run_indices:
            version, first, _ = runs[run_idx]
            base = offsets[run_idx]
            lo = base
            hi = offsets[run_idx + 1] - 1
            if step > 0:
                # Positions in this slice satisfy pos < stop.
                if hi >= stop:
                    hi = stop - 1
                if pos > hi:
                    continue
                if pos < lo:
                    pos += ((lo - pos + step - 1) // step) * step
                while pos <= hi:
                    yield IPAddress(first + (pos - base), version)
                    pos += step
            else:
                # Positions in this slice satisfy pos > stop.
                if lo <= stop:
                    lo = stop + 1
                if pos < lo:
                    continue
                if pos > hi:
                    pos -= ((pos - hi - step - 1) // (-step)) * (-step)
                while pos >= lo:
                    yield IPAddress(first + (pos - base), version)
                    pos += step

    def __repr__(self):
        return '%s(%r, %r, %r, %r)' % (
            self.__class__.__name__,
            self._view,
            self._start,
            self._stop,
            self._step,
        )

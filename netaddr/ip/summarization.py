# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""
CIDR summarisation under a hard rule limit.

Given a set of target IP addresses/subnets and a forbidden set that must
never be covered, choose at most ``max_rules`` CIDR blocks so that:

* every target address is covered;
* no forbidden address is covered;
* the number of extra (non-target) addresses covered is minimised;
* ties are broken deterministically (fewest rules, then lexicographically
  smallest sorted list of CIDRs).

IPv4 and IPv6 are computed independently; the integer space itself is
never enumerated. The algorithm is a binary trie with dynamic programming
over the number of rules, so running time depends on the number of prefix
boundaries and not on the (potentially astronomically large) address space.
"""

from netaddr.ip import IPNetwork
from netaddr.ip.sets import IPSet

__all__ = [
    'ExtraRange',
    'AggregationResult',
    'summarize_ipset',
    'summarize_ipsets',
]


class ExtraRange(object):
    """A non-target CIDR that an aggregation is forced to cover."""

    __slots__ = ('cidr', 'size', 'rule')

    def __init__(self, cidr, size, rule):
        self.cidr = cidr
        self.size = size
        self.rule = rule

    def __repr__(self):
        return 'ExtraRange(%r, %r, %r)' % (self.cidr, self.size, self.rule)

    def __eq__(self, other):
        return (
            isinstance(other, ExtraRange)
            and self.cidr == other.cidr
            and self.size == other.size
            and self.rule == other.rule
        )

    def __hash__(self):
        return hash((self.cidr, self.size, self.rule))


class AggregationResult(object):
    """
    Outcome of a CIDR summarisation.

    When a feasible aggregation exists, ``feasible`` is ``True`` and the
    ``rules`` attribute holds the chosen CIDR blocks. Otherwise ``rules``
    is empty and ``minimum_rules`` gives the smallest rule count for which a
    cover respecting the forbidden set exists.
    """

    __slots__ = (
        'feasible',
        'version',
        'rules',
        'max_rules',
        'extra_addresses',
        'extra_ranges',
        'target_addresses',
        'covered_addresses',
        'minimum_rules',
    )

    def __init__(
        self,
        feasible,
        version,
        rules,
        max_rules,
        extra_addresses,
        extra_ranges,
        target_addresses,
        covered_addresses,
        minimum_rules,
    ):
        self.feasible = feasible
        self.version = version
        self.rules = rules
        self.max_rules = max_rules
        self.extra_addresses = extra_addresses
        self.extra_ranges = extra_ranges
        self.target_addresses = target_addresses
        self.covered_addresses = covered_addresses
        self.minimum_rules = minimum_rules

    def __repr__(self):
        status = 'feasible' if self.feasible else 'infeasible'
        return 'AggregationResult(%s, v%d, rules=%r, extra=%r)' % (
            status,
            self.version,
            [str(c) for c in self.rules],
            self.extra_addresses,
        )

    def __eq__(self, other):
        if not isinstance(other, AggregationResult):
            return NotImplemented
        return (
            self.feasible == other.feasible
            and self.version == other.version
            and self.rules == other.rules
            and self.max_rules == other.max_rules
            and self.extra_addresses == other.extra_addresses
            and self.extra_ranges == other.extra_ranges
            and self.target_addresses == other.target_addresses
            and self.covered_addresses == other.covered_addresses
            and self.minimum_rules == other.minimum_rules
        )

    def to_dict(self):
        """
        Return a plain ``dict`` representation.

        Large cardinalities (up to ``2 ** 128``) remain exact Python
        integers; callers that need JSON should format them explicitly.
        """
        return {
            'feasible': self.feasible,
            'version': self.version,
            'rules': [str(c) for c in self.rules],
            'max_rules': self.max_rules,
            'extra_addresses': self.extra_addresses,
            'extra_ranges': [
                {
                    'cidr': str(x.cidr),
                    'size': x.size,
                    'rule': str(x.rule),
                }
                for x in self.extra_ranges
            ],
            'target_addresses': self.target_addresses,
            'covered_addresses': self.covered_addresses,
            'minimum_rules': self.minimum_rules,
        }


# -----------------------------------------------------------------------------
#   Helpers operating on integer intervals (no address-space enumeration).
# -----------------------------------------------------------------------------


def _merge_intervals(intervals):
    """Merge overlapping/adjacent (lo, hi) integer intervals (inclusive)."""
    merged = []
    for lo, hi in sorted(intervals):
        if merged and lo <= merged[-1][1] + 1:
            if hi > merged[-1][1]:
                merged[-1] = (merged[-1][0], hi)
        else:
            merged.append((lo, hi))
    return merged


def _intervals_overlap(a_intervals, b_intervals):
    """``True`` iff two lists of disjoint, sorted intervals intersect."""
    i = j = 0
    while i < len(a_intervals) and j < len(b_intervals):
        lo_a, hi_a = a_intervals[i]
        lo_b, hi_b = b_intervals[j]
        if lo_a <= hi_b and lo_b <= hi_a:
            return True
        if hi_a < hi_b:
            i += 1
        else:
            j += 1
    return False


def _subtract_intervals(lo, hi, holes):
    """Subtract disjoint sorted inclusive ``holes`` from ``[lo, hi]``."""
    fragments = []
    cursor = lo
    for hole_lo, hole_hi in holes:
        if hole_hi < cursor:
            continue
        if hole_lo > hi:
            break
        if hole_lo > cursor:
            fragments.append((cursor, min(hole_lo - 1, hi)))
        cursor = max(cursor, hole_hi + 1)
        if cursor > hi:
            break
    if cursor <= hi:
        fragments.append((cursor, hi))
    return fragments


def _intervals_to_cidrs(intervals, bits):
    """Convert inclusive integer intervals into minimal aligned CIDR tuples."""
    cidrs = []
    for lo, hi in intervals:
        cur = lo
        while cur <= hi:
            max_host_bits = (cur & -cur).bit_length() - 1 if cur else bits
            remaining = (hi - cur + 1).bit_length() - 1
            host_bits = min(max_host_bits, remaining)
            prefix_len = bits - host_bits
            cidrs.append((cur, prefix_len))
            cur += 1 << host_bits
    return cidrs


# -----------------------------------------------------------------------------
#   Binary trie over prefixes; each node covers an aligned address block.
# -----------------------------------------------------------------------------


class _Node(object):

    __slots__ = (
        'address',
        'depth',
        'children',
        'whole_target',
        'whole_forbidden',
        'block_size',
        'target_size',
        'min_rules',
    )

    def __init__(self, address, depth, block_size):
        self.address = address
        self.depth = depth
        self.children = None
        #   'whole_*' is True when the *entire* block is marked.
        self.whole_target = False
        self.whole_forbidden = False
        self.block_size = block_size
        self.target_size = 0
        self.min_rules = None


def _build_trie(target_cidrs, forbidden_cidrs, bits):
    """
    Insert CIDR prefixes into a lazy binary trie.

    The trie only contains nodes on paths reachable from inserted prefixes,
    so its size is linear in the number of prefix boundaries, independent
    of ``2 ** bits``.
    """
    root = _Node(0, 0, 1 << bits)

    def insert(cidrs, attribute):
        for prefix_addr, prefix_len in cidrs:
            node = root
            for depth in range(1, prefix_len + 1):
                bit = (prefix_addr >> (bits - depth)) & 1
                if node.children is None:
                    node.children = [None, None]
                child = node.children[bit]
                if child is None:
                    child_block = node.block_size >> 1
                    bit_addr = node.address | (bit << (bits - depth))
                    child = _Node(bit_addr, depth, child_block)
                    node.children[bit] = child
                node = child
            setattr(node, attribute, True)

    insert(target_cidrs, 'whole_target')
    insert(forbidden_cidrs, 'whole_forbidden')

    #   Bottom-up propagation of exact sizes and minimum rule counts.
    stack = [root]
    postorder = []
    while stack:
        node = stack.pop()
        postorder.append(node)
        if node.children is not None:
            for child in node.children:
                if child is not None:
                    stack.append(child)

    for node in reversed(postorder):
        if node.whole_target:
            node.target_size = node.block_size
            node.min_rules = 1
        elif node.children is None:
            node.target_size = 0
            node.min_rules = 0
        else:
            total = 0
            min_rules = 0
            for child in node.children:
                if child is None:
                    continue
                total += child.target_size
                min_rules += child.min_rules
            node.target_size = total
            node.min_rules = min_rules
    return root




# -----------------------------------------------------------------------------
#   Trie solver: dynamic program over rule counts (prefix structure only).
# -----------------------------------------------------------------------------


class _TrieSolver(object):
    """
    DP over the prefix trie, parameterised by the address-family width.

    Cost DP
        Every node maps an exact rule count to the minimum extra-address
        cost (plain knapsack convolution over its children), with a
        ``('self',)`` / ``('split',)`` choice marker. The cost tables are
        the only O(K^2) structure; they never enumerate addresses.

    Deterministic tie-break
        For a fixed (rule count, minimum cost) the winner is the
        lexicographically smallest sorted CIDR tuple. Selected blocks are
        disjoint and appear in trie (address) order, so reconstruction
        walks children left-to-right and greedily commits to the smallest
        allocation that keeps a suffix able to consume the *exact* remaining
        rule count and cost, then recurses.
    """

    def __init__(self, root, bits, max_rules):
        self.root = root
        self.bits = bits
        self.max_rules = max_rules
        self._forbidden_memo = {}
        self._cost_memo = {}
        self._reach_memo = {}

    # ------------------------------------------------------------------
    #   Forbidden-ancestor flag.
    # ------------------------------------------------------------------

    def has_forbidden(self, node):
        idx = id(node)
        if idx in self._forbidden_memo:
            return self._forbidden_memo[idx]
        if node.whole_forbidden:
            result = True
        elif node.children is None:
            result = False
        else:
            result = any(
                child is not None and self.has_forbidden(child)
                for child in node.children
            )
        self._forbidden_memo[idx] = result
        return result

    # ------------------------------------------------------------------
    #   Cost DP.
    # ------------------------------------------------------------------

    def cost_dp(self, node):
        idx = id(node)
        if idx in self._cost_memo:
            return self._cost_memo[idx]

        if node.whole_target:
            result = {1: (0, ('self',))}
        elif node.children is None:
            result = {0: (0, ('split',))}
        else:
            children = [c for c in node.children if c is not None]
            combined = {0: 0}
            for child in children:
                child_dp = self.cost_dp(child)
                new_combined = {}
                for r1, c1 in combined.items():
                    for r2, (c2, _) in child_dp.items():
                        rules = r1 + r2
                        if rules > self.max_rules:
                            continue
                        cost = c1 + c2
                        if rules not in new_combined or cost < new_combined[rules]:
                            new_combined[rules] = cost
                combined = new_combined

            result = {
                rules: (cost, ('split',))
                for rules, cost in combined.items()
            }

            if node.target_size and not self.has_forbidden(node):
                cost = node.block_size - node.target_size
                old = result.get(1)
                if old is None or cost < old[0]:
                    result[1] = (cost, ('self',))

            kept = {}
            prefix_min = None
            for rules in sorted(result):
                cost = result[rules][0]
                if prefix_min is None or cost < prefix_min:
                    kept[rules] = result[rules]
                    prefix_min = cost
            result = kept

        self._cost_memo[idx] = result
        return result

    # ------------------------------------------------------------------
    #   Exact suffix reachability: for children[i:] of a node, the set of
    #   achievable (rule_count, exact_cost) pairs.
    # ------------------------------------------------------------------

    def _suffix_reach(self, node, i):
        key = (id(node), i)
        if key in self._reach_memo:
            return self._reach_memo[key]

        children = [c for c in node.children if c is not None]
        if i == len(children):
            result = {(0, 0)}
        else:
            child_dp = self.cost_dp(children[i])
            later = self._suffix_reach(node, i + 1)
            result = set()
            for r1, (c1, _) in child_dp.items():
                for r2, c2 in later:
                    rules = r1 + r2
                    if rules <= self.max_rules:
                        result.add((rules, c1 + c2))

        self._reach_memo[key] = result
        return result

    # ------------------------------------------------------------------
    #   Greedy lexicographic reconstruction.
    # ------------------------------------------------------------------

    def reconstruct(self, node, count, cost):
        if node.whole_target:
            if count == 1 and cost == 0:
                return ((node.address, node.depth),)
            return None
        if node.children is None:
            return () if count == 0 and cost == 0 else None

        dp = self.cost_dp(node)
        if dp.get(count, (None,))[0] != cost:
            return None

        #   Selecting the node block gives the smallest possible first CIDR
        #   (the block start precedes every descendant CIDR start).
        if (
            count == 1
            and node.target_size
            and not self.has_forbidden(node)
            and node.block_size - node.target_size == cost
        ):
            return ((node.address, node.depth),)

        children = [c for c in node.children if c is not None]
        chosen = []
        remaining_rules = count
        remaining_cost = cost
        for pos, child in enumerate(children):
            suffix = self._suffix_reach(node, pos + 1)
            commit = None
            for rules, (child_cost, _) in sorted(
                self.cost_dp(child).items()
            ):
                if rules > remaining_rules or child_cost > remaining_cost:
                    continue
                needed = (
                    remaining_rules - rules,
                    remaining_cost - child_cost,
                )
                if needed in suffix:
                    commit = (rules, child_cost)
                    break
            if commit is None:
                return None
            chosen.append((child, commit[0], commit[1]))
            remaining_rules -= commit[0]
            remaining_cost -= commit[1]

        if remaining_rules != 0 or remaining_cost != 0:
            return None

        result = []
        for child, rules, child_cost in chosen:
            part = self.reconstruct(child, rules, child_cost)
            if part is None:
                return None
            result.extend(part)
        return tuple(result)

    def rules_for(self, node, count):
        entry = self.cost_dp(node).get(count)
        if entry is None:
            return None
        return self.reconstruct(node, count, entry[0])


# -----------------------------------------------------------------------------
#   Public API
# -----------------------------------------------------------------------------


def _as_intervals(ipset, version):
    intervals = []
    for cidr in ipset.iter_cidrs():
        if cidr.version != version:
            raise ValueError(
                'target and forbidden sets must belong to the same IP '
                'version; mixed IPv4/IPv6 input is not allowed within one '
                'call (got IPv%d entries among IPv%d)'
                % (cidr.version, version)
            )
        intervals.append((cidr.first, cidr.last))
    return _merge_intervals(intervals)


def _cidr_key(cidr):
    return (cidr.first, cidr.prefixlen)


def _aggregate_version(targets, forbidden, max_rules, version):
    bits = 32 if version == 4 else 128

    target_intervals = _as_intervals(targets, version)
    forbidden_intervals = _as_intervals(forbidden, version)

    if _intervals_overlap(target_intervals, forbidden_intervals):
        raise ValueError(
            'target and forbidden sets must be disjoint: a forbidden '
            'address is itself a target, so no cover can exist'
        )

    target_addresses = sum(hi - lo + 1 for lo, hi in target_intervals)

    if not target_intervals:
        return AggregationResult(
            feasible=True,
            version=version,
            rules=[],
            max_rules=max_rules,
            extra_addresses=0,
            extra_ranges=[],
            target_addresses=0,
            covered_addresses=0,
            minimum_rules=0,
        )

    target_prefixes = _intervals_to_cidrs(target_intervals, bits)
    forbidden_prefixes = _intervals_to_cidrs(forbidden_intervals, bits)
    root = _build_trie(target_prefixes, forbidden_prefixes, bits)

    solver = _TrieSolver(root, bits, max_rules)
    root_state = solver.cost_dp(root)
    minimum_rules = root.min_rules

    feasible_counts = [rules for rules in root_state if rules <= max_rules]
    if not feasible_counts:
        return AggregationResult(
            feasible=False,
            version=version,
            rules=[],
            max_rules=max_rules,
            extra_addresses=None,
            extra_ranges=None,
            target_addresses=target_addresses,
            covered_addresses=None,
            minimum_rules=minimum_rules,
        )

    #   DP pruning leaves one best cost per rule count; minimise extra
    #   addresses first, then rule count, then lexicographic CIDR order.
    best_count = min(
        feasible_counts, key=lambda r: (root_state[r][0], r)
    )
    chosen = solver.rules_for(root, best_count)

    rule_networks = [
        IPNetwork((address, prefix_len), version=version)
        for address, prefix_len in chosen
    ]
    rule_networks.sort(key=_cidr_key)

    covered_addresses = sum(cidr.size for cidr in rule_networks)
    extra_addresses = covered_addresses - target_addresses

    #   Extra ranges: every selected rule block minus target/forbidden
    #   addresses. Rules are disjoint, so each leftover fragment belongs to
    #   exactly one rule. Computed with integer interval subtraction -- no
    #   per-rule IPSet operation and no address enumeration.
    extra_ranges = []
    for rule in rule_networks:
        fragments = _subtract_intervals(
            rule.first, rule.last, target_intervals
        )
        for addr, prefix_len in _intervals_to_cidrs(fragments, bits):
            cidr = IPNetwork((addr, prefix_len), version=version)
            extra_ranges.append(
                ExtraRange(cidr=cidr, size=cidr.size, rule=rule)
            )

    return AggregationResult(
        feasible=True,
        version=version,
        rules=rule_networks,
        max_rules=max_rules,
        extra_addresses=extra_addresses,
        extra_ranges=extra_ranges,
        target_addresses=target_addresses,
        covered_addresses=covered_addresses,
        minimum_rules=minimum_rules,
    )


def _coerce_ipset(value):
    if value is None:
        return IPSet()
    if isinstance(value, IPSet):
        return value
    if isinstance(value, (list, tuple, set, frozenset)):
        return IPSet(value)
    raise TypeError(
        'expected an IPSet or an iterable of IP addresses/networks, got %r'
        % type(value).__name__
    )


def summarize_ipset(targets, forbidden=None, max_rules=4096):
    """
    Summarise one IP version under a hard CIDR rule limit.

    :param targets: an :class:`~netaddr.IPSet` (or iterable of IP
        addresses/networks) whose addresses must all be covered.
    :param forbidden: an :class:`~netaddr.IPSet` (or iterable) of addresses
        that must never be covered.
    :param max_rules: maximum number of CIDR rules allowed; the result never
        contains more rules than this. Must be a positive integer.
    :return: an :class:`AggregationResult`.

    A ``ValueError`` is raised when the inputs mix IP versions, when a
    target address is also forbidden, or when ``max_rules`` is not positive.
    When no cover exists within the rule limit the result's ``feasible``
    flag is ``False`` (and ``minimum_rules`` reports the true minimum).

    >>> from netaddr import IPSet
    >>> result = summarize_ipset(
    ...     IPSet(['10.0.0.1/32', '10.0.0.2/32']),
    ...     IPSet(['10.0.0.3/32']),
    ...     max_rules=1,
    ... )
    >>> result.feasible
    False
    >>> result.minimum_rules
    2
    >>> result = summarize_ipset(
    ...     IPSet(['10.0.0.1/32', '10.0.0.2/32']),
    ...     IPSet(['10.0.0.3/32']),
    ...     max_rules=2,
    ... )
    >>> [str(c) for c in result.rules]
    ['10.0.0.1/32', '10.0.0.2/32']
    >>> result.extra_addresses
    0
    """
    if not isinstance(max_rules, int) or isinstance(max_rules, bool):
        raise TypeError('max_rules must be an int')
    if max_rules <= 0:
        raise ValueError('max_rules must be a positive integer')

    targets = _coerce_ipset(targets)
    forbidden = _coerce_ipset(forbidden)

    target_cidrs = targets.iter_cidrs()
    forbidden_cidrs = forbidden.iter_cidrs()
    versions = {c.version for c in target_cidrs}
    versions.update(c.version for c in forbidden_cidrs)

    if not versions:
        raise ValueError(
            'cannot determine IP version from empty targets and forbidden; '
            'use summarize_ipsets or provide at least one entry'
        )
    if len(versions) > 1:
        raise ValueError(
            'summarize_ipset handles one IP version at a time; use '
            'summarize_ipsets to aggregate IPv4 and IPv6 independently'
        )

    return _aggregate_version(targets, forbidden, max_rules, versions.pop())


def summarize_ipsets(targets, forbidden=None, max_rules=4096):
    """
    Summarise :class:`~netaddr.IPSet` inputs, handling IPv4 and IPv6
    independently.

    :return: a dict keyed by IP version (``4`` and/or ``6``) holding one
        :class:`AggregationResult` per version that contains targets.
        Versions with no targets are omitted.

    >>> from netaddr import IPSet
    >>> result = summarize_ipsets(IPSet(['192.0.2.0/24', '2001:db8::/48']))
    >>> sorted(result)
    [4, 6]
    >>> [str(c) for c in result[4].rules]
    ['192.0.2.0/24']
    >>> [str(c) for c in result[6].rules]
    ['2001:db8::/48']
    """
    if not isinstance(max_rules, int) or isinstance(max_rules, bool):
        raise TypeError('max_rules must be an int')
    if max_rules <= 0:
        raise ValueError('max_rules must be a positive integer')

    targets = _coerce_ipset(targets)
    forbidden = _coerce_ipset(forbidden)

    results = {}
    for version in (4, 6):
        version_targets = IPSet(
            c for c in targets.iter_cidrs() if c.version == version
        )
        if not version_targets.iter_cidrs():
            continue
        version_forbidden = IPSet(
            c for c in forbidden.iter_cidrs() if c.version == version
        )
        results[version] = _aggregate_version(
            version_targets, version_forbidden, max_rules, version
        )
    return results

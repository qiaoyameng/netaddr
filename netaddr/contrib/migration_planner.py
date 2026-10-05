# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""
A datacentre migration planner.

Maps legacy ("source") address ranges onto new ("target") ranges while
preserving the offset every address has inside its source range.  Only
integer range arithmetic is used: address ranges are never expanded into
individual addresses, so IPv6-scale inputs stay cheap.

A migration is *executable* only when every check passes.  Plans that fail a
check are reported as conflicts and are never exposed as executable results.
Cross-family (IPv4 <-> IPv6) migration is rejected unless explicitly
enabled, and it never silently drops the address offset.
"""

from netaddr import AddrFormatError
from netaddr.ip import IPAddress, IPNetwork, IPRange

__all__ = [
    'MigrationPlanner',
    'MigrationPair',
    'MigrationPlan',
    'MigrationReport',
    'Conflict',
    'ConflictKind',
    'LookupStatus',
    'LookupResult',
    'plan_migrations',
    'intersect_ranges',
    'coerce_range',
]


class ConflictKind(object):
    """Categories that can make a migration pair non-executable."""

    SOURCE_OVERLAP = 'source_overlap'
    INSUFFICIENT_TARGET_CAPACITY = 'insufficient_target_capacity'
    ADDRESS_FAMILY_MISMATCH = 'address_family_mismatch'
    TARGET_OCCUPIED = 'target_occupied'
    TARGET_FORBIDDEN = 'target_forbidden'
    TARGET_COLLISION = 'target_collision'


class LookupStatus(object):
    """Outcome of a forward/reverse single-address lookup."""

    MAPPED = 'mapped'
    NOT_MIGRATED = 'not_migrated'
    UNUSED_TARGET = 'unused_target'
    CONFLICT = 'conflict'


def coerce_range(value):
    """
    Normalise CIDRs, networks, address ranges and ``start-end`` strings into
    a single :class:`IPRange`. No addresses are enumerated.

    :param value: an :class:`IPNetwork`, :class:`IPRange`, ``(start, end)``
        pair or string in CIDR or ``start-end`` notation.
    :return: an :class:`IPRange` covering exactly the given addresses.
    """
    if isinstance(value, IPRange):
        return value
    if isinstance(value, IPNetwork):
        return IPRange(IPAddress(value.first, value.version),
                       IPAddress(value.last, value.version))
    if isinstance(value, tuple) and len(value) == 2:
        return IPRange(value[0], value[1])
    if isinstance(value, str):
        text = value.strip()
        if '/' in text:
            network = IPNetwork(text)
            return IPRange(IPAddress(network.first, network.version),
                           IPAddress(network.last, network.version))
        if '-' in text:
            start, end = text.split('-', 1)
            return IPRange(start.strip(), end.strip())
    raise AddrFormatError('unsupported IP range format: %r' % (value,))


def intersect_ranges(left, right):
    """
    :param left: an :class:`IPRange`.
    :param right: an :class:`IPRange`.
    :return: the :class:`IPRange` where the two inputs genuinely overlap,
        or ``None`` when they belong to different address families or do not
        intersect. Pure integer interval arithmetic; addresses are not
        expanded.
    """
    if left.version != right.version:
        return None
    first = max(left.first, right.first)
    last = min(left.last, right.last)
    if first <= last:
        return IPRange(IPAddress(first, left.version), IPAddress(last, left.version))
    return None


class MigrationPair(object):
    """
    A requested mapping of one source range onto one target range.

    :param source: source (legacy) range in any form accepted by
        :func:`coerce_range`.
    :param target: target (new) range in any form accepted by
        :func:`coerce_range`.
    :param name: optional human readable identifier used in conflict reports.
    """

    __slots__ = ('source', 'target', 'name')

    def __init__(self, source, target, name=None):
        self.source = coerce_range(source)
        self.target = coerce_range(target)
        self.name = name

    def __repr__(self):
        return 'MigrationPair(%r, %r, name=%r)' % (self.source, self.target, self.name)


class Conflict(object):
    """
    A single reason why one or more plans are not executable.

    :ivar kind: one of the :class:`ConflictKind` constants.
    :ivar plans: tuple of :class:`MigrationPlan` objects involved.
    :ivar overlap: :class:`IPRange` of the genuinely overlapping addresses,
        in the address family they collide in, or ``None``.
    :ivar detail: human readable explanation.
    """

    __slots__ = ('kind', 'plans', 'overlap', 'detail')

    def __init__(self, kind, plans, overlap=None, detail=''):
        self.kind = kind
        self.plans = tuple(plans)
        self.overlap = overlap
        self.detail = detail

    def __repr__(self):
        return 'Conflict(%r, plans=%r, overlap=%r)' % (
            self.kind,
            [plan.pair.name for plan in self.plans],
            self.overlap,
        )


class MigrationPlan(object):
    """
    A validated source -> target mapping.

    :ivar pair: the originating :class:`MigrationPair`.
    :ivar used: the :class:`IPRange` actually consumed inside the target
        network: when the target is larger only the prefix portion holding
        ``target.first + source offset`` is occupied.
    """

    __slots__ = ('pair', 'used')

    def __init__(self, pair, used):
        self.pair = pair
        self.used = used

    @property
    def source(self):
        return self.pair.source

    @property
    def target(self):
        return self.pair.target

    def translate(self, address):
        """
        Map an address from the source range to its new location.
        :return: an :class:`IPAddress`.
        """
        offset = int(address) - self.source.first
        return IPAddress(self.used.first, self.used.version) + offset

    def reverse(self, address):
        """
        Map an address from the used target portion back to its source.
        :return: an :class:`IPAddress`.
        """
        offset = int(address) - self.used.first
        return IPAddress(self.source.first, self.source.version) + offset

    def __repr__(self):
        return 'MigrationPlan(%r -> %r)' % (self.pair.source, self.used)


class LookupResult(object):
    """
    Result of a single-address lookup.

    :ivar status: one of the :class:`LookupStatus` constants.
    :ivar address: the :class:`IPAddress` that was looked up.
    :ivar counterpart: mapped/reverse-mapped :class:`IPAddress`, or ``None``.
    :ivar plan: executable :class:`MigrationPlan` serving the address, or
        ``None``.
    :ivar conflicts: tuple of relevant :class:`Conflict` objects.
    """

    __slots__ = ('status', 'address', 'counterpart', 'plan', 'conflicts')

    def __init__(self, status, address, counterpart=None, plan=None, conflicts=()):
        self.status = status
        self.address = address
        self.counterpart = counterpart
        self.plan = plan
        self.conflicts = tuple(conflicts)

    def __bool__(self):
        return self.status == LookupStatus.MAPPED

    def __repr__(self):
        return 'LookupResult(%s, %s -> %s)' % (
            self.status,
            self.address,
            self.counterpart,
        )


class MigrationReport(object):
    """
    Output of a planning run.

    :ivar plans: tuple of executable :class:`MigrationPlan` objects in input
        order. Failed pairs never appear here.
    :ivar conflicts: tuple of :class:`Conflict` objects explaining every
        failed pair and every target overlap.
    """

    __slots__ = ('plans', 'conflicts')

    def __init__(self, plans, conflicts):
        self.plans = tuple(plans)
        self.conflicts = tuple(conflicts)

    @property
    def ok(self):
        """``True`` when every requested pair is executable."""
        return not self.conflicts

    def lookup(self, address):
        """Forward lookup: where does this source address move to?"""
        return _lookup(self, address, reverse=False)

    def reverse_lookup(self, address):
        """Reverse lookup: which source address does this target address come from?"""
        return _lookup(self, address, reverse=True)

    def __repr__(self):
        return 'MigrationReport(plans=%d, conflicts=%d)' % (
            len(self.plans),
            len(self.conflicts),
        )


def _ip(address, version=None):
    if isinstance(address, IPAddress):
        ip = address
    else:
        ip = IPAddress(address, version)
    return ip


def _lookup(report, address, reverse):
    def covers(plan, ip):
        return ip in (plan.used if reverse else plan.source)

    for plan in report.plans:
        anchor = plan.used if reverse else plan.source
        try:
            ip = _ip(address, anchor.version)
        except (AddrFormatError, ValueError):
            continue
        if covers(plan, ip):
            counterpart = plan.reverse(ip) if reverse else plan.translate(ip)
            return LookupResult(LookupStatus.MAPPED, ip, counterpart, plan)

    parsed = _parse_any(address, report)
    if parsed is None:
        return LookupResult(LookupStatus.NOT_MIGRATED, IPAddress(address))

    relevant = []
    for conflict in report.conflicts:
        if _conflict_touches(conflict, parsed, reverse):
            relevant.append(conflict)
    if relevant:
        return LookupResult(LookupStatus.CONFLICT, parsed, conflicts=relevant)

    for plan in report.plans:
        if plan.target.version == parsed.version and parsed in plan.target:
            return LookupResult(LookupStatus.UNUSED_TARGET, parsed)

    return LookupResult(LookupStatus.NOT_MIGRATED, parsed)


def _parse_any(address, report):
    if isinstance(address, IPAddress):
        return address
    versions = {plan.source.version for plan in report.plans}
    versions.update(plan.target.version for plan in report.plans)
    for conflict in report.conflicts:
        for plan in conflict.plans:
            versions.add(plan.pair.source.version)
            versions.add(plan.pair.target.version)
    for version in versions or (4,):
        try:
            return IPAddress(address, version)
        except (AddrFormatError, ValueError):
            continue
    try:
        return IPAddress(address)
    except (AddrFormatError, ValueError):
        return None


def _conflict_touches(conflict, ip, reverse):
    #   A conflict matters only when the queried address actually sits in one
    #   of the ranges the conflict describes, in the queried direction.
    for plan in conflict.plans:
        ranges = [plan.pair.target]
        if plan.used is not None:
            ranges.append(plan.used)
        if not reverse:
            ranges.append(plan.pair.source)
        for range_ in ranges:
            if range_.version == ip.version and range_.first <= int(ip) <= range_.last:
                return True
    if conflict.overlap is not None and conflict.overlap.version == ip.version:
        first = conflict.overlap.first
        last = conflict.overlap.last
        if reverse and first <= int(ip) <= last:
            return True
        if (
            not reverse
            and conflict.kind == ConflictKind.SOURCE_OVERLAP
            and first <= int(ip) <= last
        ):
            return True
    return False


class MigrationPlanner(object):
    """
    Build executable range migrations and report conflicts.

    All checks are integer interval operations; address ranges are never
    expanded.

    :param occupied: iterable of ranges already in use on the target side.
    :param forbidden: iterable of target ranges that must never be used.
    :param allow_cross_family: set ``True`` to explicitly permit IPv4 <->
        IPv6 migration. Offsets are preserved in both directions.
    """

    def __init__(self, occupied=(), forbidden=(), allow_cross_family=False):
        self.occupied = tuple(coerce_range(item) for item in occupied)
        self.forbidden = tuple(coerce_range(item) for item in forbidden)
        self.allow_cross_family = allow_cross_family

    def plan(self, pairs):
        """
        :param pairs: iterable of :class:`MigrationPair` objects.
        :return: a :class:`MigrationReport` holding executable mappings and a
            conflict report. Pairs failing any check are excluded from the
            executable plans.
        """
        plans = []
        conflicts = []

        source_blocked = {}

        #   Source ranges must not ambiguously overlap (identical networks
        #   count as overlap). Both sides of every overlap are blocked.
        ordered = list(pairs)
        for index, pair in enumerate(ordered):
            for other in ordered[:index]:
                overlap = intersect_ranges(pair.source, other.source)
                if overlap is not None:
                    conflict = Conflict(
                        ConflictKind.SOURCE_OVERLAP,
                        (MigrationPlan(pair, None), MigrationPlan(other, None)),
                        overlap,
                        'source ranges overlap: %s' % overlap,
                    )
                    conflicts.append(conflict)
                    source_blocked[id(pair)] = conflict
                    source_blocked[id(other)] = conflict

        candidates = []
        for pair in ordered:
            if id(pair) in source_blocked:
                continue

            if pair.source.version != pair.target.version and not self.allow_cross_family:
                conflicts.append(
                    Conflict(
                        ConflictKind.ADDRESS_FAMILY_MISMATCH,
                        (MigrationPlan(pair, None),),
                        None,
                        'source is IPv%d but target is IPv%d; cross-family migration '
                        'must be explicitly enabled'
                        % (pair.source.version, pair.target.version),
                    )
                )
                continue

            source_size = pair.source.last - pair.source.first + 1
            target_size = pair.target.last - pair.target.first + 1
            if source_size > target_size:
                conflicts.append(
                    Conflict(
                        ConflictKind.INSUFFICIENT_TARGET_CAPACITY,
                        (MigrationPlan(pair, None),),
                        None,
                        'source holds %d addresses but target holds only %d'
                        % (source_size, target_size),
                    )
                )
                continue

            used = IPRange(
                IPAddress(pair.target.first, pair.target.version),
                IPAddress(pair.target.first + source_size - 1, pair.target.version),
            )
            candidates.append(MigrationPlan(pair, used))

        #   Existing target-side occupancy.
        for plan in list(candidates):
            for range_ in self.occupied:
                overlap = intersect_ranges(plan.used, range_)
                if overlap is not None:
                    conflicts.append(
                        Conflict(
                            ConflictKind.TARGET_OCCUPIED,
                            (plan,),
                            overlap,
                            'needed target portion %s overlaps existing usage %s'
                            % (plan.used, overlap),
                        )
                    )
                    candidates.remove(plan)
                    break

        #   Forbidden target ranges.
        for plan in list(candidates):
            for range_ in self.forbidden:
                overlap = intersect_ranges(plan.used, range_)
                if overlap is not None:
                    conflicts.append(
                        Conflict(
                            ConflictKind.TARGET_FORBIDDEN,
                            (plan,),
                            overlap,
                            'needed target portion %s overlaps forbidden range %s'
                            % (plan.used, overlap),
                        )
                    )
                    candidates.remove(plan)
                    break

        #   Two plans landing on the same target fragment. Every pairwise
        #   collision is reported once, naming both sources and the true
        #   overlapping interval.
        for index, plan in enumerate(candidates):
            for other in candidates[:index]:
                overlap = intersect_ranges(plan.used, other.used)
                if overlap is not None:
                    conflicts.append(
                        Conflict(
                            ConflictKind.TARGET_COLLISION,
                            (plan, other),
                            overlap,
                            'plans %r and %r both need %s'
                            % (
                                plan.pair.name or plan.pair.source,
                                other.pair.name or other.pair.source,
                                overlap,
                            ),
                        )
                    )

        #   Plans participating in a target collision are not executable.
        #   Identity comparison is used: distinct plans may legitimately
        #   carry identical interval values.
        colliding = set()
        for conflict in conflicts:
            if conflict.kind == ConflictKind.TARGET_COLLISION:
                for plan in conflict.plans:
                    colliding.add(id(plan))
        plans = [plan for plan in candidates if id(plan) not in colliding]

        return MigrationReport(plans, conflicts)


def plan_migrations(pairs, occupied=(), forbidden=(), allow_cross_family=False):
    """
    Convenience wrapper around :class:`MigrationPlanner`.

    :return: a :class:`MigrationReport`.
    """
    return MigrationPlanner(
        occupied=occupied,
        forbidden=forbidden,
        allow_cross_family=allow_cross_family,
    ).plan(pairs)

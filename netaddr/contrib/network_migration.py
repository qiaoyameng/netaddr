from dataclasses import dataclass

from netaddr.ip import IPAddress, IPNetwork, IPRange


NOT_IN_MIGRATION = 'not_in_migration'
UNUSED_TARGET = 'unused_target'
CONFLICT = 'conflict'
MAPPED = 'mapped'

PLAN_CONFLICT = 'plan_conflict'
OCCUPIED_TARGET = 'occupied_target'
FORBIDDEN_TARGET = 'forbidden_target'


@dataclass(frozen=True)
class MigrationMapping:
    plan_id: object
    source: IPNetwork
    target: IPNetwork
    requested_target: IPNetwork


@dataclass(frozen=True)
class MigrationConflict:
    kind: str
    overlap: IPRange
    plan_id: object = None
    source: IPNetwork = None
    target: IPNetwork = None
    other_plan_id: object = None
    other_source: IPNetwork = None
    other_target: IPNetwork = None
    occupied_range: IPRange = None
    forbidden_range: IPRange = None


@dataclass(frozen=True)
class MigrationPlan:
    mappings: tuple
    conflicts: tuple
    requested_targets: tuple

    @property
    def executable(self):
        return not self.conflicts


@dataclass(frozen=True)
class AddressLocation:
    status: str
    address: IPAddress
    source: IPAddress = None
    target: IPAddress = None
    source_network: IPNetwork = None
    target_network: IPNetwork = None
    plan_id: object = None
    conflicts: tuple = ()


def _as_range(value):
    if isinstance(value, IPRange):
        return IPRange(
            IPAddress(value.first, value.version), IPAddress(value.last, value.version)
        )
    if isinstance(value, IPNetwork):
        return IPRange(
            IPAddress(value.first, value.version), IPAddress(value.last, value.version)
        )
    network = IPNetwork(value)
    return IPRange(
        IPAddress(network.first, network.version),
        IPAddress(network.last, network.version),
    )


def _intersection(left, right):
    if left.version != right.version:
        return None
    first = max(left.first, right.first)
    last = min(left.last, right.last)
    if first > last:
        return None
    return IPRange(IPAddress(first, left.version), IPAddress(last, left.version))


def _used_prefix_length(source, target, allow_ipv4_to_ipv6=False, allow_ipv6_to_ipv4=False):
    source_host_bits = source._module.width - source.prefixlen

    if source.version != target.version:
        if source.version == 4 and target.version == 6 and not allow_ipv4_to_ipv6:
            raise ValueError(
                'IPv4 to IPv6 migration requires allow_ipv4_to_ipv6=True: %r -> %r'
                % (source, target)
            )
        if source.version == 6 and target.version == 4 and not allow_ipv6_to_ipv4:
            raise ValueError(
                'IPv6 to IPv4 migration requires allow_ipv6_to_ipv4=True: %r -> %r'
                % (source, target)
            )

    if target.size < source.size:
        raise ValueError(
            'target network %r is too small for source network %r' % (target, source)
        )

    return target._module.width - source_host_bits


class NetworkMigrationPlanner:
    """
    Plan relocation of source IP networks while preserving each host offset.

    Target networks may be larger than the source networks. In that case only
    the prefix-sized initial portion required for the source is used, leaving
    the remainder outside the migration.
    """

    def __init__(
        self,
        pairs,
        occupied=(),
        forbidden=(),
        *,
        allow_ipv4_to_ipv6=False,
        allow_ipv6_to_ipv4=False,
    ):
        self._entries = []
        seen_sources = []

        for index, pair in enumerate(pairs):
            if len(pair) < 2 or len(pair) > 3:
                raise ValueError('each pair must contain source, target and an optional id')

            source = IPNetwork(pair[0])
            requested_target = IPNetwork(pair[1])
            plan_id = pair[2] if len(pair) == 3 else index

            for other_id, other_source in seen_sources:
                source_range = _as_range(source)
                other_range = _as_range(other_source)
                overlap = _intersection(source_range, other_range)
                if overlap is not None:
                    raise ValueError(
                        'source networks %r (id=%r) and %r (id=%r) overlap at %s'
                        % (source, plan_id, other_source, other_id, overlap)
                    )
            seen_sources.append((plan_id, source))

            used_prefixlen = _used_prefix_length(
                source,
                requested_target,
                allow_ipv4_to_ipv6,
                allow_ipv6_to_ipv4,
            )
            target = IPNetwork(
                (requested_target.network._value, used_prefixlen),
                version=requested_target.version,
            )
            self._entries.append(
                {
                    'id': plan_id,
                    'source': source,
                    'requested_target': requested_target,
                    'target': target,
                }
            )

        self._occupied = tuple(_as_range(value) for value in occupied)
        self._forbidden = tuple(_as_range(value) for value in forbidden)

    def plan(self):
        conflicts = []
        conflicting_ids = set()

        def add_conflict(conflict):
            conflicts.append(conflict)
            conflicting_ids.add(conflict.plan_id)
            if conflict.other_plan_id is not None:
                conflicting_ids.add(conflict.other_plan_id)

        for position, entry in enumerate(self._entries):
            target_range = _as_range(entry['target'])

            for occupied_range in self._occupied:
                overlap = _intersection(target_range, occupied_range)
                if overlap is not None:
                    add_conflict(
                        MigrationConflict(
                            kind=OCCUPIED_TARGET,
                            plan_id=entry['id'],
                            source=entry['source'],
                            target=entry['target'],
                            occupied_range=occupied_range,
                            overlap=overlap,
                        )
                    )

            for forbidden_range in self._forbidden:
                overlap = _intersection(target_range, forbidden_range)
                if overlap is not None:
                    add_conflict(
                        MigrationConflict(
                            kind=FORBIDDEN_TARGET,
                            plan_id=entry['id'],
                            source=entry['source'],
                            target=entry['target'],
                            forbidden_range=forbidden_range,
                            overlap=overlap,
                        )
                    )

            for other in self._entries[position + 1 :]:
                overlap = _intersection(target_range, _as_range(other['target']))
                if overlap is not None:
                    add_conflict(
                        MigrationConflict(
                            kind=PLAN_CONFLICT,
                            plan_id=entry['id'],
                            source=entry['source'],
                            target=entry['target'],
                            other_plan_id=other['id'],
                            other_source=other['source'],
                            other_target=other['target'],
                            overlap=overlap,
                        )
                    )

        mappings = tuple(
            MigrationMapping(
                plan_id=entry['id'],
                source=entry['source'],
                target=entry['target'],
                requested_target=entry['requested_target'],
            )
            for entry in self._entries
            if entry['id'] not in conflicting_ids
        )
        requested_targets = tuple(
            (entry['id'], entry['requested_target']) for entry in self._entries
        )

        return MigrationPlan(
            mappings=mappings,
            conflicts=tuple(conflicts),
            requested_targets=requested_targets,
        )

    def lookup(self, address):
        address = IPAddress(address)
        address_range = IPRange(address, address)

        for entry in self._entries:
            overlap = _intersection(address_range, _as_range(entry['source']))
            if overlap is None:
                continue

            plan = self.plan()
            conflicts = tuple(
                conflict
                for conflict in plan.conflicts
                if conflict.plan_id == entry['id']
                or conflict.other_plan_id == entry['id']
            )
            if conflicts:
                return AddressLocation(
                    status=CONFLICT,
                    address=address,
                    source=address,
                    source_network=entry['source'],
                    target_network=entry['target'],
                    plan_id=entry['id'],
                    conflicts=conflicts,
                )

            offset = address._value - entry['source'].first
            return AddressLocation(
                status=MAPPED,
                address=address,
                source=address,
                target=IPAddress(entry['target'].first + offset, entry['target'].version),
                source_network=entry['source'],
                target_network=entry['target'],
                plan_id=entry['id'],
            )

        return AddressLocation(status=NOT_IN_MIGRATION, address=address)

    def reverse_lookup(self, address):
        address = IPAddress(address)
        address_range = IPRange(address, address)
        plan = self.plan()

        for entry in self._entries:
            if _intersection(address_range, _as_range(entry['target'])) is None:
                continue
            conflicts = tuple(
                conflict
                for conflict in plan.conflicts
                if conflict.plan_id == entry['id'] or conflict.other_plan_id == entry['id']
            )
            if not conflicts:
                continue
            offset = address._value - entry['target'].first
            return AddressLocation(
                status=CONFLICT,
                address=address,
                target=address,
                source=IPAddress(entry['source'].first + offset, entry['source'].version),
                source_network=entry['source'],
                target_network=entry['target'],
                plan_id=entry['id'],
                conflicts=conflicts,
            )

        for mapping in plan.mappings:
            target_range = _as_range(mapping.target)
            if _intersection(address_range, target_range) is not None:
                offset = address._value - mapping.target.first
                source = IPAddress(mapping.source.first + offset, mapping.source.version)
                return AddressLocation(
                    status=MAPPED,
                    address=address,
                    source=source,
                    target=address,
                    source_network=mapping.source,
                    target_network=mapping.target,
                    plan_id=mapping.plan_id,
                )

        for entry in self._entries:
            if _intersection(address_range, _as_range(entry['requested_target'])) is not None:
                return AddressLocation(
                    status=UNUSED_TARGET,
                    address=address,
                    plan_id=entry['id'],
                )

        return AddressLocation(status=NOT_IN_MIGRATION, address=address)


def plan_network_migration(
    pairs,
    occupied=(),
    forbidden=(),
    *,
    allow_ipv4_to_ipv6=False,
    allow_ipv6_to_ipv4=False,
):
    """Build a :class:`MigrationPlan` from source/target network pairs."""
    return NetworkMigrationPlanner(
        pairs,
        occupied,
        forbidden,
        allow_ipv4_to_ipv6=allow_ipv4_to_ipv6,
        allow_ipv6_to_ipv4=allow_ipv6_to_ipv4,
    ).plan()

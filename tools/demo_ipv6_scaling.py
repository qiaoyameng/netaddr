"""IPv6 large-range demonstration.

Two experiments show that solve time depends on prefix structure (number of
prefix boundaries and trie depth), never on the number of addresses.

1. Shape stability: identical trie shape with blocks shifted to different
   prefix widths -- the address cardinality grows 2**56x while node count
   and solve time stay flat.

2. Exact big-integer: one rule covering two distant singletons reports an
   extra count of ~2**80 addresses without enumerating a single one.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netaddr import IPSet
from netaddr.ip.summarization import summarize_ipset, summarize_ipsets


def count_nodes(root):
    stack = [root]
    total = 0
    while stack:
        node = stack.pop()
        total += 1
        if node.children is not None:
            stack.extend(c for c in node.children if c is not None)
    return total


def timed(targets, forbidden, max_rules, repeat=200):
    warm = summarize_ipset(targets, forbidden, max_rules)
    t0 = time.perf_counter()
    result = None
    for _ in range(repeat):
        result = summarize_ipset(targets, forbidden, max_rules)
    elapsed = (time.perf_counter() - t0) / repeat
    return result, elapsed


from netaddr import IPNetwork
from netaddr.ip.summarization import (
    _as_intervals,
    _build_trie,
    _intervals_to_cidrs,
)


def make_shape(width):
    '''Two aligned /width blocks separated by one aligned /width gap.'''
    block = 1 << (128 - width)
    base = 0x20010DB8000000000000000000000000
    t1 = IPNetwork((base, width), version=6)
    t2 = IPNetwork((base + 2 * block, width), version=6)
    forbidden = IPNetwork((base + block, width), version=6)
    return IPSet([t1, t2]), IPSet([forbidden])


def trie_of(targets, forbidden):
    ti = _as_intervals(targets, 6)
    fi = _as_intervals(forbidden, 6)
    return _build_trie(
        _intervals_to_cidrs(ti, 128), _intervals_to_cidrs(fi, 128), 128
    )


def main():
    print('== Shape stability: same trie shape, address count grows ==')
    print('width      block_addresses     rules  nodes  time/solve')
    rows = []
    for width in (120, 96, 64):
        targets, forbidden = make_shape(width)
        nodes = count_nodes(trie_of(targets, forbidden))
        result, elapsed = timed(targets, forbidden, 2)
        rows.append((width, 2 ** (128 - width), nodes, elapsed, result))
        print(
            '/%-5d %22d  %5d  %5d  %.6f'
            % (width, 2 ** (128 - width), len(result.rules), nodes, elapsed)
        )

    block_sizes = [r[1] for r in rows]
    growth = block_sizes[-1] // block_sizes[0]
    times = [r[3] for r in rows]
    print(
        'address cardinality grew 2**%d x; times stayed in %.6f..%.6f s'
        % (growth.bit_length() - 1, min(times), max(times))
    )
    print('node counts:', [r[2] for r in rows])

    print()
    print('== Same shape infeasible at K=1, exact at K=2 ==')
    for width in (120, 64):
        targets, forbidden = make_shape(width)
        tight = summarize_ipset(targets, forbidden, 1)
        exact = summarize_ipset(targets, forbidden, 2)
        print(
            '/%-3d K=1 feasible=%-5s minimum_rules=%d | K=2 extra=%d rules=%s'
            % (
                width,
                tight.feasible,
                tight.minimum_rules,
                exact.extra_addresses,
                [str(c) for c in exact.rules],
            )
        )

    print()
    print('== Exact big integer: one /48 over two distant singletons ==')
    far = IPSet(['2001:db8::1', '2001:db8:0:ffff::1'])
    big = summarize_ipset(far, max_rules=1)
    print('rules  :', [str(c) for c in big.rules])
    print('extra  :', big.extra_addresses)
    print('2**80-2 =', 2 ** 80 - 2)
    print('match  :', big.extra_addresses == 2 ** 80 - 2)
    print('extra range count:', len(big.extra_ranges))
    print(
        'sum of range sizes:',
        sum(x.size for x in big.extra_ranges),
    )
    print(
        'first 3 extra ranges:',
        [(str(x.cidr), x.size) for x in big.extra_ranges[:3]],
    )

    print()
    print('== IPv4 + IPv6 computed independently ==')
    both = summarize_ipsets(
        IPSet(['192.0.2.0/31', '2001:db8::1', '2001:db8::2']),
        IPSet(['2001:db8::3']),
        max_rules=2,
    )
    for version, res in sorted(both.items()):
        print(
            'v%d feasible=%s rules=%s extra=%d minimum_rules=%d'
            % (
                version,
                res.feasible,
                [str(c) for c in res.rules],
                res.extra_addresses,
                res.minimum_rules,
            )
        )


if __name__ == '__main__':
    main()

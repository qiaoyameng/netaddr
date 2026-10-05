import sys

import pytest

from netaddr import IPAddress, IPSet
from netaddr.ip.sets import IPSetOrdinalView, _OrdinalSlice


def sample_set():
    return IPSet(
        [
            '10.0.0.0/30',
            '10.0.0.8/29',
            '192.168.0.0/31',
            '2001:db8::/126',
            '2001:db8::8/125',
        ]
    )


def sample_addresses():
    return [
        IPAddress('10.0.0.0'),
        IPAddress('10.0.0.1'),
        IPAddress('10.0.0.2'),
        IPAddress('10.0.0.3'),
        IPAddress('10.0.0.8'),
        IPAddress('10.0.0.9'),
        IPAddress('10.0.0.10'),
        IPAddress('10.0.0.11'),
        IPAddress('10.0.0.12'),
        IPAddress('10.0.0.13'),
        IPAddress('10.0.0.14'),
        IPAddress('10.0.0.15'),
        IPAddress('192.168.0.0'),
        IPAddress('192.168.0.1'),
        IPAddress('2001:db8::'),
        IPAddress('2001:db8::1'),
        IPAddress('2001:db8::2'),
        IPAddress('2001:db8::3'),
        IPAddress('2001:db8::8'),
        IPAddress('2001:db8::9'),
        IPAddress('2001:db8::a'),
        IPAddress('2001:db8::b'),
        IPAddress('2001:db8::c'),
        IPAddress('2001:db8::d'),
        IPAddress('2001:db8::e'),
        IPAddress('2001:db8::f'),
    ]


def test_empty_view():
    view = IPSet([]).ordinal_view()
    assert view.size == 0
    assert len(view) == 0
    assert list(view) == []
    assert list(view[:]) == []
    assert list(view[::-1]) == []
    with pytest.raises(IndexError):
        view[0]
    with pytest.raises(IndexError):
        view[-1]
    with pytest.raises(ValueError):
        view.rank('10.0.0.1')
    assert view.insertion_index('10.0.0.1') == 0
    assert view.insertion_index('::1') == 0
    assert '10.0.0.1' not in view


def test_ipv4_before_ipv6_numeric_order():
    view = sample_set().ordinal_view()
    expected = sample_addresses()
    assert view.size == len(expected)
    assert list(view) == expected
    for i, addr in enumerate(expected):
        assert view[i] == addr


def test_negative_indexing():
    view = sample_set().ordinal_view()
    expected = sample_addresses()
    for i in range(1, len(expected) + 1):
        assert view[-i] == expected[-i]
    with pytest.raises(IndexError):
        view[len(expected)]
    with pytest.raises(IndexError):
        view[-len(expected) - 1]


def test_member_rank():
    view = sample_set().ordinal_view()
    expected = sample_addresses()
    for i, addr in enumerate(expected):
        assert view.rank(addr) == i
        assert view.rank(str(addr)) == i
        assert view.insertion_index(addr) == i
        assert addr in view


def test_non_member_insertion_index():
    view = sample_set().ordinal_view()
    # Before the first member.
    assert view.insertion_index('9.255.255.255') == 0
    assert view.insertion_index('0.0.0.0') == 0
    # Inside gaps between CIDR blocks.
    assert view.insertion_index('10.0.0.4') == 4
    assert view.insertion_index('10.0.0.7') == 4
    assert view.insertion_index('10.0.0.16') == 12
    assert view.insertion_index('11.0.0.1') == 12
    # Just past the last IPv4 member, still IPv4.
    assert view.insertion_index('192.168.0.2') == 14
    assert view.insertion_index('255.255.255.255') == 14
    # IPv6 non-members sort after every IPv4 member.
    assert view.insertion_index('::') == 14
    assert view.insertion_index('2001:db8::4') == 18
    assert view.insertion_index('2001:db8::7') == 18
    assert view.insertion_index('ffff::1') == 26
    # Non-members are rejected by rank().
    for addr in ('10.0.0.4', '192.168.0.2', '2001:db8::4', 'ffff::1'):
        with pytest.raises(ValueError):
            view.rank(addr)
        assert addr not in view


def test_version_boundary():
    view = sample_set().ordinal_view()
    v4_count = 14
    assert view[v4_count - 1] == IPAddress('192.168.0.1')
    assert view[v4_count] == IPAddress('2001:db8::')
    assert view[v4_count - 1].version == 4
    assert view[v4_count].version == 6
    # The last IPv4 address in the space still sorts before the first IPv6
    # member.
    assert view.insertion_index('255.255.255.255') == v4_count
    assert view.insertion_index('::') == v4_count


def test_duplicate_and_overlapping_cidrs_merged():
    ipset = IPSet()
    ipset.add('10.0.0.0/24')
    ipset.add('10.0.0.0/24')  # exact duplicate
    ipset.add('10.0.0.128/25')  # fully contained
    ipset.add('10.0.1.0/24')  # adjacent, merges into /23
    ipset.add('10.0.0.5')  # single address already covered
    view = ipset.ordinal_view()
    assert view.size == 512
    expected = [IPAddress(0x0A000000 + i) for i in range(512)]
    assert list(view) == expected
    assert view[0] == IPAddress('10.0.0.0')
    assert view[255] == IPAddress('10.0.0.255')
    assert view[256] == IPAddress('10.0.1.0')
    assert view[-1] == IPAddress('10.0.1.255')
    assert view.rank('10.0.1.100') == 356


def test_stepped_slices_match_list_slicing():
    view = sample_set().ordinal_view()
    expected = sample_addresses()
    slices = [
        slice(None, None, None),
        slice(2, 10, None),
        slice(None, None, 2),
        slice(1, 20, 3),
        slice(None, None, -1),
        slice(20, 2, -3),
        slice(-5, None, None),
        slice(None, -20, -2),
        slice(-1, -8, -2),
        slice(7, 7, 1),
        slice(100, 200, 1),
        slice(-100, 3, 1),
    ]
    for s in slices:
        sliced = view[s]
        assert isinstance(sliced, _OrdinalSlice)
        assert sliced.size == len(expected[s])
        assert list(sliced) == expected[s]
        for i, addr in enumerate(expected[s]):
            assert sliced[i] == addr
            assert sliced[i - len(expected[s])] == addr


def test_slice_of_slice_composes_lazily():
    view = sample_set().ordinal_view()
    expected = sample_addresses()
    sub = view[1:-1:2][::2]
    assert isinstance(sub, _OrdinalSlice)
    assert list(sub) == expected[1:-1:2][::2]
    sub2 = view[::-2][1:6][::-1]
    assert list(sub2) == expected[::-2][1:6][::-1]


def test_slice_is_lazy():
    view = IPSet(['2001:db8::/64']).ordinal_view()
    sliced = view[:: 2 ** 60]
    # Creating and sizing the slice must not enumerate addresses.
    assert sliced.size == 16
    assert sliced[0] == IPAddress('2001:db8::')
    assert sliced[-1] == IPAddress('2001:db8::f000:0000:0000:0000')
    assert len(list(sliced)) == 16


def test_view_is_immutable_snapshot():
    ipset = sample_set()
    view = ipset.ordinal_view()
    before = list(view)
    ipset.add('10.0.0.4')
    ipset.add('172.16.0.0/24')
    ipset.remove('192.168.0.0/31')
    ipset.remove('2001:db8::/126')
    assert list(view) == before
    assert view.size == len(before)
    with pytest.raises(ValueError):
        view.rank('10.0.0.4')
    assert '192.168.0.0' in view


def test_huge_set_beyond_sys_maxsize():
    ipset = IPSet(['10.0.0.0/8', '2001:db8::/64'])
    view = ipset.ordinal_view()
    v4_count = 2 ** 24
    v6_count = 2 ** 64
    assert view.size == v4_count + v6_count
    assert view.size > sys.maxsize
    # len() must not be relied upon for sets this large.
    with pytest.raises(IndexError):
        len(view)
    # Indexing is arithmetic, not iteration: the last members of a /64 are
    # reachable directly.
    assert view[0] == IPAddress('10.0.0.0')
    assert view[v4_count - 1] == IPAddress('10.255.255.255')
    assert view[v4_count] == IPAddress('2001:db8::')
    assert view[-1] == IPAddress('2001:db8::ffff:ffff:ffff:ffff')
    assert view[-2] == IPAddress('2001:db8::ffff:ffff:ffff:fffe')
    # Slicing off the tail is lazy and does not walk the set.
    tail = view[-3:]
    assert tail.size == 3
    assert list(tail) == [
        IPAddress('2001:db8::ffff:ffff:ffff:fffd'),
        IPAddress('2001:db8::ffff:ffff:ffff:fffe'),
        IPAddress('2001:db8::ffff:ffff:ffff:ffff'),
    ]
    # Rank and insertion position work at the far end too.
    assert view.rank('2001:db8::ffff:ffff:ffff:ffff') == view.size - 1
    assert view.insertion_index('2001:db8::ffff:ffff:ffff:ffff') == view.size - 1
    assert view.insertion_index('ffff::') == view.size
    assert view.rank('10.255.255.255') == v4_count - 1


def test_huge_slice_len_guard():
    view = IPSet(['2001:db8::/64']).ordinal_view()
    sliced = view[:]
    assert sliced.size == 2 ** 64
    with pytest.raises(IndexError):
        len(sliced)


def test_view_constructor_and_export():
    ipset = sample_set()
    view = IPSetOrdinalView(ipset)
    assert view.size == ipset.size
    assert list(view) == list(ipset.ordinal_view())
    from netaddr import IPSetOrdinalView as exported

    assert exported is IPSetOrdinalView

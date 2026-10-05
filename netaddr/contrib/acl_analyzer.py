# -----------------------------------------------------------------------------
#   Copyright (c) 2008 by David P. D. Moss. All rights reserved.
#
#   Released under the BSD license. See the LICENSE file for details.
# -----------------------------------------------------------------------------
"""
An analyzer for ordered IP allow/deny rule lists (ACLs).

Rules are evaluated top-down; the first rule whose address set matches an
address decides its fate.  Addresses matched by no rule fall through to a
default action.

Each rule may contain multiple CIDR blocks plus per-rule exclusions
(``cidrs`` minus ``excludes``).  Because earlier rules win, a later rule can
be *shadowed* by the union of any number of preceding rules -- looking at
adjacent pairs of rules is not enough.

For every rule this analyzer reports, using merged CIDR blocks (addresses
are never enumerated, so IPv6 space is handled safely):

- ``match``     -- the full address region the rule itself selects.
- ``effective`` -- the region where this rule is actually the first match.
- ``redundant`` -- the region already decided, with the *same* action, by
                   earlier rules (harmless duplication).
- ``truncated`` -- the region already decided, with the *opposite* action,
                   by earlier rules (the rule is cut off / possibly
                   misconfigured).
- ``shadowers`` -- every preceding rule overlapping ``match``, with the
                   overlapping region.

A rule whose entire match region is covered by earlier same-action rules is
``safe_to_remove``: deleting it cannot change any decision.  A rule fully
covered but involving an opposite action is dead too, yet flagged
``overridden`` instead of redundant, because its presence usually signals a
configuration mistake and it is excluded from the safe-removal set.

``verify_removals`` proves that removing a set of rules leaves the decision
identical on *every* partition of the address space, by comparing the
per-action decision regions (as IPSets) before and after removal.
"""

from netaddr import IPSet


class Rule(object):
    """
    A single ordered allow/deny rule.

    :param name: human readable identifier used in reports.
    :param action: decision taken on a match, e.g. ``'allow'`` / ``'deny'``.
        Any hashable label works; two actions are "opposite" when they
        differ.
    :param cidrs: iterable of CIDR strings the rule matches.
    :param excludes: iterable of CIDR strings carved out of ``cidrs``.
    """

    def __init__(self, name, action, cidrs, excludes=()):
        self.name = name
        self.action = action
        self.cidrs = list(cidrs)
        self.excludes = list(excludes)

    def match_set(self):
        """The rule's address region as an IPSet (cidrs minus excludes)."""
        result = IPSet(self.cidrs)
        for excluded in self.excludes:
            result = result - IPSet([excluded])
        return result

    def __repr__(self):
        return 'Rule(%r, %r)' % (self.name, self.action)


class Shadower(object):
    """A preceding rule overlapping the analysed rule's match region."""

    def __init__(self, index, rule, overlap, same_action):
        self.index = index
        self.rule = rule
        self.overlap = overlap
        self.same_action = same_action

    @property
    def relation(self):
        return 'same-action' if self.same_action else 'opposite-action'


class RuleAnalysis(object):
    """Shadowing analysis for a single rule."""

    def __init__(self, index, rule, match, redundant, truncated, effective,
                 shadowers):
        self.index = index
        self.rule = rule
        self.match = match
        self.redundant = redundant
        self.truncated = truncated
        self.effective = effective
        self.shadowers = shadowers

    @property
    def fully_shadowed(self):
        """True when no address is left for this rule to decide."""
        return not self.effective

    @property
    def safe_to_remove(self):
        """
        True when the rule never fires and everything it would have matched
        is already decided with the same action by earlier rules.
        """
        return self.fully_shadowed and not self.truncated

    @property
    def status(self):
        if not self.match:
            return 'empty'
        if not self.effective:
            return 'redundant' if self.safe_to_remove else 'overridden'
        if self.redundant or self.truncated:
            return 'partially-shadowed'
        return 'effective'


def _universe():
    return IPSet(['0.0.0.0/0', '::/0'])


def analyze_rules(rules, default_action):
    """
    Analyse an ordered rule list.

    :param rules: sequence of :class:`Rule` in evaluation order.
    :param default_action: action applied to addresses no rule matches.
    :return: list of :class:`RuleAnalysis`, one per rule.
    """
    analyses = []
    unions = {}               # action -> union of earlier match sets
    prior_rules = []          # (index, rule, match_set)

    for index, rule in enumerate(rules):
        match = rule.match_set()
        shadowers = []
        for prev_index, prev_rule, prev_match in prior_rules:
            overlap = match & prev_match
            if overlap:
                shadowers.append(Shadower(
                    prev_index, prev_rule, overlap,
                    prev_rule.action == rule.action))

        prior_same = unions.get(rule.action, IPSet())
        prior_opposite = IPSet()
        for action, union in unions.items():
            if action != rule.action:
                prior_opposite = prior_opposite | union

        redundant = match & prior_same
        truncated = match & prior_opposite
        effective = match - (prior_same | prior_opposite)

        analyses.append(RuleAnalysis(
            index, rule, match, redundant, truncated, effective, shadowers))

        prior_rules.append((index, rule, match))
        unions.setdefault(rule.action, IPSet())
        unions[rule.action] = unions[rule.action] | match

    return analyses


def decision_regions(rules, default_action):
    """
    Partition the whole address space by decision.

    :return: dict mapping each action (including the default) to the IPSet
        of addresses for which the ruleset produces that action.
    """
    regions = {}
    covered = IPSet()
    for rule in rules:
        effective = rule.match_set() - covered
        regions.setdefault(rule.action, IPSet())
        regions[rule.action] = regions[rule.action] | effective
        covered = covered | rule.match_set()
    regions.setdefault(default_action, IPSet())
    regions[default_action] = regions[default_action] | (_universe() - covered)
    return regions


def verify_removals(rules, default_action, remove_indexes):
    """
    Check that deleting the given rules changes no decision anywhere.

    Compares the per-action decision regions (merged IPSets, never
    enumerated addresses) of the original and the reduced ruleset.

    :return: ``(equivalent, before, after)`` where *before* and *after* are
        the decision-region maps; ``equivalent`` is True iff every address
        partition keeps its decision.
    """
    remove_indexes = set(remove_indexes)
    before = decision_regions(rules, default_action)
    remaining = [r for i, r in enumerate(rules) if i not in remove_indexes]
    after = decision_regions(remaining, default_action)
    actions = set(before) | set(after)
    equivalent = all(
        before.get(a, IPSet()) == after.get(a, IPSet()) for a in actions)
    return equivalent, before, after


def _fmt(ipset):
    if not ipset:
        return '(none)'
    return ', '.join(str(cidr) for cidr in ipset.iter_cidrs())


def format_report(rules, default_action, analyses=None):
    """Render a human readable shadowing report using merged CIDRs."""
    if analyses is None:
        analyses = analyze_rules(rules, default_action)
    lines = []
    lines.append('ACL shadowing analysis: %d rules, default action: %s'
                 % (len(rules), default_action))
    for a in analyses:
        lines.append('')
        lines.append('rule %d "%s" [%s] -> %s'
                     % (a.index, a.rule.name, a.rule.action, a.status))
        lines.append('  match     : %s' % _fmt(a.match))
        lines.append('  effective : %s' % _fmt(a.effective))
        if a.redundant:
            lines.append('  redundant (same-action, earlier): %s'
                         % _fmt(a.redundant))
        if a.truncated:
            lines.append('  truncated (opposite-action, earlier): %s'
                         % _fmt(a.truncated))
        for s in a.shadowers:
            lines.append('  shadowed by rule %d "%s" [%s, %s]: %s'
                         % (s.index, s.rule.name, s.rule.action,
                            s.relation, _fmt(s.overlap)))
        if a.fully_shadowed:
            if a.safe_to_remove:
                lines.append('  => SAFE TO REMOVE (fully redundant)')
            else:
                lines.append('  => DEAD but OVERRIDDEN by opposite action;'
                             ' review before removing')
    safe = [a.index for a in analyses if a.safe_to_remove]
    lines.append('')
    lines.append('safe-to-remove rules: %s'
                 % (', '.join('#%d %s' % (i, rules[i].name) for i in safe)
                    or '(none)'))
    return '\n'.join(lines)


def joint_shadow_example():
    """
    Example ruleset where three rules jointly shadow a fourth.

    Rules 0-2 each cover only a slice of 10.0.0.0/8, so no single one of
    them (and no adjacent pair) covers rule 3 -- only their union does.
    Rule 5 shows the opposite-action case: an earlier allow truncates a
    later deny.  Rule 6 exercises exclusions and IPv6.

    :return: ``(rules, default_action)``
    """
    rules = [
        Rule('edge-a', 'allow', ['10.0.0.0/9']),
        Rule('edge-b', 'allow', ['10.128.0.0/10']),
        Rule('edge-c', 'allow', ['10.192.0.0/10']),
        Rule('legacy-catchall', 'allow', ['10.0.0.0/8']),
        Rule('dmz', 'allow', ['192.168.0.0/24'],
             excludes=['192.168.0.128/25']),
        Rule('dmz-lockdown', 'deny', ['192.168.0.0/25']),
        Rule('v6-uplink', 'allow', ['2001:db8::/32'],
             excludes=['2001:db8:bad::/48']),
    ]
    return rules, 'deny'


def main():
    rules, default_action = joint_shadow_example()
    analyses = analyze_rules(rules, default_action)
    print(format_report(rules, default_action, analyses))

    safe = [a.index for a in analyses if a.safe_to_remove]
    equivalent, before, after = verify_removals(rules, default_action, safe)
    print('')
    print('removing safe rules %s keeps all decisions identical: %s'
          % (safe, equivalent))
    for action in sorted(before):
        print('  %-6s before: %-40s after: %s'
              % (action, _fmt(before[action]), _fmt(after[action])))


if __name__ == '__main__':
    main()

"""Sequential IP allow/deny rule shadow analysis."""

import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence

from netaddr.ip import IPAddress, IPNetwork, IPRange
from netaddr.ip.sets import IPSet


ALLOW = 'allow'
DENY = 'deny'
ACTIONS = (ALLOW, DENY)


def _normalize_action(action: str) -> str:
    normalized = str(action).strip().lower()
    if normalized not in ACTIONS:
        raise ValueError('action must be %r or %r' % (ALLOW, DENY))
    return normalized


def _as_ip_set(values: Optional[Iterable[object]] = None) -> IPSet:
    ip_set = IPSet()
    for value in values or []:
        if isinstance(value, IPSet):
            ip_set.update(value)
        elif isinstance(value, IPRange):
            ip_set.add(value)
        elif isinstance(value, IPNetwork):
            ip_set.add(value.cidr)
        elif isinstance(value, IPAddress):
            ip_set.add(IPNetwork(value).cidr)
        elif isinstance(value, str):
            ip_set.add(IPNetwork(value).cidr)
        else:
            raise TypeError('unsupported IP set value: %r' % (value,))
    return ip_set


def _cidrs(ip_set: IPSet) -> List[str]:
    return [str(cidr) for cidr in ip_set.iter_cidrs()]


def _default_universe() -> IPSet:
    return IPSet(['0.0.0.0/0', '::/0'])


@dataclass
class FirewallRule:
    """An ordered first-match firewall rule."""

    rule_id: object
    action: str
    cidrs: Iterable[object]
    excludes: Iterable[object] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        self.action = _normalize_action(self.action)
        self._included = _as_ip_set(self.cidrs)
        self._excluded = _as_ip_set(self.excludes)
        self._match_set = self._included - self._excluded

    @classmethod
    def from_mapping(cls, data: Dict[str, object], index: int = 0) -> 'FirewallRule':
        return cls(
            rule_id=data.get('id', data.get('rule_id', index + 1)),
            action=data['action'],
            cidrs=data.get('cidrs', data.get('include', ())),
            excludes=data.get('excludes', data.get('exclusions', ())),
        )

    @property
    def match_set(self) -> IPSet:
        return self._match_set.copy()


@dataclass
class RuleShadow:
    """Intersection with one preceding effective rule."""

    rule_id: object
    action: str
    relationship: str
    cidrs: List[str]
    complete: bool


@dataclass
class RuleAnalysis:
    """Coverage and effective-match report for one ordered rule."""

    index: int
    rule: FirewallRule
    declared_cidrs: List[str]
    effective_cidrs: List[str]
    redundant_cidrs: List[str]
    truncated_cidrs: List[str]
    shadowing_rules: List[RuleShadow]
    fully_shadowed_individually_by: List[object]
    partially_shadowed_by: List[object]
    jointly_fully_shadowed: bool
    status: str
    safe_to_delete: bool

    @property
    def redundant_rule_ids(self) -> List[object]:
        return [
            shadow.rule_id
            for shadow in self.shadowing_rules
            if shadow.relationship == 'redundant'
        ]

    @property
    def truncating_rule_ids(self) -> List[object]:
        return [
            shadow.rule_id
            for shadow in self.shadowing_rules
            if shadow.relationship == 'truncating'
        ]


@dataclass
class PolicyDecision:
    """Final disjoint allow and deny address partitions."""

    default_action: str
    decisions: Dict[str, IPSet]

    @property
    def partitions(self) -> Dict[str, List[str]]:
        return {action: _cidrs(ip_set) for action, ip_set in self.decisions.items()}


@dataclass
class FirewallAnalysis:
    default_action: Optional[str]
    rules: List[RuleAnalysis]
    policy: Optional[PolicyDecision] = None

    @property
    def safe_to_delete(self) -> List[object]:
        return [report.rule.rule_id for report in self.rules if report.safe_to_delete]


@dataclass
class DeletionVerification:
    removed_rule_ids: List[object]
    equivalent: bool
    before: PolicyDecision
    after: PolicyDecision
    differences: Dict[str, List[str]]


def prepare_rules(rules: Sequence[object]) -> List[FirewallRule]:
    prepared = []
    seen = set()
    for index, rule in enumerate(rules):
        if not isinstance(rule, FirewallRule):
            rule = FirewallRule.from_mapping(rule, index)
        if rule.rule_id in seen:
            raise ValueError('duplicate rule id: %r' % (rule.rule_id,))
        seen.add(rule.rule_id)
        prepared.append(rule)
    return prepared


def compile_firewall_policy(
    rules: Sequence[object],
    default_action: str,
    universe: Optional[IPSet] = None,
) -> PolicyDecision:
    """Return final decision sets under ordered first-match semantics."""

    default_action = _normalize_action(default_action)
    prepared_rules = prepare_rules(rules)
    address_universe = universe.copy() if universe is not None else _default_universe()
    decisions = {ALLOW: IPSet(), DENY: IPSet()}
    matched = IPSet()

    for rule in prepared_rules:
        effective = (rule.match_set & address_universe) - matched
        decisions[rule.action].update(effective)
        matched.update(effective)

    decisions[default_action].update(address_universe - matched)
    return PolicyDecision(default_action=default_action, decisions=decisions)


def analyze_firewall(
    rules: Sequence[object],
    default_action: Optional[str] = None,
    universe: Optional[IPSet] = None,
) -> FirewallAnalysis:
    """Analyze each rule's effective region and preceding shadow regions."""

    prepared_rules = prepare_rules(rules)
    address_universe = universe.copy() if universe is not None else _default_universe()
    reports = []
    prior_effective = []
    covered_union = IPSet()

    for index, rule in enumerate(prepared_rules):
        declared = rule.match_set & address_universe
        covered = declared & covered_union
        effective = declared - covered_union
        redundant = IPSet()
        truncating = IPSet()
        shadows = []
        complete = []
        partial = []

        for prior_rule, prior_set in prior_effective:
            intersection = declared & prior_set
            if not intersection:
                continue

            relationship = (
                'redundant' if prior_rule.action == rule.action else 'truncating'
            )
            if relationship == 'redundant':
                redundant.update(intersection)
            else:
                truncating.update(intersection)

            individually_complete = declared.issubset(prior_set)
            if individually_complete:
                complete.append(prior_rule.rule_id)
            else:
                partial.append(prior_rule.rule_id)
            shadows.append(
                RuleShadow(
                    rule_id=prior_rule.rule_id,
                    action=prior_rule.action,
                    relationship=relationship,
                    cidrs=_cidrs(intersection),
                    complete=individually_complete,
                )
            )

        if not declared:
            status = 'empty'
        elif effective:
            status = 'partially_shadowed' if covered else 'active'
        elif redundant and not truncating:
            status = 'fully_redundant'
        elif truncating and not redundant:
            status = 'fully_truncated'
        else:
            status = 'fully_shadowed_mixed'

        reports.append(
            RuleAnalysis(
                index=index,
                rule=rule,
                declared_cidrs=_cidrs(declared),
                effective_cidrs=_cidrs(effective),
                redundant_cidrs=_cidrs(redundant),
                truncated_cidrs=_cidrs(truncating),
                shadowing_rules=shadows,
                fully_shadowed_individually_by=complete,
                partially_shadowed_by=partial,
                jointly_fully_shadowed=bool(declared) and not bool(effective),
                status=status,
                safe_to_delete=not bool(effective),
            )
        )
        prior_effective.append((rule, effective))
        covered_union.update(effective)

    policy = None
    if default_action is not None:
        policy = compile_firewall_policy(
            prepared_rules, default_action=default_action, universe=universe
        )
    return FirewallAnalysis(default_action=default_action, rules=reports, policy=policy)


def verify_safe_deletions(
    rules: Sequence[object],
    default_action: str,
    rule_ids: Optional[Sequence[object]] = None,
    universe: Optional[IPSet] = None,
) -> DeletionVerification:
    """Delete rules and compare final decisions on every address partition."""

    rule_input = [
        report.rule if isinstance(report, RuleAnalysis) else report
        for report in rules
    ]
    prepared_rules = prepare_rules(rule_input)
    if rule_ids is None:
        analysis = analyze_firewall(
            prepared_rules, default_action=default_action, universe=universe
        )
        rule_ids = analysis.safe_to_delete

    removed = list(rule_ids)
    removed_set = set(removed)
    if len(removed_set) != len(removed):
        raise ValueError('duplicate rule id in deletion request')

    known_ids = {rule.rule_id for rule in prepared_rules}
    unknown = removed_set - known_ids
    if unknown:
        raise ValueError('unknown rule id: %r' % (sorted(unknown, key=str),))

    before = compile_firewall_policy(
        prepared_rules, default_action=default_action, universe=universe
    )
    pruned = [rule for rule in prepared_rules if rule.rule_id not in removed_set]
    after = compile_firewall_policy(
        pruned, default_action=default_action, universe=universe
    )

    differences = {}
    equivalent = True
    for action in ACTIONS:
        changed = before.decisions[action] ^ after.decisions[action]
        if changed:
            equivalent = False
            differences[action] = _cidrs(changed)

    return DeletionVerification(
        removed_rule_ids=removed,
        equivalent=equivalent,
        before=before,
        after=after,
        differences=differences,
    )


def format_analysis(analysis: FirewallAnalysis) -> str:
    """Render a concise human-readable report."""

    lines = []
    if analysis.default_action is not None:
        lines.append('default action: %s' % analysis.default_action)

    for report in analysis.rules:
        rule = report.rule
        lines.append(
            '%s (%s): %s' % (rule.rule_id, rule.action, report.status)
        )
        lines.append('  declared after exclusions: %s' % _format_cidrs(report.declared_cidrs))
        lines.append('  effective: %s' % _format_cidrs(report.effective_cidrs))
        lines.append('  same-decision redundancy: %s' % _format_cidrs(report.redundant_cidrs))
        lines.append('  opposite-decision truncation: %s' % _format_cidrs(report.truncated_cidrs))
        lines.append(
            '  individually complete predecessors: %s'
            % _format_ids(report.fully_shadowed_individually_by)
        )
        lines.append(
            '  partial predecessors: %s'
            % _format_ids(report.partially_shadowed_by)
        )
        lines.append(
            '  jointly complete: %s' % report.jointly_fully_shadowed
        )
        lines.append('  safe to delete: %s' % report.safe_to_delete)

    return '\n'.join(lines)


def _format_cidrs(cidrs: Sequence[str]) -> str:
    return ', '.join(cidrs) if cidrs else '(none)'


def _format_ids(rule_ids: Sequence[object]) -> str:
    return ', '.join(str(rule_id) for rule_id in rule_ids) if rule_ids else '(none)'


def analysis_to_dict(
    analysis: FirewallAnalysis,
    verification: Optional[DeletionVerification] = None,
) -> Dict[str, object]:
    """Return a JSON-serializable representation of an analysis."""

    data = {
        'default_action': analysis.default_action,
        'safe_to_delete': analysis.safe_to_delete,
        'rules': [
            {
                'index': report.index,
                'id': report.rule.rule_id,
                'action': report.rule.action,
                'declared_cidrs': report.declared_cidrs,
                'effective_cidrs': report.effective_cidrs,
                'same_decision_redundancy_cidrs': report.redundant_cidrs,
                'opposite_decision_truncation_cidrs': report.truncated_cidrs,
                'shadowing_rules': [
                    {
                        'id': shadow.rule_id,
                        'action': shadow.action,
                        'relationship': shadow.relationship,
                        'cidrs': shadow.cidrs,
                        'complete': shadow.complete,
                    }
                    for shadow in report.shadowing_rules
                ],
                'fully_shadowed_individually_by': report.fully_shadowed_individually_by,
                'partially_shadowed_by': report.partially_shadowed_by,
                'jointly_fully_shadowed': report.jointly_fully_shadowed,
                'status': report.status,
                'safe_to_delete': report.safe_to_delete,
            }
            for report in analysis.rules
        ],
    }
    if analysis.policy is not None:
        data['final_partitions'] = analysis.policy.partitions
    if verification is not None:
        data['deletion_verification'] = {
            'removed_rule_ids': verification.removed_rule_ids,
            'equivalent': verification.equivalent,
            'differences': verification.differences,
            'before': verification.before.partitions,
            'after': verification.after.partitions,
        }
    return data


def _load_rules(path: str) -> Dict[str, object]:
    if path == '-':
        payload = json.load(sys.stdin)
    else:
        with open(path, encoding='utf-8') as stream:
            payload = json.load(stream)
    if isinstance(payload, list):
        return {'rules': payload}
    return payload


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description='Analyze sequential IP allow/deny firewall rules.'
    )
    parser.add_argument('rules', help='JSON rules file, or - for standard input')
    parser.add_argument(
        '--default-action',
        choices=ACTIONS,
        help='action for addresses not matched by a rule',
    )
    parser.add_argument('--json', action='store_true', help='emit JSON')
    parser.add_argument(
        '--verify-safe-deletions',
        action='store_true',
        help='delete reported safe rules and compare final address partitions',
    )
    args = parser.parse_args(argv)

    payload = _load_rules(args.rules)
    default_action = args.default_action or payload.get('default_action') or payload.get(
        'default'
    )
    if default_action is not None:
        default_action = _normalize_action(default_action)

    analysis = analyze_firewall(payload.get('rules', ()), default_action=default_action)
    verification = None
    if args.verify_safe_deletions:
        if default_action is None:
            parser.error('--verify-safe-deletions requires --default-action')
        verification = verify_safe_deletions(analysis.rules, default_action=default_action)

    if args.json:
        print(
            json.dumps(analysis_to_dict(analysis, verification), indent=2, sort_keys=True)
        )
    else:
        print(format_analysis(analysis))
        if verification is not None:
            print(
                'deletion verification: equivalent=%s for %r'
                % (verification.equivalent, verification.removed_rule_ids)
            )
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

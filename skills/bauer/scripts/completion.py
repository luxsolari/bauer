"""Validate supplied audit-completion records; no queries or classification."""
import json
from pathlib import Path
from typing import Any, Optional

STATUSES = ('checked', 'reviewed', 'not_applicable', 'blocked', 'not_tested', 'unattempted', 'unavailable', 'error')
APPLICABILITY = ('applicable', 'not_applicable', 'unknown')


def require_text(value):
    if not isinstance(value, str) or not value.strip():
        raise ValueError('completion requires nonempty text')
    return value


def identities(value):
    if not isinstance(value, list) or len(value) > 10000:
        raise ValueError('identity list required (maximum 10000)')
    for item in value:
        require_text(item)
    if len(value) != len(set(value)):
        raise ValueError('duplicate identity')
    return set(value)


def scope_state(document) -> Optional[dict[str, Any]]:
    scope = document.get('completion_scope')
    if scope is None:
        return None
    fields = {'inventory_ids', 'approved_ids', 'queried_ids', 'excluded', 'blocked',
              'inventory_evidence', 'query_evidence', 'remote_targets', 'remote_scope_evidence',
              'published_cve_ids', 'cve_assessment_evidence'}
    if not isinstance(scope, dict) or set(scope) != fields:
        raise ValueError('invalid completion scope fields')
    for field in ('inventory_evidence', 'query_evidence', 'remote_scope_evidence', 'cve_assessment_evidence'):
        require_text(scope[field])
    inventory, approved, queried = (identities(scope[k]) for k in ('inventory_ids', 'approved_ids', 'queried_ids'))
    if not queried <= approved <= inventory:
        raise ValueError('queried identities must be approved inventory subset')
    dispositions = {}
    for field in ('excluded', 'blocked'):
        if not isinstance(scope[field], list) or len(scope[field]) > 10000:
            raise ValueError('dispositions require bounded array')
        records = {}
        for row in scope[field]:
            if not isinstance(row, dict) or set(row) != {'id', 'reason', 'evidence'}:
                raise ValueError('invalid disposition')
            for value in row.values():
                require_text(value)
            if row['id'] not in inventory or row['id'] in records:
                raise ValueError('duplicate or out-of-inventory disposition')
            records[row['id']] = dict(row)
        dispositions[field] = records
    excluded, blocked = (set(dispositions[k]) for k in ('excluded', 'blocked'))
    if excluded & blocked or queried & (excluded | blocked):
        raise ValueError('overlapping dependency dispositions')
    unresolved = inventory - queried - excluded
    remote_targets = identities(scope['remote_targets'])
    cves = identities(scope['published_cve_ids'])
    import re
    if any(not re.fullmatch(r'CVE-[0-9]{4}-[0-9]{4,}', identifier) for identifier in cves):
        raise ValueError('invalid published CVE identity')
    coverage = dict(inventory_count=len(inventory), approved_count=len(approved), queried_count=len(queried),
                    excluded_count=len(excluded), blocked_count=len(blocked),
                    unresolved_ids=sorted(unresolved), unattempted_ids=sorted(unresolved - blocked),
                    inventory_ids=sorted(inventory), approved_ids=sorted(approved), queried_ids=sorted(queried),
                    excluded=[dispositions['excluded'][i] for i in sorted(excluded)],
                    blocked=[dispositions['blocked'][i] for i in sorted(blocked)],
                    inventory_evidence=scope['inventory_evidence'], query_evidence=scope['query_evidence'],
                    status='partial' if unresolved else 'complete')
    return dict(coverage=coverage, remote_targets=sorted(remote_targets),
                remote_scope_evidence=scope['remote_scope_evidence'], published_cve_ids=sorted(cves),
                cve_assessment_evidence=scope['cve_assessment_evidence'])


def evaluate(document):
    registry = json.loads((Path(__file__).resolve().parent.parent / 'references/security-sources.json').read_text(encoding='utf-8'))
    ids = [s['id'] for s in registry['sources']] + ['dependency_coverage', 'remote_configuration']
    scope = scope_state(document)
    if scope is not None:
        ids += ['remote:' + target for target in scope['remote_targets']]
    records = document.get('completion_checks', [])
    if not isinstance(records, list):
        raise ValueError('completion checks require array')
    supplied = {}
    for record in records:
        if not isinstance(record, dict) or set(record) != {'id', 'applicability', 'status', 'reason', 'evidence'}:
            raise ValueError('invalid completion record fields')
        for value in record.values():
            require_text(value)
        identifier = record['id']
        if identifier not in ids or identifier in supplied:
            raise ValueError('unknown or duplicate completion ID')
        app, status = record['applicability'], record['status']
        if app not in APPLICABILITY or status not in STATUSES:
            raise ValueError('invalid completion state')
        if (status == 'not_applicable') != (app == 'not_applicable'):
            raise ValueError('nonapplicability requires explicit supported classification')
        supplied[identifier] = dict(record, record_supplied=True,
                                    satisfied=(app != 'unknown' and status in ('checked', 'reviewed', 'not_applicable')))
    rows = [supplied.get(i, dict(id=i, applicability='unknown', status='unattempted', reason='No record supplied',
                               evidence='', record_supplied=False, satisfied=False)) for i in ids]
    by_id = {row['id']: row for row in rows}
    coverage_complete = scope is not None and scope['coverage']['status'] == 'complete'
    if not coverage_complete:
        by_id['dependency_coverage'].update(satisfied=False, gate_reason='Inventory trace absent or identities unresolved')
    if scope is not None and by_id['dependency_coverage']['status'] == 'not_applicable':
        coverage = scope['coverage']
        excluded_ids = {row['id'] for row in coverage['excluded']}
        if (coverage['approved_ids'] or coverage['queried_ids'] or
                set(coverage['inventory_ids']) - excluded_ids):
            by_id['dependency_coverage'].update(
                satisfied=False, gate_reason='Dependency nonapplicability contradicts approved, queried or nonexcluded inventory identities')
    if (scope is not None and scope['coverage']['queried_ids'] and
            by_id['osv']['status'] == 'not_applicable'):
        by_id['osv'].update(
            satisfied=False,
            gate_reason='OSV nonapplicability is not established over queried identities: ledger lacks source-specific applicability')
    if scope is None:
        by_id['remote_configuration'].update(satisfied=False, gate_reason='Remote scope not evidenced')
    elif scope['remote_targets']:
        remote_complete = all(by_id['remote:' + target]['satisfied'] and
                              by_id['remote:' + target]['applicability'] == 'applicable' for target in scope['remote_targets'])
        if not remote_complete or by_id['remote_configuration']['applicability'] != 'applicable':
            by_id['remote_configuration'].update(satisfied=False, gate_reason='Relevant remote settings not all checked with evidence')
    for identifier in ('cve', 'nvd', 'kev', 'epss'):
        if by_id[identifier]['status'] == 'not_applicable' and (
                not coverage_complete or scope is None or scope['published_cve_ids']):
            by_id[identifier].update(satisfied=False, gate_reason='Absence of applicable published CVEs not established over resolved scope')
    return dict(policy_version='bauer-completion-v1', status='complete' if all(r['satisfied'] for r in rows) else 'partial',
                obligations=rows, dependency_coverage=scope['coverage'] if scope is not None else None,
                assessed_scope=scope,
                authority='Supplied evidence trace validation only; not truth verification or safety certification.')

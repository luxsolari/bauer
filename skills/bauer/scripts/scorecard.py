"""Deterministic supplied-evidence Security Scorecard, not a security rating."""
STATES = ('open', 'fix_reported', 'fix_verified')
DEFAULTS = 'Missing remediation_state defaults to open for queue accounting; not a verified real-world state.'


def build(report):
    gate = report['completion_gate']
    rows = gate['obligations']
    blockers = [r for r in rows if r['selected'] and not r['satisfied']]
    findings = report['findings']
    unresolved = [f for f in findings if f.get('remediation_state', 'open') != 'fix_verified']
    action = dict(kind='none', reason='No unresolved supplied findings or selected coverage gaps; not certification')
    if unresolved:
        first = unresolved[0]
        action = dict(kind='finding', id=first['id'], severity=first['severity'], evidence_status=first['status'],
                      evidence=first['evidence'], remediation_state=first.get('remediation_state', 'open'),
                      action=first['remediation'], verification=first['verification'])
    elif blockers:
        first = blockers[0]
        action = dict(kind='coverage_gap', id=first['id'], reason=first.get('gate_reason', first['reason']),
                      evidence=first['evidence'], status=first['status'])
    card = dict(schema_version='bauer-security-scorecard-v1', scope=report['scope'],
                revision=report.get('revision'), audited_at=report.get('audited_at'),
                audit_profile=report['audit_profile'], completion=gate['status'],
                selected_count=sum(r['selected'] for r in rows),
                satisfied_count=sum(r['selected'] and r['satisfied'] for r in rows), blockers=blockers,
                exclusions=[r for r in rows if not r['selected']], dependency_coverage=gate['dependency_coverage'],
                remote_gaps=[r for r in blockers if r['id'] == 'remote_configuration' or r['id'].startswith('remote:')],
                severity_counts=report['counts'],
                evidence_counts={s: sum(f['status'] == s for f in findings) for s in ('candidate', 'supported', 'reproduced')},
                remediation_counts={s: sum(f.get('remediation_state', 'open') == s for f in findings) for s in STATES},
                remediation_defaults=DEFAULTS,
                jev_queue=report.get('jev_selection', {}).get('queue'),
                jev_outcomes=[dict(id=f['id'], outcome=f['jev']) for f in findings if 'jev' in f],
                next_action=action, authority=gate['authority'])
    if 'run_record' in report:
        record = report['run_record']
        card.update(run_id=record['run_id'], review_decision=record['review_decision'],
                    record_id=record['record_id'], confirmation_status=record['status'],
                    key_present=record['host_environment']['key_present'],
                    run_authority=record['authority'])
    return card


def markdown(card, text):
    lines = ['## Security Scorecard', '', 'Not a numeric security score or safety certification.', '',
             '| Field | Supplied evidence / derived status |', '| --- | --- |']
    profile = card['audit_profile']
    coverage = card['dependency_coverage']
    values = [('Scope', card['scope']), ('Revision', card['revision']), ('Audited at', card['audited_at']),
              ('Profile', profile['mode'] + ' / ' + profile['version']),
              ('Selected sources', ', '.join(profile['selected_sources']) or 'none'),
              ('Completion', card['completion']), ('Selected obligations', card['selected_count']),
              ('Satisfied obligations', card['satisfied_count']),
              ('Out of scope', ', '.join(r['id'] for r in card['exclusions']) or 'none'),
              ('Dependency counts', '; '.join(k + ': ' + str(coverage[k]) for k in
                  ('inventory_count', 'approved_count', 'queried_count', 'excluded_count', 'blocked_count')) +
                  '; unresolved: ' + str(len(coverage['unresolved_ids'])) if coverage is not None else None),
              ('Remote gaps', ', '.join(r['id'] for r in card['remote_gaps']) or 'none'),
              ('Evidence counts', '; '.join(s + ': ' + str(card['evidence_counts'][s]) for s in ('candidate', 'supported', 'reproduced'))),
              ('Remediation counts', '; '.join(s + ': ' + str(card['remediation_counts'][s]) for s in STATES)),
              ('Remediation defaults', card['remediation_defaults'])]
    for key, value in values:
        lines.append('| ' + key + ' | ' + text('unknown / not supplied' if value is None else value) + ' |')
    if 'run_id' in card:
        for key in ('run_id', 'record_id', 'confirmation_status', 'key_present', 'review_decision', 'run_authority'):
            lines.append('| ' + text(key) + ' | ' + text(card[key]) + ' |')
    lines.extend(['', '### Blockers', '', '| Obligation | Outcome | Reason | Evidence |', '| --- | --- | --- | --- |'])
    for row in card['blockers']:
        lines.append('| ' + ' | '.join(text(v) for v in (row['id'], row['status'],
                     row.get('gate_reason', row['reason']), row['evidence'])) + ' |')
    if not card['blockers']:
        lines.append('No selected coverage blockers in supplied evidence.')
    lines.extend(['', '### Next action', ''])
    for key, value in sorted(card['next_action'].items()):
        lines.append('- ' + text(key) + ': ' + text(value))
    lines.extend(['', '### Jev queue and outcomes', ''])
    if card['jev_queue'] is None:
        lines.append('Queue unknown / not supplied; no review completion inferred.')
    else:
        lines.extend(['| Finding | Severity | Evidence status | State |', '| --- | --- | --- | --- |'])
        for row in card['jev_queue']:
            lines.append('| ' + ' | '.join(text(row[k]) for k in ('id', 'severity', 'status', 'state')) + ' |')
        if not card['jev_queue']:
            lines.append('No supplied findings to queue.')
    for outcome in card['jev_outcomes']:
        lines.append('- ' + text(outcome['id']) + ': ' + text(outcome['outcome']))
    if not card['jev_outcomes']:
        lines.append('No supplemental Jev outcomes supplied.')
    return lines

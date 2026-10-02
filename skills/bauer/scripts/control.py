#!/usr/bin/env python3
"""New-audit preflight, offline plans and frozen report controls.

Preflight alone checks boolean key presence. No network, audited scripts,
background processes or settings writes. Audit is a plan, not a scanner.
"""
import argparse
import json
import os
from pathlib import Path
import sys
from profiles import normalize as normalize_profile, PREREQUISITES
from report import unique_object, RESOURCE_NOTE, SEVERITIES, normalize as normalize_report, markdown_text
from scorecard import markdown as scorecard_markdown
from run_record import create as create_run_record, decision as validate_decision, validate as validate_run_record, confirm, profile_decision


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'bauer control: invalid arguments\n')


def read_json(path):
    return json.loads(path.read_text(encoding='utf-8'), object_pairs_hook=unique_object,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError('nonfinite JSON')))


def main(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    subs = parser.add_subparsers(dest='command', required=True, parser_class=SafeParser)
    for name in ('preflight', 'mode', 'audit'):
        sub = subs.add_parser(name, allow_abbrev=False)
        sub.add_argument('--mode', choices=('lean', 'full', 'custom'))
        sub.add_argument('--selected-source', action='append')
        sub.add_argument('--profile-file', type=Path)
        if name == 'preflight':
            sub.add_argument('--review-decision', type=Path,
                             help='Supplied user-decision object, not verified authorization; presence always checked')
            sub.add_argument('--profile-decision', type=Path, help='Literal request/proposal provenance; no authenticated authority')
            sub.add_argument('--output', type=Path, help='Explicit approved artifact path; exclusive creation, no overwrite')
            sub.add_argument('--previous-run-record', type=Path)
            sub.add_argument('--scope-change-decision', type=Path, help='New-run scope change: literal instruction, decision_ref and reason')
    sub = subs.add_parser('confirm', allow_abbrev=False, help='Capture a later user response; cannot authenticate chat')
    sub.add_argument('--run-record', type=Path, required=True)
    sub.add_argument('--decision', choices=('confirm', 'decline'), required=True)
    sub.add_argument('--user-response', required=True, help='Literal real later response, not agent-generated consent')
    sub.add_argument('--response-ref', required=True, help='Actual supplied response reference, never invented origin')
    sub.add_argument('--output', type=Path, help='Exclusive new artifact, never overwrite pending')
    for name in ('status', 'scorecard'):
        sub = subs.add_parser(name, allow_abbrev=False)
        sub.add_argument('report', type=Path)
        sub.add_argument('--format', choices=('json', 'markdown'), default='json')
        if name == 'status':
            sub.add_argument('--current-revision')
    args = parser.parse_args(argv)
    try:
        if args.command == 'confirm':
            record = confirm(read_json(args.run_record), args.decision, args.user_response, args.response_ref)
            if args.output is not None:
                with args.output.open('x', encoding='utf-8') as stream:
                    stream.write(json.dumps(record, indent=2, sort_keys=True, allow_nan=False) + '\n')
            print(json.dumps(dict(operation='capture_confirmation', run_record=record,
                                  chat_delivery_verified=False, user_response_authenticated=False,
                                  authority='Unsigned captured assertion; cannot authenticate user response or chat delivery'),
                             indent=2, sort_keys=True, allow_nan=False))
            return 0
        if args.command in ('status', 'scorecard'):
            report = normalize_report(read_json(args.report))
            json.dumps(report, allow_nan=False)
            card = report['security_scorecard']
            card_lines = scorecard_markdown(card, markdown_text) + [
                '', '## Severity counts', '', '| Severity | Count |', '| --- | --- |'] + [
                '| ' + severity + ' | ' + str(card['severity_counts'][severity]) + ' |' for severity in SEVERITIES]
            if args.command == 'scorecard':
                output = json.dumps(card, indent=2, sort_keys=True, allow_nan=False) if args.format == 'json' else '\n'.join(card_lines)
            else:
                current = args.current_revision
                if current is not None and not current.strip():
                    raise ValueError('empty current revision')
                revision = report.get('revision')
                comparison = 'unknown' if current is None or revision is None else (
                    'matches_supplied_revision' if revision == current else 'stale_revision')
                gaps = [key + '_not_supplied' for key in ('revision', 'audited_at') if key not in report]
                if current is None:
                    gaps.append('current_revision_not_supplied')
                status = dict(operation='saved_report_status', scope=report['scope'], revision=revision,
                              audited_at=report.get('audited_at'), current_revision=current,
                              revision_comparison=comparison, gaps=gaps, completion=card['completion'],
                              audit_profile=card['audit_profile'], blocker_count=len(card['blockers']),
                              report_handle=str(args.report), security_scorecard=card,
                              severity_counts=card['severity_counts'],
                              authority='Supplied saved report only; not freshness verification or a new audit')
                output = json.dumps(status, indent=2, sort_keys=True, allow_nan=False) if args.format == 'json' else '\n'.join(
                    ['## Saved report status', '', '| Field | Value |', '| --- | --- |'] +
                    ['| ' + markdown_text(k) + ' | ' + markdown_text('unknown / not supplied' if v is None else v) + ' |'
                     for k, v in sorted(status.items()) if k not in ('security_scorecard', 'severity_counts')] + ['', *card_lines])
            print(output)
            return 0
        if args.profile_file is not None:
            if args.mode is not None or args.selected_source is not None:
                raise ValueError('file and inline profile are mutually exclusive')
            supplied = read_json(args.profile_file)
            if not isinstance(supplied, dict):
                raise ValueError('profile file must be object')
        else:
            supplied = dict(mode=args.mode or 'lean')
            if args.selected_source is not None:
                if args.mode != 'custom':
                    raise ValueError('explicit sources require custom mode')
                supplied['selected_sources'] = args.selected_source
        profile = normalize_profile(supplied)
        if args.command == 'preflight':
            decision = validate_decision(read_json(args.review_decision)) if args.review_decision else {'state': 'not_requested'}
            disabled = decision['state'] == 'explicit_disable_captured'
            change = None
            if bool(args.previous_run_record) != bool(args.scope_change_decision):
                raise ValueError('previous run and scope change decision must be paired')
            if args.previous_run_record:
                previous = validate_run_record(read_json(args.previous_run_record))
                acknowledgement = read_json(args.scope_change_decision)
                if (not isinstance(acknowledgement, dict) or set(acknowledgement) != {'reason', 'decision_ref', 'user_instruction'} or
                        any(not isinstance(v, str) or not v.strip() for v in acknowledgement.values())):
                    raise ValueError('scope change requires supplied user instruction, reason and reference')
                change = dict(acknowledgement, previous_run_id=previous['run_id'], previous_record_id=previous['record_id'],
                              previous_audit_profile=previous['audit_profile'])
            choice = profile_decision(read_json(args.profile_decision)) if args.profile_decision else (
                {'kind': 'default'} if profile == normalize_profile() else
                dict(kind='agent_proposal', user_instruction=json.dumps(supplied, sort_keys=True),
                     decision_ref='cli:unattributed-profile-parameters', reason='CLI parameters are not proof of a user request'))
            if choice == {'kind': 'default'} and profile != normalize_profile():
                raise ValueError('default cannot change Lean')
            message = (RESOURCE_NOTE + ' If budget matters, we can agree on a bounded scope before proceeding.\n\n'
                       + 'Effective profile: ' + str(profile['mode']).title() + '. Selected sources: '
                       + (', '.join(profile['selected_sources']) or '(none)') + '. '
                       + 'Lean is default; Full/Custom require a request or labeled proposal. '
                       + 'Dependency coverage and relevant remote controls remain required. '
                       + 'Jev selection is disabled by default, not a user decline, even for offline audits.')
            key_present = bool(os.environ.get('TYPESAFE_API_KEY'))
            availability = 'key_present' if key_present else 'missing_key'
            if disabled:
                message += ' A supplied explicit user-disable instruction/reference is captured; its authority is not verified. Boolean presence was still checked.'
            result = dict(operation='new_audit_preflight', audit_profile=profile,
                          key_present=key_present, key_availability=availability,
                          explicit_user_disable=disabled, required_chat_message=True,
                          preflight_message=message, resource_note=RESOURCE_NOTE,
                          persistence='none; per-run selection only',
                          authority='Deterministic preflight output only; cannot guarantee agent chat delivery or adherence; no audit checks run')
            result['run_record'] = create_run_record(profile, key_present, decision, change, choice)
            record = result['run_record']
            message += ('\n\nPending record: ' + record['record_id'] + '. Profile choice: ' + choice['kind']
                        + '. Excluded sources: ' + (', '.join(record['excluded_sources']) or '(none)')
                        + '. Review availability: ' + availability + '. Scheduling decision: ' + decision['state']
                        + (' (user_requested, supplied assertion)' if disabled else ' (default/pending, not declined)') + '.')
            if choice['kind'] != 'default':
                message += ' Literal profile decision: ' + choice['user_instruction'] + ' [' + choice['decision_ref'] + '].'
            if disabled:
                message += ' Literal review decision: ' + decision['user_instruction'] + ' [' + decision['decision_ref'] + '].'
            if change:
                message += ' Scope change from ' + change['previous_record_id'] + ': ' + change['user_instruction'] + ' [' + change['decision_ref'] + '].'
            message += '\nConfirm this mode/decision record, or state corrections? I must stop here and wait for your response before inspecting the target, selecting findings, fetching guidance or creating a report.'
            result.update(preflight_message=message, status=record['status'], next_action='ask_confirmation_then_stop',
                          chat_delivery_verified=False, user_response_authenticated=False)
            if args.output is not None:
                with args.output.open('x', encoding='utf-8') as stream:
                    stream.write(json.dumps(result['run_record'], indent=2, sort_keys=True, allow_nan=False) + '\n')
            print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
            return 0
        result: dict = dict(operation='effective_mode' if args.command == 'mode' else 'agent_audit_plan',
                      audit_profile=profile, persistence='none; per-run selection only',
                      authority='Offline supplied policy plan; agent-led audit, not a scanner')
        if args.command == 'audit':
            result.update(always_required=['dependency_coverage', 'remote_configuration', 'each relevant remote target'],
                          prerequisites=PREREQUISITES, resource_note=RESOURCE_NOTE,
                          next_action='Announce effective profile, scope and authorize checks through the Bauer skill; no checks run here')
        print(json.dumps(result, indent=2, sort_keys=True, allow_nan=False))
    except (OSError, ValueError, TypeError, RecursionError):
        print('bauer control: invalid input', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())

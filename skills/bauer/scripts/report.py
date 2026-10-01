"""Deterministic aggregation of supplied audit evidence, not a scanner."""
import argparse
import html
from datetime import datetime
import hashlib
import json
import re
import sys
import unicodedata
from pathlib import Path, PurePosixPath
from urllib.parse import urlsplit

SEVERITIES = ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')
IDENTIFIER = re.compile(r'(?:A|LLM)(?:0[1-9]|10):20[0-9]{2}')


def normalize(document):
    if not isinstance(document, dict):
        raise ValueError('audit must be an object')
    for field in ('scope',):
        if not isinstance(document.get(field), str) or not document[field].strip():
            raise ValueError('missing audit scope')
    for field in ('sources', 'coverage', 'limitations', 'findings'):
        if not isinstance(document.get(field), list):
            raise ValueError('missing audit list: ' + field)
    if any(not isinstance(item, str) or not item.strip() for item in document['limitations']):
        raise ValueError('limitations must be nonempty strings')
    for source in document['sources']:
        if not isinstance(source, dict):
            raise ValueError('source must be an object')
        for field in ('edition', 'url', 'retrieved_at', 'sha256'):
            if not isinstance(source.get(field), str) or not source[field].strip():
                raise ValueError('missing source text: ' + field)
        if not re.fullmatch(r'20[0-9]{2}', source['edition']) or not re.fullmatch(r'[a-f0-9]{64}', source['sha256']):
            raise ValueError('invalid source edition or digest')
        url = urlsplit(source['url'])
        if url.scheme != 'https' or not url.hostname or url.username is not None or url.password is not None:
            raise ValueError('source URL requires HTTPS without credentials')
        timestamp = datetime.fromisoformat(source['retrieved_at'].replace('Z', '+00:00'))
        if timestamp.tzinfo is None:
            raise ValueError('source retrieval time requires timezone')
    for field, statuses in (
        ('source_checks', ('checked', 'not_applicable', 'unavailable')),
        ('framework_checks', ('reviewed', 'not_applicable', 'not_tested')),
        ('supply_chain_checks', ('reviewed', 'not_applicable', 'not_tested')),
    ):
        if field not in document:
            continue
        if not isinstance(document[field], list):
            raise ValueError('checks must be an array')
        identifiers = set()
        for entry in document[field]:
            if not isinstance(entry, dict):
                raise ValueError('check must be an object')
            for key in ('id', 'reason'):
                if not isinstance(entry.get(key), str) or not entry[key].strip():
                    raise ValueError('check requires text')
            if entry.get('status') not in statuses:
                raise ValueError('invalid check status')
            for key in ('version', 'url', 'retrieved_at', 'sha256', 'evidence'):
                if key in entry and (not isinstance(entry[key], str) or not entry[key].strip()):
                    raise ValueError('invalid check metadata text')
            if 'url' in entry:
                url = urlsplit(entry['url'])
                if (url.scheme != 'https' or not url.hostname or url.username is not None
                        or url.password is not None or any(c.isspace() or ord(c) < 32 for c in entry['url'])):
                    raise ValueError('invalid check URL')
            if 'retrieved_at' in entry:
                timestamp = datetime.fromisoformat(entry['retrieved_at'].replace('Z', '+00:00'))
                if timestamp.tzinfo is None:
                    raise ValueError('check time requires timezone')
            if 'sha256' in entry and not re.fullmatch(r'[a-f0-9]{64}', entry['sha256']):
                raise ValueError('invalid check digest')
            if entry['id'] in identifiers:
                raise ValueError('duplicate check ID')
            identifiers.add(entry['id'])
    coverage_ids = set()
    for entry in document['coverage']:
        if not isinstance(entry, dict) or not isinstance(entry.get('id'), str) or not IDENTIFIER.fullmatch(entry['id']):
            raise ValueError('coverage requires edition-qualified ID')
        if entry.get('status') not in ('reviewed', 'not_applicable', 'not_tested'):
            raise ValueError('invalid coverage status')
        if not isinstance(entry.get('reason'), str) or not entry['reason'].strip():
            raise ValueError('coverage requires reason')
        if entry['id'] in coverage_ids:
            raise ValueError('duplicate coverage category')
        coverage_ids.add(entry['id'])
    findings = []
    identities = set()
    for source in document['findings']:
        if not isinstance(source, dict):
            raise ValueError('finding must be an object')
        finding = dict(source)
        for field in ('rule', 'path', 'title', 'evidence', 'remediation', 'verification'):
            if not isinstance(finding.get(field), str) or not finding[field].strip():
                raise ValueError('missing finding text: ' + field)
        path = PurePosixPath(finding['path'])
        if path.is_absolute() or '..' in path.parts or '\\' in finding['path'] or ':' in finding['path']:
            raise ValueError('finding path must be repository relative')
        if type(finding.get('line')) is not int or finding['line'] < 1:
            raise ValueError('finding line must be a positive integer')
        if finding.get('severity') not in SEVERITIES:
            raise ValueError('invalid severity')
        if finding.get('status') not in ('candidate', 'supported', 'reproduced'):
            raise ValueError('invalid evidence status')
        categories = finding.get('categories')
        if not isinstance(categories, list) or not categories or any(
            not isinstance(c, str) or not IDENTIFIER.fullmatch(c)
            for c in categories
        ):
            raise ValueError('categories require edition-qualified OWASP IDs')
        finding['categories'] = sorted(set(categories))
        finding['path'] = path.as_posix()
        identity = json.dumps([finding['rule'], finding['path'], finding['line']], separators=(',', ':'))
        if identity in identities:
            raise ValueError('duplicate finding identity; merge evidence explicitly')
        identities.add(identity)
        finding['id'] = 'BAUER-' + hashlib.sha256(identity.encode()).hexdigest()[:16]
        findings.append(finding)
    findings.sort(key=lambda item: (SEVERITIES.index(item['severity']), item['path'], item['line'], item['rule']))
    result = dict(document)
    result.update(schema_version='1.0', findings=findings,
                  counts={level: sum(item['severity'] == level for item in findings) for level in SEVERITIES})
    if 'jev_selection' in document and 'jev_policy' not in document:
        raise ValueError('selection requires explicit policy')
    if 'jev_policy' in document:
        supplied = document['jev_policy']
        if not isinstance(supplied, dict) or set(supplied) - {'policy_version', 'enabled', 'min_severity'}:
            raise ValueError('invalid Jev policy')
        policy = dict(policy_version='bauer-jev-selection-v1', enabled=False, min_severity='MEDIUM')
        policy.update(supplied)
        if (policy['policy_version'] != 'bauer-jev-selection-v1' or type(policy['enabled']) is not bool
                or policy['min_severity'] not in SEVERITIES):
            raise ValueError('invalid Jev policy metadata')
        result['jev_policy'] = policy
        queue = []
        for item in findings:
            eligible = SEVERITIES.index(item['severity']) <= SEVERITIES.index(policy['min_severity'])
            state, reason = 'disabled', 'policy_disabled'
            if policy['enabled']:
                state, reason = (('pending_packet_approval', 'severity_at_or_above_threshold') if eligible
                                 else ('not_selected', 'below_min_severity'))
            queue.append(dict(id=item['id'], severity=item['severity'], status=item['status'],
                              eligible=eligible, state=state, reason=reason))
        result['jev_selection'] = dict(policy=policy, queue=queue)
        if ('jev_selection' in document and
                json.dumps(document['jev_selection'], sort_keys=True, allow_nan=False) !=
                json.dumps(result['jev_selection'], sort_keys=True, allow_nan=False)):
            raise ValueError('selection metadata does not match evidence and policy')
    return result


def visible_text(value):
    """Keep controls and formatting marks visible, never executable."""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False, separators=(',', ':'))
    return ''.join(('\\u%04x' % ord(c)) if unicodedata.category(c) in ('Cc', 'Cf', 'Cs', 'Zl', 'Zp')
                   else c for c in str(value))


def markdown_text(value):
    """Entities prevent HTML, Markdown syntax and automatic URL linking."""
    escaped = ''.join(c if c.isalnum() or c in ' ;' else '&#%d;' % ord(c)
                      for c in visible_text(value))
    # Linkifiers may decode entities before recognizing URLs. Code spans are
    # excluded from linkification; retain entities inside them as a second layer.
    decoded = html.unescape(str(value))
    if re.search(r'(?i)([a-z][a-z0-9+.-]*:|www\.|@)', decoded):
        return '` ' + escaped + ' `'
    return escaped


def markdown_code(value):
    """Use a longer delimiter than every supplied backtick run."""
    value = html.escape(visible_text(value), quote=False)
    width = max((len(run) for run in re.findall(r'`+', value)), default=0) + 1
    fence = '`' * width
    return fence + ' ' + value + ' ' + fence


def render_markdown(report):
    """Render an already normalized report without collecting new evidence."""
    text = markdown_text
    lines = ['# Bauer audit report', '', 'Scope: ' + text(report['scope']), '', '## Severity counts', '']
    lines.extend(['| Severity | Count |', '| --- | --- |'])
    lines.extend('| ' + level + ' | ' + str(report['counts'][level]) + ' |' for level in SEVERITIES)
    lines.extend(['', '## Findings', ''])
    for finding in report['findings']:
        status = finding['status'] + (' (unconfirmed)' if finding['status'] == 'candidate' else '')
        lines.extend(['### ' + finding['id'] + ' — ' + text(finding['title']), '',
                      '- Severity: ' + finding['severity'], '- Status: ' + status,
                      '- Location: ' + markdown_code(finding['path'] + ':' + str(finding['line'])),
                      '- Rule: ' + text(finding['rule']),
                      '- Categories: ' + text(', '.join(finding['categories']))])
        for key in ('evidence', 'remediation', 'verification'):
            lines.append('- ' + key.capitalize() + ': ' + text(finding[key]))
        if 'jev' in finding:
            lines.append('- Jev (supplemental): ' + text(json.dumps(finding['jev'], sort_keys=True, allow_nan=False)))
        lines.append('')
    if not report['findings']:
        lines.append('No supplied findings; this is not proof of safety.')
    if 'jev_selection' in report:
        selection = report['jev_selection']
        policy = selection['policy']
        lines.extend(['', '## Jev selection queue', '',
                      '- Policy version: ' + text(policy['policy_version']),
                      '- Enabled: ' + str(policy['enabled']).lower(),
                      '- Minimum severity: ' + policy['min_severity'],
                      '', 'Eligibility is not disclosure approval; no requests are made by selection.', '',
                      '| Finding | Severity | Status | Eligible | State | Reason |',
                      '| --- | --- | --- | --- | --- | --- |'])
        for item in selection['queue']:
            lines.append('| ' + ' | '.join(text(item[key]) for key in
                         ('id', 'severity', 'status', 'eligible', 'state', 'reason')) + ' |')
        if not selection['queue']:
            lines.append('No supplied findings to select.')
    lines.extend(['', '## Remediation queue', ''])
    for finding in report['findings']:
        lines.append('- ' + finding['severity'] + ' / ' + finding['id'] + ': ' + text(finding['remediation']))
    for field, heading in [('sources', 'Sources'), ('coverage', 'Coverage'),
                           ('source_checks', 'Source checks'), ('framework_checks', 'Framework checks'),
                           ('supply_chain_checks', 'Supply-chain checks')]:
        if field not in report:
            continue
        lines.extend(['', '## ' + heading, ''])
        for entry in report[field]:
            lines.append('- ' + '; '.join(text(key) + ': ' + text(value) for key, value in sorted(entry.items())))
        if not report[field]:
            lines.append('No entries supplied; coverage is not established.')
    lines.extend(['', '## Coverage gaps', ''])
    gaps = []
    for field in ('coverage', 'source_checks', 'framework_checks', 'supply_chain_checks'):
        for entry in report.get(field, []):
            if entry['status'] in ('not_tested', 'unavailable'):
                gaps.append('- ' + field + ' / ' + text(entry['id']) + ': ' + entry['status'] + ' — ' + text(entry['reason']))
    lines.extend(gaps or ['No explicit gaps supplied; completeness is not established.'])
    lines.extend(['', '## Limitations', ''])
    lines.extend(['- ' + text(item) for item in report['limitations']] or ['No limitations supplied; this is not a completeness claim.'])
    return '\n'.join(lines) + '\n'


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'bauer report: invalid arguments\n')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def main():
    parser = SafeArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--format', choices=('json', 'markdown'), default='json')
    args = parser.parse_args()
    try:
        report = normalize(json.loads(args.evidence.read_text(encoding='utf-8'), object_pairs_hook=unique_object))
        normalized_json = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + '\n'
        output = normalized_json if args.format == 'json' else render_markdown(report)
    except (OSError, ValueError, TypeError, RecursionError):
        print('bauer report: invalid input', file=sys.stderr)
        return 1
    print(output, end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())

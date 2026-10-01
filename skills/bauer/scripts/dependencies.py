#!/usr/bin/env python3
"""Opt-in OSV dependency advisory queries; Python 3.9+, stdlib only.

Input: {"packages": [{"ecosystem": "PyPI", "name": "public-name",
"version": "1.2.3"}]}. Supply exact resolved public identities in OSV's
case-sensitive spelling. Approval asserts that this curated inventory is
public and reviewed; the helper cannot verify registry visibility or resolve
versions. No repository scanning, credentials, installation, or URL collection.
Inventory: 128 KiB, 1..100 packages, identity strings up to 1024 UTF-8 bytes.
Constraints, common moving tags, URLs, whitespace and common credentials are
rejected without normalization. Package versions are never compared locally.

Fixed HTTPS POST https://api.osv.dev/v1/query; timeout 20 seconds per network
operation, no redirects/retries, 8 MiB per response, at most 20 pages/package.
OSV documents fuzzy upstream version matching: results are advisory matches,
not proof of applicability, runtime reachability, exploitability or safety.
Structural validation covers consumed fields, not full OSV schema semantics;
source metadata and extension fields are retained, not independently verified.

JSON stdout and optional --output contain status (complete/partial/unavailable),
inventory_sha256, packages (identity, checked/incomplete, pages, reason),
matches (package, advisory_ids, aliases, current records), skipped withdrawn
records, advisory_history (all deduplicated records/provenance by exact queried
package and advisory ID, state active/withdrawn/needs_adjudication), adjudications
(conflicting latest records), and responses (exact query, request_sha256,
response_sha256, retrieved_at UTC, status). Latest modified wins per advisory ID,
never by alias; older withdrawal can be superseded by newer active content.
Equal latest timestamps with differing content require adjudication, exclude that
ID from ordinary matches, and mark its package incomplete/nonzero. RFC3339
fractions compare exactly (including nanoseconds); original strings are retained.
records retain entire advisory objects including modified/published,
affected ranges, fixed events, severity and source metadata; response_indices
link them to provenance. Each record has identity_status (exact/mismatch/unknown
for affected ecosystem/name) and applicability=unverified even on exact names.
Only explicit IDs/aliases merge, separately for each
exact package ecosystem/name/version. Conflicting source records are preserved.
Errors retain prior validated matches, mark incomplete, and exit nonzero using
static reason codes, never exception text. Invalid input/absent approval exits 1;
invalid arguments exits 2. Oversize/interrupted responses have no full-response
hash; they cannot count as checked. Complete means all queries exhausted, not
an exhaustive vulnerability audit. Save stdout or use --output for frozen data;
fresh calls can change source content and UTC dates. No other feeds queried.

Official contract: https://google.github.io/osv.dev/post-v1-query/
Schema: https://ossf.github.io/osv-schema/
"""
import argparse
import json
import hashlib
import http.client
import math
import re
from fractions import Fraction
from datetime import datetime, timezone
from pathlib import Path
import urllib.request

ENDPOINT = 'https://api.osv.dev/v1/query'
RESPONSE_LIMIT = 8 * 1024 * 1024


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_key')
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError('nonfinite')


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError('nonfinite')
    return number


def decode_json(raw):
    return json.loads(raw.decode('utf-8'), object_pairs_hook=unique_object,
                      parse_constant=reject_constant, parse_float=finite_float)


def text(value, limit=1024):
    if not isinstance(value, str) or not value or len(value.encode('utf-8')) > limit:
        raise ValueError('invalid_string')
    if value != value.strip() or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError('invalid_string')


def load_inventory(path):
    with Path(path).open('rb') as stream:
        raw = stream.read(128 * 1024 + 1)
    if len(raw) > 128 * 1024:
        raise ValueError('inventory_size')
    inventory = decode_json(raw)
    if not isinstance(inventory, dict) or set(inventory) != {'packages'}:
        raise ValueError('invalid_fields')
    packages = inventory['packages']
    if not isinstance(packages, list) or not 1 <= len(packages) <= 100:
        raise ValueError('package_count')
    for package in packages:
        if not isinstance(package, dict) or set(package) != {'ecosystem', 'name', 'version'}:
            raise ValueError('invalid_package')
        for key, value in package.items():
            text(value)
            forbidden = ('=', '<', '>', '^', '*', '|', '\\t')
            if value.startswith('~') or any(char in value for char in forbidden) or (key != 'ecosystem' and any(c.isspace() for c in value)):
                raise ValueError('unresolved_or_credential')
            if '://' in value or value.lower().startswith(('bearer', 'token:', 'password:', 'ghp_', 'github_pat_', 'sk-proj-')):
                raise ValueError('credential_or_url')
        if package['version'].lower() in ('latest', 'unknown', 'main', 'master', 'head'):
            raise ValueError('unresolved_version')
    return packages, hashlib.sha256(raw).hexdigest()


def timestamp(value):
    """Validate RFC3339 and return exact UTC seconds without altering source text."""
    text(value)
    match = re.fullmatch(
        r'([0-9]{4}-[0-9]{2}-[0-9]{2})[Tt]([0-9]{2}:[0-9]{2}:[0-9]{2})'
        r'(?:\.([0-9]+))?([Zz]|[+-][0-9]{2}:[0-9]{2})', value)
    if not match:
        raise ValueError('invalid_timestamp')
    date, clock, fraction, offset = match.groups()
    # Parse whole seconds only: Python 3.9 rejects longer fractional precision.
    parsed = datetime.fromisoformat(date + 'T' + clock)
    offset_seconds = 0
    if offset not in ('Z', 'z'):
        hours, minutes = int(offset[1:3]), int(offset[4:6])
        if hours > 23 or minutes > 59:
            raise ValueError('invalid_timezone')
        offset_seconds = (hours * 3600 + minutes * 60) * (1 if offset[0] == '+' else -1)
    seconds = ((parsed.toordinal() * 24 + parsed.hour) * 60 + parsed.minute) * 60 + parsed.second
    return Fraction(seconds - offset_seconds) + (Fraction(int(fraction), 10 ** len(fraction))
                                                if fraction else Fraction(0))


def string_list(value):
    if not isinstance(value, list):
        raise ValueError('list_required')
    for item in value:
        text(item)


def metadata(value):
    for key in ('database_specific', 'ecosystem_specific'):
        if key in value and not isinstance(value[key], dict):
            raise ValueError('metadata_object_required')
    if 'severity' in value:
        if not isinstance(value['severity'], list):
            raise ValueError('severity_list_required')
        for severity in value['severity']:
            if not isinstance(severity, dict):
                raise ValueError('severity_object_required')
            text(severity.get('type'))
            text(severity.get('score'))
            if 'source' in severity:
                text(severity['source'])


def validate_response(payload):
    # Validate the consumed OSV structural contract; preserve extension fields.
    if not isinstance(payload, dict) or set(payload) - {'vulns', 'next_page_token'}:
        raise ValueError('response_object_required')
    if 'next_page_token' in payload and payload['next_page_token'] != '':
        text(payload['next_page_token'], 8192)
    advisories = payload.get('vulns', [])
    if not isinstance(advisories, list):
        raise ValueError('vulns_list_required')
    for advisory in advisories:
        if not isinstance(advisory, dict):
            raise ValueError('advisory_object_required')
        text(advisory.get('id'))
        timestamp(advisory.get('modified'))
        for key in ('published', 'withdrawn'):
            if key in advisory:
                timestamp(advisory[key])
        for key in ('aliases', 'related', 'upstream'):
            if key in advisory:
                string_list(advisory[key])
        for key in ('summary', 'details', 'schema_version'):
            if key in advisory and not isinstance(advisory[key], str):
                raise ValueError('string_required')
        metadata(advisory)
        if 'references' in advisory:
            if not isinstance(advisory['references'], list):
                raise ValueError('references_list_required')
            for reference in advisory['references']:
                if not isinstance(reference, dict):
                    raise ValueError('reference_object_required')
                text(reference.get('type'))
                text(reference.get('url'), RESPONSE_LIMIT)
        affected = advisory.get('affected', [])
        if not isinstance(affected, list):
            raise ValueError('affected_list_required')
        for entry in affected:
            if not isinstance(entry, dict):
                raise ValueError('affected_object_required')
            metadata(entry)
            if 'package' in entry:
                package = entry['package']
                if not isinstance(package, dict):
                    raise ValueError('package_object_required')
                text(package.get('ecosystem'))
                text(package.get('name'))
                if 'purl' in package:
                    text(package['purl'])
            if 'versions' in entry:
                string_list(entry['versions'])
            ranges = entry.get('ranges', [])
            if not isinstance(ranges, list):
                raise ValueError('ranges_list_required')
            for affected_range in ranges:
                if not isinstance(affected_range, dict):
                    raise ValueError('range_object_required')
                if affected_range.get('type') not in ('GIT', 'SEMVER', 'ECOSYSTEM'):
                    raise ValueError('range_type')
                metadata(affected_range)
                if 'repo' in affected_range:
                    text(affected_range['repo'])
                events = affected_range.get('events')
                if not isinstance(events, list) or not events:
                    raise ValueError('events_required')
                for event in events:
                    if not isinstance(event, dict) or len(event) != 1 or not set(event) <= {'introduced', 'fixed', 'last_affected', 'limit'}:
                        raise ValueError('event_shape')
                    text(next(iter(event.values())))
    return payload


def merge_match(matches, package, advisory, index):
    identities = {advisory['id']} | set(advisory.get('aliases', []))
    connected = []
    for match in matches:
        if match['package'] == package and identities & (set(match['advisory_ids']) | set(match['aliases'])):
            connected.append(match)
    records = [{'advisory': advisory, 'response_indices': [index]}]
    for match in connected:
        records.extend(match['records'])
        matches.remove(match)
    unique = {}
    for record in records:
        key = json.dumps(record['advisory'], sort_keys=True, separators=(',', ':'), ensure_ascii=False)
        if key not in unique:
            unique[key] = {'advisory': record['advisory'], 'response_indices': []}
        unique[key]['response_indices'] = sorted(set(unique[key]['response_indices'] + record['response_indices']))
    retained = [unique[key] for key in sorted(unique)]
    for record in retained:
        identities = [entry['package'] for entry in record['advisory'].get('affected', []) if 'package' in entry]
        exact = any(all(identity.get(key) == package[key] for key in ('ecosystem', 'name')) for identity in identities)
        record['identity_status'] = 'exact' if exact else ('mismatch' if identities else 'unknown')
        record['applicability'] = 'unverified'
    matches.append({'package': package,
                    'advisory_ids': sorted({r['advisory']['id'] for r in retained}),
                    'aliases': sorted({a for r in retained for a in r['advisory'].get('aliases', [])}),
                    'records': retained})
    matches.sort(key=lambda m: (m['package']['ecosystem'], m['package']['name'],
                               m['package']['version'], m['advisory_ids']))


def reconcile_advisories(result):
    """Select current records by exact query identity and advisory ID, not aliases."""
    collected = result['matches']
    result['matches'] = []
    result['advisory_history'] = []
    result['adjudications'] = []
    for component in collected:
        package = component['package']
        for identifier in component['advisory_ids']:
            records = [r for r in component['records'] if r['advisory']['id'] == identifier]
            latest = max(timestamp(r['advisory']['modified']) for r in records)
            current = [r for r in records if timestamp(r['advisory']['modified']) == latest]
            state = 'withdrawn' if 'withdrawn' in current[0]['advisory'] else 'active'
            if len(current) > 1:
                state = 'needs_adjudication'
                result['adjudications'].append({'package': package, 'advisory_id': identifier,
                    'reason': 'conflicting_latest_records', 'records': current})
                for outcome in result['packages']:
                    if outcome['package'] == package:
                        outcome['status'] = 'incomplete'
                        outcome.setdefault('reason', 'advisory_conflict')
            result['advisory_history'].append({'package': package, 'advisory_id': identifier,
                                               'state': state, 'records': records})
            if state == 'active':
                for record in current:
                    for index in record['response_indices']:
                        merge_match(result['matches'], package, record['advisory'], index)
    result['advisory_history'].sort(key=lambda h: (h['package']['ecosystem'],
        h['package']['name'], h['package']['version'], h['advisory_id']))


class RejectRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def query_inventory(path, allowed=False):
    result = {'status': 'unavailable', 'matches': [], 'packages': [], 'responses': [],
              'skipped': [], 'source': 'OSV', 'endpoint': ENDPOINT}
    if not allowed:
        return dict(result, reason='consent_required')
    try:
        packages, digest = load_inventory(path)
    except (OSError, ValueError, RecursionError):
        return dict(result, reason='invalid_inventory')
    result['inventory_sha256'] = digest
    for package in packages:
        query = {'package': {key: package[key] for key in ('ecosystem', 'name')},
                 'version': package['version']}
        seen_tokens = set()
        reason = None
        pages_read = 0
        for page in range(20):
            body = json.dumps(query, sort_keys=True, separators=(',', ':')).encode('utf-8')
            request = urllib.request.Request(ENDPOINT, data=body, method='POST',
                                             headers={'Content-Type': 'application/json'})
            provenance = {'query': dict(query), 'request_sha256': hashlib.sha256(body).hexdigest(),
                          'retrieved_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}
            result['responses'].append(provenance)
            try:
                with urllib.request.build_opener(RejectRedirects()).open(request, timeout=20) as response:
                    if response.status != 200:
                        raise ValueError('http_status')
                    raw = response.read(RESPONSE_LIMIT + 1)
            except (OSError, ValueError, http.client.HTTPException):
                provenance['status'] = 'transport_error'
                reason = 'transport_error'
                break
            if len(raw) > RESPONSE_LIMIT:
                provenance['status'] = 'response_too_large'
                reason = 'response_too_large'
                break
            provenance['response_sha256'] = hashlib.sha256(raw).hexdigest()
            index = len(result['responses']) - 1
            try:
                payload = validate_response(decode_json(raw))
            except (ValueError, RecursionError):
                provenance['status'] = 'invalid_response'
                reason = 'invalid_response'
                break
            provenance['status'] = 'validated'
            for advisory in payload.get('vulns', []):
                if 'withdrawn' in advisory:
                    result['skipped'].append({'package': package, 'reason': 'withdrawn',
                                              'advisory': advisory, 'response_index': index})
                merge_match(result['matches'], package, advisory, index)
            pages_read += 1
            token = payload.get('next_page_token')
            if not token:
                break
            if token in seen_tokens:
                reason = 'repeated_page_token'
                break
            seen_tokens.add(token)
            query['page_token'] = token
        else:
            reason = 'page_limit'
        outcome = {'package': package, 'status': 'incomplete' if reason else 'checked', 'pages': pages_read}
        if reason:
            outcome['reason'] = reason
        result['packages'].append(outcome)
    reconcile_advisories(result)
    result['status'] = 'partial' if any(p['status'] != 'checked' for p in result['packages']) else 'complete'
    return result


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('invalid_arguments')


def main(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False,
                        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('inventory', help='Curated public resolved inventory JSON')
    parser.add_argument('--allow-inventory-disclosure', action='store_true',
                        help='Approve disclosure of this reviewed inventory to OSV')
    parser.add_argument('--output', help='Save result JSON (also emitted on stdout)')
    try:
        args = parser.parse_args(argv)
    except ValueError:
        print(json.dumps({'status': 'unavailable', 'reason': 'invalid_arguments'}))
        return 2
    result = query_inventory(args.inventory, args.allow_inventory_disclosure)
    encoded = json.dumps(result, sort_keys=True, ensure_ascii=True, allow_nan=False)
    if args.output:
        try:
            Path(args.output).write_text(encoded + '\n', encoding='utf-8')
        except (OSError, ValueError):
            result['status'] = 'partial' if result['packages'] else 'unavailable'
            result['reason'] = 'output_error'
            encoded = json.dumps(result, sort_keys=True, allow_nan=False)
    print(encoded)
    return 0 if result['status'] == 'complete' else 1


if __name__ == '__main__':
    raise SystemExit(main())

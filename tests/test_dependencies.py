"""OSV adapter tests: synthetic identities and mocked transports only."""
import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / 'skills/bauer/scripts/dependencies.py'
PACKAGE = {'ecosystem': 'PyPI', 'name': 'synthetic-example', 'version': '1.2.3'}


def load_adapter():
    assert SCRIPT.is_file(), 'OSV adapter must exist'
    spec = importlib.util.spec_from_file_location('bauer_dependencies', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.adapter = load_adapter()

    def run_cli(self, inventory=None, flags=None, raw=None, extra=None):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'inventory.json'
            path.write_bytes(raw if raw is not None else json.dumps(
                inventory if inventory is not None else {'packages': [PACKAGE]}).encode())
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = self.adapter.main([str(path)] + (flags or []) + (extra or []))
            return code, json.loads(output.getvalue())

    def test_exact_query_empty_response_provenance(self):
        raw = b'{ "vulns": [] }\n'
        with mock.patch('urllib.request.build_opener') as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = raw
            code, result = self.run_cli(flags=['--allow-inventory-disclosure'])
        self.assertEqual(code, 0)
        self.assertEqual(result['status'], 'complete')
        self.assertEqual(result['matches'], [])
        self.assertEqual(result['packages'][0]['status'], 'checked')
        request = factory.return_value.open.call_args.args[0]
        self.assertEqual(request.full_url, 'https://api.osv.dev/v1/query')
        self.assertEqual(request.get_method(), 'POST')
        self.assertEqual(json.loads(request.data), {'package': {
            'ecosystem': PACKAGE['ecosystem'], 'name': PACKAGE['name']}, 'version': PACKAGE['version']})
        self.assertIsNone(request.get_header('Authorization'))
        self.assertEqual(factory.return_value.open.call_args.kwargs, {'timeout': 20})
        response.read.assert_called_once_with(8 * 1024 * 1024 + 1)
        provenance = result['responses'][0]
        self.assertEqual(provenance['response_sha256'], hashlib.sha256(raw).hexdigest())
        self.assertEqual(provenance['request_sha256'], hashlib.sha256(request.data).hexdigest())
        self.assertTrue(provenance['retrieved_at'].endswith('Z'))
        self.assertEqual(provenance['query'], json.loads(request.data))

    def test_invalid_inventory_rejected_without_disclosure(self):
        invalid = [b'no json', b'[]', b'{}', b'{"packages":[]}', b'\xff',
                   b'{"packages":[],"packages":[]}', b'{"packages":NaN}',
                   b'[' * 2000, b' ' * (128 * 1024 + 1)]
        for package in ({}, dict(PACKAGE, private=True), dict(PACKAGE, version='>=1.0'),
                        dict(PACKAGE, version='latest'), dict(PACKAGE, version='1.*'),
                        dict(PACKAGE, version='^1.0'), dict(PACKAGE, name='https://user:pass@host'),
                        dict(PACKAGE, name=' synthetic'), dict(PACKAGE, name='token=secret'),
                        dict(PACKAGE, name=1), dict(PACKAGE, version=''),
                        dict(PACKAGE, ecosystem='PyPI\n'), dict(PACKAGE, version='x' * 1025)):
            invalid.append(json.dumps({'packages': [package]}).encode())
        invalid.append(json.dumps({'packages': [PACKAGE] * 101}).encode())
        invalid.append(json.dumps({'packages': [PACKAGE], 'token': 'secret'}).encode())
        with mock.patch('urllib.request.build_opener') as network:
            for raw in invalid:
                with self.subTest(raw=raw[:80]):
                    code, result = self.run_cli(raw=raw, flags=['--allow-inventory-disclosure'])
                    self.assertNotEqual(code, 0)
                    self.assertEqual(result['reason'], 'invalid_inventory')
            network.assert_not_called()

    @staticmethod
    def advisory(identifier='GHSA-synthetic-0001', aliases=None, package=None):
        return {'id': identifier, 'aliases': aliases or ['CVE-2099-0001'],
                'modified': '2026-10-01T00:00:00Z', 'published': '2026-09-01T00:00:00Z',
                'summary': 'Synthetic advisory', 'database_specific': {'cwe_ids': ['CWE-79']},
                'affected': [{'package': {key: (package or PACKAGE)[key] for key in ('ecosystem', 'name')},
                              'ranges': [{'type': 'ECOSYSTEM', 'events': [
                                  {'introduced': '0'}, {'fixed': '2.0.0'}]}],
                              'ecosystem_specific': {'custom': 'retain'}, 'versions': ['1.2.3']}]}

    def response_cli(self, pages, inventory=None):
        with mock.patch('urllib.request.build_opener') as factory:
            streams = []
            for page in pages:
                response = mock.MagicMock()
                response.status = 200
                response.read.return_value = page if isinstance(page, bytes) else json.dumps(page).encode()
                context = mock.MagicMock()
                context.__enter__.return_value = response
                streams.append(context)
            factory.return_value.open.side_effect = streams
            code, result = self.run_cli(inventory=inventory, flags=['--allow-inventory-disclosure'])
            requests = [json.loads(call.args[0].data) for call in factory.return_value.open.call_args_list]
        return code, result, requests

    def test_advisory_match_retains_full_metadata_and_withdrawn_skip(self):
        active = self.advisory()
        withdrawn = dict(self.advisory('OSV-synthetic-withdrawn'), withdrawn='2026-09-30T00:00:00Z')
        code, result, _ = self.response_cli([{'vulns': [active, withdrawn]}])
        self.assertEqual(code, 0)
        self.assertEqual(len(result['matches']), 1)
        match = result['matches'][0]
        self.assertEqual(match['package'], PACKAGE)
        self.assertEqual(match['advisory_ids'], [active['id']])
        self.assertEqual(match['aliases'], active['aliases'])
        self.assertEqual(match['records'][0]['advisory'], active)
        self.assertEqual(match['records'][0]['response_indices'], [0])
        self.assertEqual(result['skipped'][0]['reason'], 'withdrawn')
        self.assertEqual(result['skipped'][0]['advisory'], withdrawn)

    def test_newer_withdrawal_replaces_active_in_either_order(self):
        active = self.advisory()
        withdrawn = dict(active, modified='2026-10-02T00:00:00Z',
                         withdrawn='2026-10-02T00:00:00Z')
        for ordered in ([active, withdrawn], [withdrawn, active]):
            for paginated in (False, True):
                with self.subTest(order=[a['modified'] for a in ordered], paginated=paginated):
                    pages = ([{'vulns': [ordered[0]], 'next_page_token': 'more'},
                              {'vulns': [ordered[1]]}] if paginated else [{'vulns': ordered}])
                    code, result, _ = self.response_cli(pages)
                    self.assertEqual(code, 0)
                    self.assertEqual(result['matches'], [])
                    history = result['advisory_history'][0]
                    self.assertEqual(history['package'], PACKAGE)
                    self.assertEqual(history['advisory_id'], active['id'])
                    self.assertEqual(history['state'], 'withdrawn')
                    self.assertCountEqual([r['advisory'] for r in history['records']], ordered)
                    for record in history['records']:
                        expected = ordered.index(record['advisory']) if paginated else 0
                        self.assertEqual(record['response_indices'], [expected])
                        self.assertEqual(result['responses'][expected]['status'], 'validated')
                    self.assertEqual(result['skipped'][0]['advisory'], withdrawn)

    def test_equal_time_conflicts_require_adjudication_in_either_order(self):
        active = self.advisory()
        withdrawn = dict(active, withdrawn='2026-10-01T00:00:00Z',
                         modified='2026-09-30T21:00:00-03:00')
        changed = dict(active, summary='Conflicting active content')
        for conflict in (withdrawn, changed):
            for ordered in ([active, conflict], [conflict, active]):
                with self.subTest(conflict=conflict, order=ordered):
                    code, result, _ = self.response_cli([
                        {'vulns': [ordered[0]], 'next_page_token': 'more'},
                        {'vulns': [ordered[1]]}])
                    self.assertEqual(code, 1)
                    self.assertEqual(result['status'], 'partial')
                    self.assertEqual(result['packages'][0]['status'], 'incomplete')
                    self.assertEqual(result['packages'][0]['reason'], 'advisory_conflict')
                    self.assertEqual(result['matches'], [])
                    adjudication = result['adjudications'][0]
                    self.assertEqual(adjudication['reason'], 'conflicting_latest_records')
                    self.assertEqual(adjudication['advisory_id'], active['id'])
                    self.assertEqual(adjudication['package'], PACKAGE)
                    history = result['advisory_history'][0]
                    self.assertEqual(history['state'], 'needs_adjudication')
                    self.assertCountEqual([r['advisory'] for r in history['records']], ordered)
                    self.assertEqual([r['response_indices'] for r in history['records']],
                                     [r['response_indices'] for r in adjudication['records']])

    def test_newer_active_supersedes_withdrawal_with_history_in_all_permutations(self):
        from itertools import permutations
        old = self.advisory()
        withdrawn = dict(old, modified='2026-10-02T00:00:00Z',
                         withdrawn='2026-10-02T00:00:00Z')
        active = dict(old, modified='2026-10-03T00:00:00Z', summary='Reinstated')
        for ordered in permutations([old, withdrawn, active]):
            with self.subTest(order=[a['modified'] for a in ordered]):
                pages = [{'vulns': [advisory], 'next_page_token': str(index)}
                         for index, advisory in enumerate(ordered)]
                del pages[-1]['next_page_token']
                code, result, _ = self.response_cli(pages)
                self.assertEqual(code, 0)
                self.assertEqual(len(result['matches']), 1)
                self.assertEqual([r['advisory'] for r in result['matches'][0]['records']], [active])
                history = result['advisory_history'][0]
                self.assertEqual(history['state'], 'active')
                self.assertCountEqual([r['advisory'] for r in history['records']], ordered)
                for record in history['records']:
                    self.assertEqual(record['response_indices'], [ordered.index(record['advisory'])])

    def test_withdrawal_is_scoped_to_id_ecosystem_name_and_version(self):
        from itertools import permutations
        active = self.advisory('OSV-A')
        withdrawn = dict(active, modified='2026-10-02T00:00:00Z',
                         withdrawn='2026-10-02T00:00:00Z')
        separate = self.advisory('OSV-B')  # Same alias, independent advisory ID.
        isolated = [dict(PACKAGE, name='second-synthetic'),
                    dict(PACKAGE, version='1.2.4'), dict(PACKAGE, ecosystem='npm')]
        for ordered in permutations([active, withdrawn, separate]):
            with self.subTest(order=[a['id'] + a['modified'] for a in ordered]):
                code, result, _ = self.response_cli(
                    [{'vulns': list(ordered)}] + [{'vulns': [active]} for _ in isolated],
                    {'packages': [PACKAGE] + isolated})
                self.assertEqual(code, 0)
                self.assertEqual(len(result['matches']), 4)
                for match in result['matches']:
                    expected = separate if match['package'] == PACKAGE else active
                    self.assertEqual(match['advisory_ids'], [expected['id']])
                    self.assertEqual([r['advisory'] for r in match['records']], [expected])
                history = [h for h in result['advisory_history'] if h['package'] == PACKAGE]
                self.assertEqual({h['advisory_id']: h['state'] for h in history},
                                 {'OSV-A': 'withdrawn', 'OSV-B': 'active'})

    def test_duplicate_records_preserve_all_response_indices(self):
        active = self.advisory()
        withdrawn = dict(active, modified='2026-10-02T00:00:00Z',
                         withdrawn='2026-10-02T00:00:00Z')
        code, result, _ = self.response_cli([
            {'vulns': [active, withdrawn], 'next_page_token': 'more'},
            {'vulns': [withdrawn, active]}])
        self.assertEqual(code, 0)
        self.assertEqual(result['matches'], [])
        records = result['advisory_history'][0]['records']
        self.assertEqual(len(records), 2)
        self.assertTrue(all(r['response_indices'] == [0, 1] for r in records))
        self.assertEqual([r['response_index'] for r in result['skipped']], [0, 1])

    def test_rfc3339_nanosecond_updates_are_retained_and_ordered_exactly(self):
        active = dict(self.advisory(), modified='2026-09-10T03:50:25.139398550Z')
        withdrawn = dict(active, modified='2026-09-10T00:50:25.139398551-03:00',
                         withdrawn='2026-09-10T03:50:25.139398551Z')
        for ordered in ([active, withdrawn], [withdrawn, active]):
            with self.subTest(order=ordered):
                code, result, _ = self.response_cli([{'vulns': ordered}])
                self.assertEqual(code, 0)
                self.assertEqual(result['matches'], [])
                history = result['advisory_history'][0]
                self.assertEqual(history['state'], 'withdrawn')
                self.assertCountEqual([r['advisory'] for r in history['records']], ordered)
                self.assertEqual(result['adjudications'], [])
        self.assertEqual(self.adapter.timestamp('2026-09-10T03:50:25.139398550Z'),
                         self.adapter.timestamp('2026-09-10T00:50:25.13939855-03:00'))

    def test_timestamp_rejects_malformed_rfc3339_without_losing_provenance(self):
        malformed = ['2026-10-01', '2026-10-01T00:00:00',
                     '2026-10-01 00:00:00Z', '2026-10-01T00:00Z',
                     '2026-10-01T00:00:00+0300', '2026-10-01T00:00:00+03',
                     '2026-10-01T00:00:00+03:00:01',
                     '2026-10-01T00:00:00+24:00', '2026-10-01T00:00:00+00:60',
                     '2026-10-01T24:00:00Z', '2026-02-30T00:00:00Z',
                     '2026-10-01T00:00:00.Z', '2026-10-01T00:00:00,123Z']
        for value in malformed:
            with self.subTest(value=value):
                code, result, _ = self.response_cli([
                    {'vulns': [dict(self.advisory(), modified=value)]}])
                self.assertEqual(code, 1)
                self.assertEqual(result['packages'][0]['reason'], 'invalid_response')
                self.assertEqual(result['matches'], [])
                self.assertIn('response_sha256', result['responses'][0])

    def test_pagination_including_token_only_page(self):
        code, result, requests = self.response_cli([
            {'next_page_token': 'opaque-one'},
            {'vulns': [self.advisory()], 'next_page_token': 'opaque-two'}, {}])
        self.assertEqual(code, 0)
        self.assertEqual(len(requests), 3)
        self.assertNotIn('page_token', requests[0])
        self.assertEqual(requests[1]['page_token'], 'opaque-one')
        self.assertEqual(requests[2]['page_token'], 'opaque-two')
        self.assertEqual(len(result['responses']), 3)
        self.assertEqual(result['matches'][0]['records'][0]['response_indices'], [1])
        self.assertEqual(result['packages'][0]['pages'], 3)

    def test_page_bound_and_repeated_token_preserve_partial_matches(self):
        cases = [([{'vulns': [self.advisory()], 'next_page_token': str(i)} for i in range(20)],
                  'page_limit', 20),
                 ([{'vulns': [self.advisory()], 'next_page_token': 'same'}] * 2,
                  'repeated_page_token', 2)]
        for pages, reason, count in cases:
            with self.subTest(reason=reason):
                code, result, requests = self.response_cli(pages)
                self.assertNotEqual(code, 0)
                self.assertEqual(result['status'], 'partial')
                self.assertEqual(result['packages'][0]['status'], 'incomplete')
                self.assertEqual(result['packages'][0]['reason'], reason)
                self.assertEqual(len(requests), count)
                self.assertTrue(result['matches'])

    def test_malformed_response_leaves_explicit_partial_with_hash(self):
        import copy
        invalid = [b'no json', b'\xff', b'[' * 2000, b'{"vulns":[],"vulns":[]}',
                   b'{"vulns":NaN}', [], {'vulns': None}, {'vulns': [None]},
                   {'next_page_token': 1}, {'next_page_token': 'x' * 8193},
                   b' ' * (8 * 1024 * 1024 + 1)]
        for path, value in [(('id',), ''), (('aliases',), [1]), (('modified',), 'not-time'),
                            (('withdrawn',), None), (('affected',), None),
                            (('affected', 0, 'package', 'name'), 1),
                            (('affected', 0, 'ranges'), 'bad'),
                            (('affected', 0, 'ranges', 0, 'events'), [{'fixed': 1}]),
                            (('affected', 0, 'ranges', 0, 'events'), [{'fixed': '2', 'introduced': '0'}]),
                            (('affected', 0, 'versions'), [True]), (('database_specific',), []),
                            (('severity',), [{'type': 'CVSS_V3', 'score': 1}]),
                            (('references',), [{'type': 'WEB', 'url': 1}])]:
            advisory = copy.deepcopy(self.advisory())
            target = advisory
            for part in path[:-1]:
                target = target[part]
            target[path[-1]] = value
            invalid.append({'vulns': [advisory]})
        del_missing = self.advisory()
        del del_missing['modified']
        invalid.append({'vulns': [del_missing]})
        for page in invalid:
            with self.subTest(page=str(page)[:80]):
                code, result, _ = self.response_cli([page])
                self.assertNotEqual(code, 0)
                self.assertEqual(result['status'], 'partial')
                self.assertEqual(result['packages'][0]['reason'], 'response_too_large' if isinstance(page, bytes) and len(page) > 8 * 1024 * 1024 else 'invalid_response')
                self.assertEqual(result['matches'], [])
                self.assertEqual(len(result['responses']), 1)
                if result['packages'][0]['reason'] == 'response_too_large':
                    self.assertNotIn('response_sha256', result['responses'][0])
                else:
                    self.assertIn('response_sha256', result['responses'][0])

    def test_transport_failure_preserves_other_packages_and_never_leaks(self):
        import http.client
        import urllib.error
        failures = [TimeoutError('PRIVATE BODY'), OSError('PRIVATE BODY'),
                    http.client.IncompleteRead(b'PRIVATE BODY'),
                    urllib.error.URLError('PRIVATE BODY'),
                    urllib.error.HTTPError('https://evil.invalid', 403, 'PRIVATE BODY', {}, io.BytesIO(b'PRIVATE BODY'))]
        other = dict(PACKAGE, name='second-synthetic')
        for failure in failures:
            with self.subTest(kind=type(failure).__name__):
                with mock.patch('urllib.request.build_opener') as factory:
                    context = mock.MagicMock()
                    context.__enter__.return_value.status = 200
                    context.__enter__.return_value.read.return_value = b'{}'
                    factory.return_value.open.side_effect = [failure, context]
                    code, result = self.run_cli({'packages': [PACKAGE, other]}, ['--allow-inventory-disclosure'])
                self.assertNotEqual(code, 0)
                self.assertEqual(result['status'], 'partial')
                self.assertEqual(result['packages'][0]['reason'], 'transport_error')
                self.assertEqual(result['packages'][1]['status'], 'checked')
                self.assertNotIn('PRIVATE BODY', json.dumps(result))
                self.assertEqual(factory.return_value.open.call_count, 2)

    def test_non_success_status_and_read_failure_are_partial(self):
        for status in (201, 204, 301, 302, 303, 307, 308, 400, 429, 500):
            with self.subTest(status=status):
                with mock.patch('urllib.request.build_opener') as factory:
                    response = factory.return_value.open.return_value.__enter__.return_value
                    response.status = status
                    response.read.return_value = b'PRIVATE BODY'
                    code, result = self.run_cli(flags=['--allow-inventory-disclosure'])
                    response.read.assert_not_called()
                self.assertNotEqual(code, 0)
                self.assertEqual(result['packages'][0]['reason'], 'transport_error')
        with mock.patch('urllib.request.build_opener') as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.side_effect = TimeoutError('PRIVATE BODY')
            code, result = self.run_cli(flags=['--allow-inventory-disclosure'])
        self.assertNotEqual(code, 0)
        self.assertEqual(result['packages'][0]['reason'], 'transport_error')
        self.assertNotIn('PRIVATE BODY', json.dumps(result))

    def test_redirects_do_not_disclose_inventory_to_second_host(self):
        import email.message
        import urllib.request
        import urllib.response
        real_build = urllib.request.build_opener
        requests = []

        class FakeHTTPS(urllib.request.HTTPSHandler):
            def https_open(self, request):
                requests.append(request)
                headers = email.message.Message()
                headers['Location'] = 'https://evil.invalid/collect'
                response = urllib.response.addinfourl(io.BytesIO(b'PRIVATE BODY'), headers, request.full_url, status)
                response.msg = 'Redirect'
                return response

        for status in (301, 302, 303, 307, 308):
            requests.clear()
            with self.subTest(status=status):
                with mock.patch('urllib.request.build_opener', side_effect=lambda *handlers: real_build(FakeHTTPS(), *handlers)):
                    code, result = self.run_cli(flags=['--allow-inventory-disclosure'])
                self.assertNotEqual(code, 0)
                self.assertEqual(len(requests), 1)
                self.assertEqual(requests[0].full_url, 'https://api.osv.dev/v1/query')
                self.assertNotIn('PRIVATE BODY', json.dumps(result))

    def test_alias_components_are_transitive_and_package_version_aware(self):
        other = dict(PACKAGE, name='second-synthetic')
        newer = dict(PACKAGE, version='1.2.4')
        first = self.advisory('OSV-A', ['CVE-2099-0001'])
        second = self.advisory('OSV-B', ['GHSA-link'])
        bridge = self.advisory('OSV-C', ['CVE-2099-0001', 'GHSA-link'])
        unrelated = self.advisory('OSV-D', ['CVE-2099-0002'])
        code, result, _ = self.response_cli([
            {'vulns': [first, second], 'next_page_token': 'more'},
            {'vulns': [bridge, first, unrelated]},
            {'vulns': [self.advisory(package=other)]},
            {'vulns': [first]}], {'packages': [PACKAGE, other, newer]})
        self.assertEqual(code, 0)
        self.assertEqual(len(result['matches']), 4)
        matches = [m for m in result['matches'] if m['package'] == PACKAGE]
        merged = next(m for m in matches if 'OSV-A' in m['advisory_ids'])
        self.assertEqual(merged['advisory_ids'], ['OSV-A', 'OSV-B', 'OSV-C'])
        self.assertEqual(merged['aliases'], ['CVE-2099-0001', 'GHSA-link'])
        self.assertEqual(len(merged['records']), 3)
        self.assertEqual(next(r for r in merged['records'] if r['advisory']['id'] == 'OSV-A')['response_indices'], [0, 1])
        self.assertEqual(len(matches), 2)  # Same CWE and summary are not aliases.

    def test_saved_result_and_help_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / 'matches.json'
            with mock.patch('urllib.request.build_opener') as factory:
                response = factory.return_value.open.return_value.__enter__.return_value
                response.status = 200
                response.read.return_value = b'{}'
                code, result = self.run_cli(flags=['--allow-inventory-disclosure'], extra=['--output', str(output_path)])
            self.assertEqual(code, 0)
            self.assertEqual(json.loads(output_path.read_text()), result)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), self.assertRaises(SystemExit) as exit:
            self.adapter.main(['--help'])
        self.assertEqual(exit.exception.code, 0)
        for field in ('packages', 'matches', 'advisory_ids', 'aliases', 'response_sha256', 'retrieved_at', 'partial', '8 MiB'):
            self.assertIn(field, stdout.getvalue())

    def test_cli_errors_are_safe_json(self):
        for args in ([], ['x', '--endpoint=https://PRIVATE.invalid'], ['x', '--allow-inv']):
            with self.subTest(args=args):
                output, stderr = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(output), contextlib.redirect_stderr(stderr):
                    code = self.adapter.main(args)
                self.assertEqual(code, 2)
                self.assertEqual(json.loads(output.getvalue())['reason'], 'invalid_arguments')
                self.assertEqual(stderr.getvalue(), '')
        with mock.patch('urllib.request.build_opener') as factory:
            response = factory.return_value.open.return_value.__enter__.return_value
            response.status = 200
            response.read.return_value = b'{}'
            code, result = self.run_cli(flags=['--allow-inventory-disclosure'], extra=['--output', '/nonexistent-directory/result.json'])
        self.assertNotEqual(code, 0)
        self.assertEqual(result['reason'], 'output_error')
        self.assertEqual(result['packages'][0]['status'], 'checked')

    def test_nonfinite_extension_numbers_fail_closed(self):
        raw = json.dumps({'vulns': [self.advisory()]}).encode().replace(
            b'"custom": "retain"', b'"custom": 1e999')
        code, result, _ = self.response_cli([raw])
        self.assertNotEqual(code, 0)
        self.assertEqual(result['packages'][0]['reason'], 'invalid_response')
        self.assertEqual(result['matches'], [])

    def test_ecosystem_spelling_and_version_are_preserved(self):
        package = {'ecosystem': 'Rocky Linux:8', 'name': 'synthetic-rpm', 'version': '1:2.0-1.el8'}
        code, result, requests = self.response_cli([{}], {'packages': [package]})
        self.assertEqual(code, 0)
        self.assertEqual(requests[0]['package']['ecosystem'], 'Rocky Linux:8')
        self.assertEqual(requests[0]['version'], package['version'])
        self.assertEqual(result['packages'][0]['package'], package)

    def test_affected_identity_mismatch_remains_explicit(self):
        wrong = self.advisory(package=dict(PACKAGE, name='different-synthetic'))
        missing = self.advisory('OSV-missing')
        del missing['affected']
        code, result, _ = self.response_cli([{'vulns': [wrong, missing]}])
        self.assertEqual(code, 0)
        records = result['matches'][0]['records']
        self.assertEqual({r['identity_status'] for r in records}, {'mismatch', 'unknown'})
        self.assertTrue(all(r['applicability'] == 'unverified' for r in records))

    def test_conflicting_alias_records_are_not_discarded(self):
        first = self.advisory()
        conflict = self.advisory('OSV-alias-conflict')
        conflict['affected'][0]['ranges'][0]['events'][1]['fixed'] = '3.0.0'
        code, result, _ = self.response_cli([{'vulns': [first, conflict]}])
        self.assertEqual(code, 0)
        self.assertEqual(len(result['matches']), 1)
        self.assertEqual(len(result['matches'][0]['records']), 2)
        self.assertEqual({r['identity_status'] for r in result['matches'][0]['records']}, {'exact'})

    def test_later_page_failure_keeps_validated_records_and_saves_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / 'partial.json'
            with mock.patch('urllib.request.build_opener') as factory:
                context = mock.MagicMock()
                context.__enter__.return_value.status = 200
                context.__enter__.return_value.read.return_value = json.dumps(
                    {'vulns': [self.advisory()], 'next_page_token': 'more'}).encode()
                factory.return_value.open.side_effect = [context, TimeoutError('PRIVATE BODY')]
                code, result = self.run_cli(flags=['--allow-inventory-disclosure'], extra=['--output', str(output)])
            self.assertEqual(code, 1)
            self.assertEqual(len(result['matches']), 1)
            self.assertEqual(len(result['responses']), 2)
            self.assertEqual(result['packages'][0]['pages'], 1)
            self.assertEqual(result['packages'][0]['reason'], 'transport_error')
            self.assertEqual(json.loads(output.read_text()), result)
            self.assertNotIn('response_sha256', result['responses'][1])
        code, result = self.response_cli([{'vulns': [self.advisory()], 'next_page_token': 'next'}, b'no json'])[:2]
        self.assertEqual(code, 1)
        self.assertEqual(len(result['matches']), 1)
        self.assertEqual(result['packages'][0]['reason'], 'invalid_response')

    def test_resolved_distribution_prerelease_is_not_a_constraint(self):
        package = {'ecosystem': 'Debian:12', 'name': 'synthetic-deb', 'version': '1:2.0~rc1-1'}
        code, _, requests = self.response_cli([{}], {'packages': [package]})
        self.assertEqual(code, 0)
        self.assertEqual(requests[0]['version'], package['version'])

    def test_consent_required_before_read_or_network(self):
        with mock.patch('urllib.request.build_opener') as network:
            code, result = self.run_cli(raw=b'invalid')
        self.assertEqual(code, 1)
        self.assertEqual(result['reason'], 'consent_required')
        self.assertEqual(result['status'], 'unavailable')
        network.assert_not_called()


if __name__ == '__main__':
    unittest.main()

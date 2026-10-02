"""Offline deterministic selection policy tests; synthetic evidence only."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_report import load_report, synthetic_document, recorded_document

SCRIPT = Path(__file__).resolve().parents[1] / 'skills/bauer/scripts/selection.py'


class SelectionTests(unittest.TestCase):
    def test_cli_naked_raw_evidence_rejects_without_queue(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'raw.json'
            for document in (synthetic_document(), dict(synthetic_document(), findings=[]),
                             dict(synthetic_document(), report_origin='historical_saved_report')):
                path.write_text(json.dumps(document))
                for flags in ([], ['--enabled']):
                    with self.subTest(document=document, flags=flags):
                        run = subprocess.run([sys.executable, str(SCRIPT), str(path), *flags], capture_output=True)
                        self.assertEqual(run.returncode, 1)
                        self.assertEqual(run.stdout, b'')
                        self.assertEqual(run.stderr, ('bauer selection: invalid input' + os.linesep).encode())

    def test_cli_confirmed_boundary_and_saved_history_preserve_original(self):
        module = load_report()
        confirmed = recorded_document()
        pending = confirmed['run_record']['confirmation']['pending_record']
        # Use the actual confirmation validator to produce a genuine declined fixture.
        import importlib.util
        spec = importlib.util.spec_from_file_location('selection_record', SCRIPT.with_name('run_record.py'))
        assert spec is not None and spec.loader is not None
        record_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(record_module)
        declined = record_module.confirm(pending, 'decline', 'Synthetic decline', 'fixture:later-decline')
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path, record_path = Path(directory) / 'evidence.json', Path(directory) / 'record.json'
            def run(*flags):
                return subprocess.run([sys.executable, str(SCRIPT), str(path), *flags], capture_output=True)
            path.write_text(json.dumps(synthetic_document()))
            for record in (pending, declined, {}, None):
                record_path.write_text(json.dumps(record))
                rejected = run('--run-record', str(record_path), '--enabled')
                self.assertEqual(rejected.returncode, 1)
                self.assertEqual(rejected.stdout, b'')
                self.assertEqual(rejected.stderr, ('bauer selection: invalid input' + os.linesep).encode())
            record_path.write_text(json.dumps(confirmed['run_record']))
            for document in (synthetic_document(), dict(synthetic_document(), findings=[])):
                path.write_text(json.dumps(document))
                accepted = run('--run-record', str(record_path), '--enabled')
                self.assertEqual(accepted.returncode, 0, accepted.stderr)
                selection = json.loads(accepted.stdout)
                report = module.normalize_new_evidence(module.bind_run_record(document, confirmed['run_record']))
                self.assertEqual(selection['run_id'], report['security_scorecard']['run_id'])
                self.assertEqual(selection['record_id'], report['security_scorecard']['record_id'])
            path.write_text(json.dumps(dict(synthetic_document(), audit_profile={'mode': 'full'})))
            self.assertEqual(run('--run-record', str(record_path)).returncode, 1)
            self.assertEqual(run('--run-record', str(Path(directory) / 'missing.json')).stdout, b'')
            for name in ('complete', 'asvs-gap', 'disabled-policy'):
                original = json.loads((SCRIPT.parents[3] / ('tests/fixtures/v021-' + name + '.json')).read_text())
                saved = module.normalize_saved(original)
                self.assertEqual(saved['audit_profile']['mode'], 'full')
                self.assertEqual(saved['completion_migration']['legacy_gate'], original['completion_gate'])
                if name == 'asvs-gap':
                    self.assertIn('asvs', [row['id'] for row in saved['security_scorecard']['blockers']])
                path.write_text(json.dumps(original))
                before = path.read_bytes()
                for flags in ([], ['--enabled'], ['--enabled', '--min-severity', 'HIGH']):
                    accepted = run(*flags)
                    self.assertEqual(accepted.returncode, 0, accepted.stderr)
                    selection = json.loads(accepted.stdout)
                    self.assertEqual([item['id'] for item in selection['queue']],
                                     [item['id'] for item in saved['findings']])
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(module.normalize_saved(saved), saved)
                for field in ('completion_gate', 'completion_migration', 'security_scorecard', 'jev_selection'):
                    forged = copy.deepcopy(saved)
                    forged[field] = {}
                    path.write_text(json.dumps(forged))
                    rejected = run('--enabled', '--min-severity', 'HIGH')
                    self.assertEqual(rejected.returncode, 1)
                    self.assertEqual(rejected.stdout, b'')
                    self.assertEqual(rejected.stderr, ('bauer selection: invalid input' + os.linesep).encode())
            for helper in (module.normalize_new_evidence, module.normalize_saved):
                for document in (synthetic_document(), dict(synthetic_document(), report_origin='historical_saved_report')):
                    with self.assertRaises(ValueError):
                        helper(document)
            # The aggregation API remains pure and backward-compatible, not a CLI consent boundary.
            self.assertEqual(len(module.normalize(synthetic_document())['findings']), 1)

    def test_default_policy_disabled_medium_boundary_for_every_status(self):
        module = load_report()
        document = synthetic_document()
        base = document['findings'][0]
        document['findings'] = [dict(base, severity=severity, status=status, rule=severity + status)
                                for severity in module.SEVERITIES
                                for status in ('candidate', 'supported', 'reproduced')]
        document['jev_policy'] = {}
        result = module.normalize(document)
        selection = result.get('jev_selection')
        self.assertIsNotNone(selection, 'normalized report needs deterministic selection')
        self.assertEqual(result['jev_policy'], dict(policy_version='bauer-jev-selection-v1',
                                                    enabled=False, min_severity='MEDIUM'))
        self.assertEqual(len(selection['queue']), 15)
        for item, finding in zip(selection['queue'], result['findings']):
            self.assertEqual(item['id'], finding['id'])
            self.assertEqual(item['severity'], finding['severity'])
            self.assertEqual(item['status'], finding['status'])
            self.assertEqual(item['eligible'], finding['severity'] in ('CRITICAL', 'HIGH', 'MEDIUM'))
            self.assertEqual(item['state'], 'disabled')
            self.assertEqual(item['reason'], 'policy_disabled')
        self.assertEqual(selection['policy'], result['jev_policy'])

    def test_enabled_threshold_overrides_include_reproduced_without_a_cap(self):
        module = load_report()
        document = synthetic_document()
        base = document['findings'][0]
        document['findings'] = [dict(base, severity=severity, status=status, rule=severity + status)
                                for severity in module.SEVERITIES
                                for status in ('candidate', 'supported', 'reproduced')]
        for threshold in module.SEVERITIES:
            with self.subTest(threshold=threshold):
                document['jev_policy'] = dict(enabled=True, min_severity=threshold)
                queue = module.normalize(document)['jev_selection']['queue']
                self.assertEqual(len(queue), len(document['findings']))
                for item in queue:
                    eligible = module.SEVERITIES.index(item['severity']) <= module.SEVERITIES.index(threshold)
                    self.assertEqual(item['eligible'], eligible)
                    self.assertEqual(item['state'], 'pending_packet_approval' if eligible else 'not_selected')
                    self.assertEqual(item['reason'], 'severity_at_or_above_threshold' if eligible else 'below_min_severity')

    def test_policy_and_derived_metadata_fail_closed(self):
        module = load_report()
        for policy in [None, [], True, dict(enabled=1), dict(enabled='false'),
                       dict(min_severity='medium'), dict(min_severity=None),
                       dict(policy_version='v2'), dict(allow_external=True)]:
            with self.subTest(policy=policy), self.assertRaises(ValueError):
                module.normalize(dict(synthetic_document(), jev_policy=policy))
        normalized = module.normalize(dict(synthetic_document(), jev_policy=dict(enabled=True)))
        self.assertEqual(module.normalize(normalized), normalized)
        forged = copy.deepcopy(normalized)
        forged['jev_selection']['queue'][0]['state'] = 'approved'
        with self.assertRaises(ValueError):
            module.normalize(forged)
        with self.assertRaises(ValueError):
            module.normalize(dict(synthetic_document(), jev_selection={}))

    def test_cli_repeated_bytes_permutations_and_explicit_opt_in(self):
        self.assertTrue(SCRIPT.is_file(), 'selection CLI missing')
        module = load_report()
        document = recorded_document()
        document['findings'].append(dict(document['findings'][0], rule='other', severity='LOW', status='reproduced'))
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'evidence.json'
            def run(*flags):
                return subprocess.run([sys.executable, str(SCRIPT), str(path), *flags], capture_output=True)
            path.write_text(json.dumps(document), encoding='utf-8')
            first = run('--enabled')
            self.assertEqual(first.returncode, 0, first.stderr)
            self.assertEqual(first.stderr, b'')
            self.assertEqual(first.stdout, run('--enabled').stdout)
            queue = json.loads(first.stdout)
            self.assertEqual(queue, module.normalize(dict(document, jev_policy=dict(enabled=True)))['jev_selection'])
            document['findings'].reverse()
            document['findings'][0]['id'] = 'untrusted-supplied-id'
            path.write_text(json.dumps(document), encoding='utf-8')
            self.assertEqual(first.stdout, run('--enabled').stdout)
            disabled = json.loads(run().stdout)
            self.assertFalse(disabled['policy']['enabled'])
            self.assertTrue(all(item['state'] == 'disabled' for item in disabled['queue']))
            for threshold in ('LOW', 'HIGH'):
                changed = run('--enabled', '--min-severity', threshold)
                self.assertEqual(changed.returncode, 0, changed.stderr)
                self.assertEqual(json.loads(changed.stdout)['policy']['min_severity'], threshold)

    def test_derived_metadata_rejects_boolean_integer_aliases(self):
        module = load_report()
        normalized = module.normalize(dict(synthetic_document(), jev_policy=dict(enabled=True)))
        for mutate in ('eligible', 'enabled'):
            forged = copy.deepcopy(normalized)
            if mutate == 'eligible':
                forged['jev_selection']['queue'][0]['eligible'] = 1
            else:
                forged['jev_selection']['policy']['enabled'] = 1
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                module.normalize(forged)

    def test_markdown_displays_policy_and_every_queue_state_separately(self):
        module = load_report()
        document = synthetic_document()
        document['findings'].append(dict(document['findings'][0], rule='low', severity='LOW'))
        for enabled in (False, True):
            normalized = module.normalize(dict(document, jev_policy=dict(enabled=enabled)))
            output = module.render_markdown(normalized)
            self.assertIn('## Jev selection queue', output)
            self.assertIn('bauer&#45;jev&#45;selection&#45;v1', output)
            self.assertIn('MEDIUM', output)
            for item in normalized['jev_selection']['queue']:
                self.assertIn(item['id'], output)
                self.assertIn(module.markdown_text(item['state']), output)
                self.assertIn(module.markdown_text(item['reason']), output)
            self.assertIn('not disclosure approval', output)

    def test_cli_saved_policy_overrides_recompute_card_after_original_validation(self):
        module = load_report()
        legacy = json.loads((SCRIPT.parents[3] / 'tests/fixtures/v021-complete.json').read_text())
        documents = [legacy, json.loads((SCRIPT.parents[3] / 'tests/fixtures/v021-disabled-policy.json').read_text()),
                     module.normalize(recorded_document()),
                     module.normalize(recorded_document(dict(synthetic_document(), jev_policy={'enabled': False}))),
                     module.normalize(recorded_document(dict(synthetic_document(), findings=[], jev_policy={})))]
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'saved.json'
            for document in documents:
                for flags, enabled, threshold in [([], False, 'MEDIUM'), (['--enabled'], True, 'MEDIUM'),
                        (['--enabled', '--min-severity', 'CRITICAL'], True, 'CRITICAL')]:
                    path.write_text(json.dumps(document))
                    with self.subTest(profile=document.get('audit_profile'), flags=flags):
                        run = subprocess.run([sys.executable, str(SCRIPT), str(path), *flags], capture_output=True)
                        self.assertEqual(run.returncode, 0, run.stderr)
                        queue = json.loads(run.stdout)
                        self.assertEqual(queue['policy']['enabled'], enabled)
                        self.assertEqual(queue['policy']['min_severity'], threshold)
                        self.assertEqual(len(queue['queue']), len(document['findings']))
                        for item in queue['queue']:
                            self.assertEqual(item['eligible'], threshold != 'CRITICAL')
                for field in ('completion_gate', 'security_scorecard', 'jev_selection'):
                    if field not in document:
                        continue
                    forged = copy.deepcopy(document)
                    forged[field] = {}
                    path.write_text(json.dumps(forged))
                    run = subprocess.run([sys.executable, str(SCRIPT), str(path), '--enabled'], capture_output=True)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertEqual(run.stdout, b'')

    def test_cli_invalid_evidence_and_arguments_emit_no_queue(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'PRIVATE.json'
            document = recorded_document()
            documents = [dict(document, findings=document['findings'] * 2),
                         dict(document, findings=[dict(document['findings'][0], severity='PRIVATE')]),
                         dict(document, jev_policy=dict(enabled='PRIVATE')),
                         dict(document, extra=float('nan')), dict(document, extra=float('inf'))]
            contents = [json.dumps(item).encode() for item in documents]
            contents += [b'not json PRIVATE', b'\xffPRIVATE', b'[]',
                         json.dumps(document).encode()[:-1] + b',"scope":"PRIVATE"}']
            for raw in contents:
                path.write_bytes(raw)
                with self.subTest(raw=raw[:40]):
                    run = subprocess.run([sys.executable, str(SCRIPT), str(path), '--enabled'], capture_output=True)
                    self.assertNotEqual(run.returncode, 0)
                    self.assertEqual(run.stdout, b'')
                    self.assertEqual(run.stderr, ('bauer selection: invalid input' + os.linesep).encode('ascii'))
            for flags in (['--min-severity', 'PRIVATE'], ['--enable'], ['--allow-external'], ['--packet-reviewed']):
                run = subprocess.run([sys.executable, str(SCRIPT), str(path), *flags], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, b'')
                self.assertEqual(run.stderr, ('bauer selection: invalid arguments' + os.linesep).encode('ascii'))

    def test_enabled_selection_cannot_access_keys_network_or_adapter(self):
        import contextlib
        import importlib.util
        import io
        from unittest import mock
        with mock.patch.object(sys, 'path', [str(SCRIPT.parent)] + sys.path):
            spec = importlib.util.spec_from_file_location('bauer_selection', SCRIPT)
            assert spec is not None and spec.loader is not None
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'evidence.json'
            path.write_text(json.dumps(recorded_document()), encoding='utf-8')
            output = io.StringIO()
            def forbid_key_access(name, default=None):
                if name == 'TYPESAFE_API_KEY':
                    raise AssertionError('key access forbidden')
                return default
            with mock.patch('urllib.request.build_opener') as network, \
                    mock.patch('os.environ.get', side_effect=forbid_key_access), \
                    contextlib.redirect_stdout(output):
                self.assertEqual(module.main([str(path), '--enabled']), 0)
                network.assert_not_called()
            selection = json.loads(output.getvalue())
            self.assertEqual(selection['queue'][0]['state'], 'pending_packet_approval')
            self.assertNotIn('jev', sys.modules)

    def test_supplemental_review_outcomes_never_suppress_selection(self):
        module = load_report()
        for assessment in [dict(status='available', review_only=True),
                           dict(status='declined', review_only=True, reason='Packet disclosure declined'),
                           dict(status='unavailable', review_only=True, reason='missing_api_key')]:
            document = synthetic_document()
            document['findings'][0].update(status='reproduced', jev=assessment)
            result = module.normalize(dict(document, jev_policy=dict(enabled=True)))
            self.assertEqual(result['findings'][0]['jev'], assessment)
            self.assertEqual(result['counts']['HIGH'], 1)
            self.assertEqual(result['jev_selection']['queue'][0]['state'], 'pending_packet_approval')


if __name__ == '__main__':
    unittest.main()

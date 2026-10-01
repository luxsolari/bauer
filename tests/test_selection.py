"""Offline deterministic selection policy tests; synthetic evidence only."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_report import load_report, synthetic_document

SCRIPT = Path(__file__).resolve().parents[1] / 'skills/bauer/scripts/selection.py'


class SelectionTests(unittest.TestCase):
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
        document = synthetic_document()
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

    def test_cli_invalid_evidence_and_arguments_emit_no_queue(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'PRIVATE.json'
            document = synthetic_document()
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
                    self.assertEqual(run.stderr, b'bauer selection: invalid input\n')
            for flags in (['--min-severity', 'PRIVATE'], ['--enable'], ['--allow-external'], ['--packet-reviewed']):
                run = subprocess.run([sys.executable, str(SCRIPT), str(path), *flags], capture_output=True)
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, b'')
                self.assertEqual(run.stderr, b'bauer selection: invalid arguments\n')

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
            path.write_text(json.dumps(synthetic_document()), encoding='utf-8')
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

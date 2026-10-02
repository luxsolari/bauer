"""Synthetic responses exercise consistency, never real user authentication."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_report import synthetic_document

SCRIPTS = Path(__file__).resolve().parents[1] / 'skills/bauer/scripts'


class ConfirmationTests(unittest.TestCase):
    def cli(self, script, *args):
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'TMPDIR')}
        return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)],
                              env=env, text=True, capture_output=True)

    def test_confirm_decline_links_and_tampering(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            pending_path, confirmed_path, evidence = [Path(directory) / n for n in ('pending.json', 'confirmed.json', 'evidence.json')]
            first = self.cli('control.py', 'preflight', '--output', pending_path)
            pending = json.loads(first.stdout)['run_record']
            original = pending_path.read_bytes()
            evidence.write_text(json.dumps(dict(synthetic_document(), findings=[], jev_policy={'enabled': False})))
            for action in ('confirm', 'decline'):
                captured = self.cli('control.py', 'confirm', '--run-record', pending_path, '--decision', action,
                                    '--user-response', 'Synthetic fixture: ' + action, '--response-ref', 'fixture:second-turn')
                self.assertEqual(captured.returncode, 0, captured.stderr)
                record = json.loads(captured.stdout)['run_record']
                self.assertEqual(record['run_id'], pending['run_id'])
                self.assertNotEqual(record['record_id'], pending['record_id'])
                self.assertEqual(record['confirmation']['pending_record'], pending)
                confirmed_path.write_text(json.dumps(record))
                run = self.cli('report.py', evidence, '--run-record', confirmed_path)
                if action == 'decline':
                    self.assertNotEqual(run.returncode, 0)
                    self.assertEqual(run.stdout, '')
                    continue
                self.assertEqual(run.returncode, 0, run.stderr)
                result = json.loads(run.stdout)
                self.assertEqual(result['security_scorecard']['record_id'], record['record_id'])
                self.assertEqual(result['jev_selection']['record_id'], record['record_id'])
                evidence.write_text(json.dumps(dict(synthetic_document(), record_id='wrong-record')))
                mismatch = self.cli('report.py', evidence, '--run-record', confirmed_path)
                self.assertNotEqual(mismatch.returncode, 0, 'top-level record identity must match confirmed snapshot')
                evidence.write_text(json.dumps(dict(synthetic_document(), review_decision={'state': 'pending'})))
                mismatch = self.cli('report.py', evidence, '--run-record', confirmed_path)
                self.assertNotEqual(mismatch.returncode, 0, 'top-level decisions must match confirmed snapshot')
                evidence.write_text(json.dumps(dict(synthetic_document(), findings=[], jev_policy={'enabled': False})))
                for field, invalid in [('response_ref', ''), ('pending_record_id', '0' * 64), ('user_response', '')]:
                    forged = copy.deepcopy(record)
                    forged['confirmation'][field] = invalid
                    confirmed_path.write_text(json.dumps(forged))
                    rejected = self.cli('report.py', evidence, '--run-record', confirmed_path)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertEqual(rejected.stdout, '')
                    self.assertNotIn('Traceback', rejected.stderr)
            self.assertEqual(pending_path.read_bytes(), original)

    def test_host_contract_requires_real_later_turn_and_unsigned_limits(self):
        root = SCRIPTS.parents[2]
        skill = (root / 'skills/bauer/SKILL.md').read_text()
        for required in ('STOP', 'later user response', 'confirm --run-record', 'agent_proposal',
                         'Do not audit in the same response', 'user_response_authenticated', 'decline'):
            self.assertIn(required, skill)
        contract = (root / 'skills/bauer/references/report.md').read_text()
        for required in ('bauer-run-record-v2', 'pending_confirmation', '--response-ref',
                         'unsigned', 'not a signature', 'unpublished v1', 'pending_record_id'):
            self.assertIn(required, contract)

    def test_pending_cannot_create_report_or_selection_even_empty(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            record, evidence = Path(directory) / 'pending.json', Path(directory) / 'evidence.json'
            first = self.cli('control.py', 'preflight', '--output', record)
            self.assertEqual(first.returncode, 0, first.stderr)
            evidence.write_text(json.dumps(dict(synthetic_document(), findings=[])))
            for script in ('report.py', 'selection.py'):
                run = self.cli(script, evidence, '--run-record', record)
                self.assertNotEqual(run.returncode, 0, 'pending confirmation must stop target workflow')
                self.assertEqual(run.stdout, '')
                self.assertNotIn('Traceback', run.stderr)
            pending = json.loads(first.stdout)['run_record']
            self.assertEqual(pending['status'], 'pending_confirmation')
            self.assertIn('Confirm', json.loads(first.stdout)['preflight_message'])

    def test_confirmation_controls_are_credential_free_and_exclusive(self):
        import contextlib
        import importlib.util
        import io
        from unittest import mock
        spec = importlib.util.spec_from_file_location('confirmation_control', SCRIPTS / 'control.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(SCRIPTS)] + sys.path):
            spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            pending, out = Path(directory) / 'pending.json', Path(directory) / 'confirmed.json'
            self.assertEqual(self.cli('control.py', 'preflight', '--output', pending).returncode, 0)
            def environment(name, default=None):
                if name not in ('LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG', 'COLUMNS', 'LINES'):
                    raise AssertionError('credential lookup forbidden')
                return default
            args = ['confirm', '--run-record', str(pending), '--decision', 'confirm',
                    '--user-response', '  Synthetic exact response.  ', '--response-ref', 'fixture:literal', '--output', str(out)]
            with mock.patch('os.environ.get', side_effect=environment), \
                    mock.patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                    mock.patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')), \
                    mock.patch('subprocess.run', side_effect=AssertionError('execution forbidden')):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(module.main(args), 0)
                self.assertEqual(json.loads(out.read_text())['confirmation']['user_response'], '  Synthetic exact response.  ')
                before = out.read_bytes()
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    self.assertEqual(module.main(args), 1)
                self.assertEqual(out.read_bytes(), before)
            for root in ([], 'private', None, True, 1):
                pending.write_text(json.dumps(root))
                bad = self.cli('control.py', *args[:-2])
                self.assertEqual(bad.returncode, 1)
                self.assertEqual(bad.stdout, '')
                self.assertEqual(bad.stderr, 'bauer control: invalid input\n')

    def test_regenerated_tampering_cannot_reuse_confirmation_for_new_scope(self):
        import importlib.util
        from test_report import confirm_fixture
        spec = importlib.util.spec_from_file_location('confirmation_record', SCRIPTS / 'run_record.py')
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        pending = json.loads(self.cli('control.py', 'preflight').stdout)['run_record']
        fake = dict(pending, status='confirmed')
        fake['record_id'] = module.digest(fake)
        with self.assertRaises(ValueError):
            module.validate(fake, require_confirmed=True)
        confirmed = confirm_fixture(pending)
        altered = copy.deepcopy(confirmed)
        altered['audit_profile'] = module.normalize_profile({'mode': 'full'})
        altered['excluded_sources'] = []
        altered['profile_decision'] = dict(kind='agent_proposal', user_instruction='Full', decision_ref='fixture:proposal', reason='test')
        altered['record_id'] = module.digest(altered)
        with self.assertRaises(ValueError):
            module.validate(altered, require_confirmed=True)
        with self.assertRaises(ValueError):
            module.confirm(confirmed, 'confirm', 'Synthetic', 'fixture:repeat')

    def test_new_scope_is_pending_linked_and_old_confirmed_profile_cannot_bind(self):
        from test_report import confirm_fixture
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            old, change, new, evidence = [Path(directory) / n for n in ('old.json', 'change.json', 'new.json', 'evidence.json')]
            confirmed = confirm_fixture(json.loads(self.cli('control.py', 'preflight').stdout)['run_record'])
            old.write_text(json.dumps(confirmed))
            change.write_text(json.dumps(dict(user_instruction='Synthetic: use Full.', decision_ref='fixture:correction', reason='test')))
            run = self.cli('control.py', 'preflight', '--mode', 'full', '--previous-run-record', old,
                           '--scope-change-decision', change, '--output', new)
            self.assertEqual(run.returncode, 0, run.stderr)
            pending = json.loads(run.stdout)['run_record']
            self.assertEqual(pending['status'], 'pending_confirmation')
            self.assertEqual(pending['scope_change']['previous_record_id'], confirmed['record_id'])
            evidence.write_text(json.dumps(dict(synthetic_document(), audit_profile={'mode': 'full'})))
            self.assertNotEqual(self.cli('report.py', evidence, '--run-record', old).returncode, 0)
            self.assertNotEqual(self.cli('report.py', evidence, '--run-record', new).returncode, 0)
            corrected = confirm_fixture(pending)
            new.write_text(json.dumps(corrected))
            self.assertEqual(self.cli('report.py', evidence, '--run-record', new).returncode, 0)


if __name__ == '__main__':
    unittest.main()

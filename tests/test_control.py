"""Actual offline CLI controls, no scanner or persistent settings."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_report import synthetic_document

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'skills/bauer/scripts/control.py'


class ControlTests(unittest.TestCase):
    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True)

    def test_preflight_actual_presence_and_required_chat_message(self):
        for present in (False, True):
            env = {k: v for k, v in os.environ.items()
                   if k in ('PATH', 'HOME', 'SYSTEMROOT', 'TMPDIR')}
            if present:
                env['TYPESAFE_API_KEY'] = 'synthetic-presence-not-a-real-key'
            run = subprocess.run([sys.executable, str(SCRIPT), 'preflight'],
                                 env=env, capture_output=True)
            self.assertEqual(run.returncode, 0, run.stderr)
            result = json.loads(run.stdout)
            self.assertIs(result['key_present'], present)
            self.assertEqual(result['key_availability'], 'key_present' if present else 'missing_key')
            self.assertIs(result['explicit_user_disable'], False)
            self.assertIs(result['required_chat_message'], True)
            self.assertEqual(result['operation'], 'new_audit_preflight')
            self.assertEqual(result['audit_profile']['mode'], 'lean')
            message = result['preflight_message']
            for term in ('Security audits can be token-intensive', 'Lean', 'Full', 'Custom',
                         'bounded scope', 'not a user decline'):
                self.assertIn(term, message)
            self.assertNotIn('synthetic-presence-not-a-real-key', (run.stdout + run.stderr).decode())
            self.assertNotIn('fully run', result['authority'])

    def test_preflight_disable_decision_captures_source_and_always_checks_presence(self):
        import contextlib
        import importlib.util
        import io
        from unittest import mock
        spec = importlib.util.spec_from_file_location('bauer_preflight_test', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(SCRIPT.parent)] + sys.path):
            spec.loader.exec_module(module)
        lookups = []
        def presence(name, default=None):
            if name == 'TYPESAFE_API_KEY':
                lookups.append(name)
                return 'synthetic-presence-only'
            return default
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory, \
                mock.patch('os.environ.get', side_effect=presence), \
                mock.patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')), \
                mock.patch('socket.socket', side_effect=AssertionError('network forbidden')):
            output = io.StringIO()
            decision = Path(directory) / 'decision.json'
            decision.write_text(json.dumps(dict(state='explicit_disable_captured', reason='User choice',
                                                user_instruction='Disable Jev.', decision_ref='user-message:test')))
            with contextlib.redirect_stdout(output):
                self.assertEqual(module.main(['preflight', '--review-decision', str(decision)]), 0)
            result = json.loads(output.getvalue())
            self.assertIs(result['explicit_user_disable'], True)
            self.assertIs(result['key_present'], True)
            self.assertEqual(lookups, ['TYPESAFE_API_KEY'])
            self.assertEqual(result['key_availability'], 'key_present')
            self.assertIn('explicit user-disable', result['preflight_message'])

    def test_preflight_shared_profiles_validation_before_presence_and_no_side_effects(self):
        import contextlib
        import importlib.util
        import io
        from unittest import mock
        spec = importlib.util.spec_from_file_location('bauer_preflight_profiles', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(SCRIPT.parent)] + sys.path):
            spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'profile.json'
            raw = json.dumps({'mode': 'custom', 'selected_sources': ['osv', 'cve', 'kev']})
            path.write_text(raw)
            valid = [[], ['--mode', 'full'], ['--mode', 'custom', '--selected-source', 'osv'],
                     ['--profile-file', str(path)]]
            invalid = [['--mode', 'custom'], ['--mode', 'custom', '--selected-source', 'kev'],
                       ['--selected-source', 'osv'], ['--profile-file', str(path), '--mode', 'custom']]
            for flags in valid + invalid:
                lookups = []
                def presence(name, default=None):
                    if name == 'TYPESAFE_API_KEY':
                        lookups.append(name)
                        self.assertIn(flags, valid, 'invalid profile accessed credentials')
                        return 'synthetic-presence-not-a-real-key'
                    return default
                out, err = io.StringIO(), io.StringIO()
                with mock.patch('os.environ.get', side_effect=presence), \
                        mock.patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')), \
                        mock.patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                        mock.patch('subprocess.run', side_effect=AssertionError('target execution forbidden')), \
                        contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = module.main(['preflight'] + flags)
                if flags in invalid:
                    self.assertEqual(code, 1)
                    self.assertEqual(out.getvalue(), '')
                    self.assertEqual(lookups, [])
                else:
                    self.assertEqual(code, 0, err.getvalue())
                    result = json.loads(out.getvalue())
                    self.assertIs(result['key_present'], True)
                    self.assertEqual(lookups, ['TYPESAFE_API_KEY'])
                    self.assertIn(result['audit_profile']['mode'].title(), result['preflight_message'])
                    self.assertIn(', '.join(result['audit_profile']['selected_sources']), result['preflight_message'])
                    self.assertNotIn('synthetic-presence-not-a-real-key', out.getvalue() + err.getvalue())
                    mode = json.loads(self.run_cli('mode', *flags).stdout)
                    self.assertEqual(result['audit_profile'], mode['audit_profile'])
            self.assertEqual(path.read_text(encoding='utf-8'), raw)
            self.assertEqual(list(Path(directory).iterdir()), [path])
        for flags in [('--offline',), ('--jev-disabled=false',), ('--mode', 'bogus')]:
            run = self.run_cli('preflight', *flags)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(run.stdout, b'')
        help_run = self.run_cli('preflight', '--help')
        self.assertEqual(help_run.returncode, 0)
        self.assertIn(b'--review-decision', help_run.stdout)
        self.assertNotIn(b'--jev-disabled', help_run.stdout)

    def test_preflight_empty_presence_and_new_run_identity_actual_cli(self):
        for value in ('', 'synthetic-preflight-only'):
            env = {k: v for k, v in os.environ.items()
                   if k in ('PATH', 'HOME', 'SYSTEMROOT', 'TMPDIR')}
            env['TYPESAFE_API_KEY'] = value
            for flags in ([],):
                command = [sys.executable, str(SCRIPT), 'preflight'] + flags
                first = subprocess.run(command, env=env, capture_output=True)
                repeat = subprocess.run(command, env=env, capture_output=True)
                self.assertEqual(first.returncode, 0, first.stderr)
                self.assertNotEqual(json.loads(first.stdout)['run_record']['run_id'], json.loads(repeat.stdout)['run_record']['run_id'])
                result = json.loads(first.stdout)
                self.assertIs(result['explicit_user_disable'], bool(flags))
                self.assertIs(result['key_present'], bool(value))
                self.assertNotIn('synthetic-preflight-only', (first.stdout + first.stderr).decode())

    def test_status_bundle_pairs_card_and_all_severity_rows_with_saved_handle(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'zero.json'
            path.write_text(json.dumps(dict(synthetic_document(), findings=[])))
            run = self.run_cli('status', str(path))
            self.assertEqual(run.returncode, 0, run.stderr)
            status = json.loads(run.stdout)
            self.assertEqual(status['report_handle'], str(path))
            self.assertEqual(status['security_scorecard']['severity_counts'], status['severity_counts'])
            self.assertEqual(status['severity_counts'], {s: 0 for s in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL')})
            for operation in ('status', 'scorecard'):
                output = self.run_cli(operation, str(path), '--format', 'markdown')
                self.assertEqual(output.returncode, 0, output.stderr)
                text = output.stdout.decode()
                self.assertLess(text.index('## Security Scorecard'), text.index('## Severity counts'))
                for severity in status['severity_counts']:
                    self.assertIn('| ' + severity + ' | 0 |', text)

    def test_mode_audit_plan_explicit_config_and_no_writes(self):
        self.assertTrue(SCRIPT.is_file(), 'offline control foundation missing')
        for mode in ('lean', 'full'):
            run = self.run_cli('mode', '--mode', mode)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)['audit_profile']['mode'], mode)
            plan = self.run_cli('audit', '--mode', mode)
            self.assertEqual(plan.returncode, 0, plan.stderr)
            self.assertEqual(json.loads(plan.stdout)['operation'], 'agent_audit_plan')
            self.assertIn('not a scanner', json.loads(plan.stdout)['authority'])
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'profile.json'
            raw = json.dumps({'mode': 'custom', 'version': 'bauer-audit-profile-v1', 'selected_sources': ['osv', 'cve', 'kev']})
            path.write_text(raw)
            run = self.run_cli('mode', '--profile-file', str(path))
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout)['audit_profile']['mode'], 'custom')
            self.assertEqual(path.read_text(encoding='utf-8'), raw)
            self.assertEqual(list(Path(directory).iterdir()), [path])
        for args in [('mode', '--mode', 'custom'), ('mode', '--mode', 'bogus'),
                     ('mode', '--selected-source', 'osv'), ('mode', '--mode', 'custom', '--selected-source', 'kev'),
                     ('mode', '--set', 'full'), ('audit', '--run')]:
            run = self.run_cli(*args)
            self.assertNotEqual(run.returncode, 0)
            self.assertEqual(run.stdout, b'')


    def test_saved_status_scorecard_revision_time_and_forged_metadata(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'report.json'
            doc = synthetic_document()
            path.write_text(json.dumps(doc))
            run = self.run_cli('status', str(path))
            self.assertEqual(run.returncode, 0, run.stderr)
            status = json.loads(run.stdout)
            self.assertEqual(status['revision_comparison'], 'unknown')
            self.assertEqual(status['audited_at'], None)
            self.assertIn('audited_at_not_supplied', status['gaps'])
            doc.update(revision='abc', audited_at='2026-10-01T12:00:00Z')
            path.write_text(json.dumps(doc))
            for current, expected in [('abc', 'matches_supplied_revision'), ('def', 'stale_revision')]:
                run = self.run_cli('status', str(path), '--current-revision', current)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(json.loads(run.stdout)['revision_comparison'], expected)
                self.assertIn('not freshness verification', json.loads(run.stdout)['authority'])
            for format in ('json', 'markdown'):
                run = self.run_cli('scorecard', str(path), '--format', format)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertEqual(run.stdout, self.run_cli('scorecard', str(path), '--format', format).stdout)
                self.assertIn(b'security' if format == 'json' else b'Security Scorecard', run.stdout)
            markdown = self.run_cli('status', str(path), '--format', 'markdown')
            self.assertEqual(markdown.returncode, 0, markdown.stderr)
            for patch in [dict(revision=''), dict(audited_at='unknown'), dict(audited_at='2026-10-01'),
                          dict(security_scorecard={'completion': 'complete'})]:
                path.write_text(json.dumps(dict(doc, **patch)))
                run = self.run_cli('scorecard', str(path))
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, b'')
            for args in [('status',), ('scorecard', str(path), '--format', 'html'),
                         ('status', str(path), '--current-revision', ''), ('mode', '--mo', 'full')]:
                self.assertNotEqual(self.run_cli(*args).returncode, 0)


    def test_controls_cannot_read_keys_or_make_requests(self):
        import contextlib
        import importlib.util
        import io
        from unittest import mock
        spec = importlib.util.spec_from_file_location('bauer_control_test', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        with mock.patch.object(sys, 'path', [str(SCRIPT.parent)] + sys.path):
            spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(synthetic_document()))
            class LocaleOnlyEnvironment:
                def get(self, name, default=None):
                    if name not in ('LANGUAGE', 'LC_ALL', 'LC_MESSAGES', 'LANG', 'COLUMNS', 'LINES'):
                        raise AssertionError('environment lookup forbidden: ' + name)
                    return default
                def __getitem__(self, name):
                    if name in ('COLUMNS', 'LINES'):
                        raise KeyError(name)  # argparse's terminal-width formatting only
                    raise AssertionError('environment indexing forbidden')
                def __iter__(self):
                    raise AssertionError('environment enumeration forbidden')
            with mock.patch('os.environ', LocaleOnlyEnvironment()), \
                    mock.patch('urllib.request.urlopen', side_effect=AssertionError('network forbidden')), \
                    mock.patch('socket.socket', side_effect=AssertionError('network forbidden')), \
                    mock.patch('subprocess.run', side_effect=AssertionError('target execution forbidden')):
                for args in [['mode'], ['audit', '--mode', 'full'], ['status', str(path)], ['scorecard', str(path)]]:
                    output = io.StringIO()
                    with contextlib.redirect_stdout(output):
                        self.assertEqual(module.main(args), 0)
                    self.assertTrue(output.getvalue())


if __name__ == '__main__':
    unittest.main()

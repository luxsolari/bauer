"""Run records enforce supplied consistency, not permission or chat truth."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from test_report import synthetic_document, load_report, confirm_fixture

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bauer/scripts'


class RunRecordTests(unittest.TestCase):
    def cli(self, script, *args, present=False):
        env = {k: v for k, v in os.environ.items() if k in ('PATH', 'HOME', 'SYSTEMROOT', 'TMPDIR')}
        if present:
            env['TYPESAFE_API_KEY'] = 'synthetic-presence-only'
        return subprocess.run([sys.executable, str(SCRIPTS / script), *map(str, args)],
                              capture_output=True, text=True, env=env)

    def test_record_backed_supplemental_disable_cannot_invent_a_user_decision(self):
        run = self.cli('control.py', 'preflight')
        record = confirm_fixture(json.loads(run.stdout)['run_record'])
        doc = dict(synthetic_document(), run_record=record)
        doc['findings'][0]['jev'] = {'status': 'explicitly_disabled', 'reason': 'offline'}
        with self.assertRaises(ValueError):
            load_report().normalize(doc)
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            decision = Path(directory) / 'decision.json'
            decision.write_text(json.dumps(dict(state='explicit_disable_captured', reason='User choice',
                                                user_instruction='Do not use Jev.', decision_ref='fixture:disable')))
            run = self.cli('control.py', 'preflight', '--review-decision', decision)
            record = confirm_fixture(json.loads(run.stdout)['run_record'])
            doc['run_record'] = record
        with self.assertRaises(ValueError):
            load_report().normalize(doc)
        doc['findings'][0]['jev']['decision_ref'] = record['review_decision']['decision_ref']
        result = load_report().normalize(doc)
        self.assertEqual(result['findings'][0]['jev']['status'], 'explicitly_disabled')

    def test_entry_and_report_docs_require_same_run_without_authority_claims(self):
        for relative in ('README.md', 'skills/bauer/SKILL.md', 'skills/bauer/references/report.md'):
            text = (ROOT / relative).read_text(encoding='utf-8')
            for term in ('run_record', '--run-record', '--output', 'user_instruction', 'decision_ref'):
                with self.subTest(relative=relative, term=term):
                    self.assertIn(term, text)
        contract = (ROOT / 'skills/bauer/references/report.md').read_text(encoding='utf-8')
        for term in ('--saved-report', 'bauer-run-record-v2', 'pending_host_delivery',
                     'explicit_disable_captured', 'fabricate', 'not_requested', 'scope-change-decision'):
            self.assertIn(term, contract)

    def test_selection_queue_links_same_record_and_does_not_rewrite_scope(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            record_path = Path(directory) / 'run.json'
            evidence = Path(directory) / 'evidence.json'
            run = self.cli('control.py', 'preflight', '--mode', 'custom', '--selected-source', 'cwe', '--output', record_path)
            record = json.loads(run.stdout)['run_record']
            record = confirm_fixture(record)
            record_path = Path(directory) / 'confirmed.json'
            record_path.write_text(json.dumps(record))
            original = record_path.read_bytes()
            evidence.write_text(json.dumps(synthetic_document()))
            queue = self.cli('selection.py', evidence, '--run-record', record_path, '--enabled', '--min-severity', 'LOW')
            self.assertEqual(queue.returncode, 0, queue.stderr)
            selected = json.loads(queue.stdout)
            self.assertEqual(selected['run_id'], record['run_id'])
            self.assertEqual(selected['queue'][0]['state'], 'pending_packet_approval')
            doc = dict(synthetic_document(), jev_policy=selected['policy'], jev_selection=selected)
            evidence.write_text(json.dumps(doc))
            report = self.cli('report.py', evidence, '--run-record', record_path)
            self.assertEqual(report.returncode, 0, report.stderr)
            normalized = json.loads(report.stdout)
            self.assertEqual(normalized['jev_selection'], selected)
            self.assertEqual(normalized['audit_profile'], record['audit_profile'])
            evidence.write_text(report.stdout)
            override = self.cli('selection.py', evidence, '--enabled', '--min-severity', 'HIGH')
            self.assertEqual(override.returncode, 0, override.stderr)
            self.assertEqual(json.loads(override.stdout)['run_id'], record['run_id'])
            self.assertEqual(record_path.read_bytes(), original)
            evidence.write_text(json.dumps(dict(synthetic_document(), audit_profile={'mode': 'full'})))
            self.assertNotEqual(self.cli('selection.py', evidence, '--run-record', record_path).returncode, 0)

    def test_scorecard_binds_run_and_rejects_contradictory_preflight_metadata(self):
        run = self.cli('control.py', 'preflight')
        record = json.loads(run.stdout)['run_record']
        module = load_report()
        record = confirm_fixture(record)
        doc = dict(synthetic_document(), run_record=record)
        result = module.normalize(doc)
        self.assertEqual(result['security_scorecard']['run_id'], record['run_id'])
        self.assertEqual(result['security_scorecard']['review_decision'], record['review_decision'])
        self.assertIs(result['security_scorecard']['key_present'], False)
        for metadata in (dict(run_id='wrong'), dict(key_present=0), dict(explicit_user_disable=True),
                         dict(key_availability='explicitly_disabled'), dict(audit_profile=None)):
            with self.subTest(metadata=metadata), self.assertRaises(ValueError):
                module.normalize(dict(doc, **metadata))
        forged = copy.deepcopy(result)
        forged['security_scorecard']['run_id'] = 'wrong'
        with self.assertRaises(ValueError):
            module.normalize(forged)

    def test_schema_tampering_and_profile_switches_reject_with_static_cli_errors(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'record.json'
            evidence = Path(directory) / 'evidence.json'
            run = self.cli('control.py', 'preflight', '--output', path)
            record = confirm_fixture(json.loads(run.stdout)['run_record'])
            path = Path(directory) / 'confirmed.json'
            path.write_text(json.dumps(record))
            original = path.read_bytes()
            patches = [dict(schema_version='unknown'), dict(run_id=1), dict(created_at=None),
                       dict(origin='verified user authority'), dict(authority='authenticated'),
                       dict(chat_delivery='verified'), dict(always_required=[]), dict(scope_change={}),
                       dict(review_decision={'state': 'explicit_disable_captured'}),
                       dict(host_environment={'key_present': None, 'key_availability': 'explicitly_disabled'}),
                       dict(audit_profile={'mode': 'full'}), dict(unrecognized=True)]
            for patch in patches:
                evidence.write_text(json.dumps(dict(synthetic_document(), run_record=dict(record, **patch))))
                for flags in ([], ['--run-record', path]):
                    rejected = self.cli('report.py', evidence, *flags)
                    self.assertNotEqual(rejected.returncode, 0)
                    self.assertEqual(rejected.stdout, '')
                    self.assertEqual(rejected.stderr, 'bauer report: invalid input\n')
            for profile in ({'mode': 'full'}, {'mode': 'custom', 'selected_sources': ['cwe']},
                            {'mode': 'lean', 'selected_sources': ['osv', 'osv']}):
                evidence.write_text(json.dumps(dict(synthetic_document(), audit_profile=profile)))
                self.assertNotEqual(self.cli('report.py', evidence, '--run-record', path).returncode, 0)
            evidence.write_text(json.dumps(dict(synthetic_document(), run_record=record, completion_gate=None)))
            self.assertEqual(self.cli('report.py', evidence).stderr, 'bauer report: invalid input\n')
            path.write_text(original.decode()[:-2] + ', "run_id": "duplicate"}\n')
            evidence.write_text(json.dumps(synthetic_document()))
            self.assertNotEqual(self.cli('report.py', evidence, '--run-record', path).returncode, 0)

    def test_public_normalizer_validates_record_without_script_path_setup(self):
        run = self.cli('control.py', 'preflight')
        self.assertEqual(run.returncode, 0, run.stderr)
        record = json.loads(run.stdout)['run_record']
        record = confirm_fixture(record)
        result = load_report().normalize(dict(synthetic_document(), run_record=record))
        self.assertEqual(result['audit_profile'], record['audit_profile'])

    def test_record_cannot_override_explicit_disable_or_boolean_embedded_truth(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'record.json'
            evidence = Path(directory) / 'evidence.json'
            decision_path = Path(directory) / 'decision.json'
            decision_path.write_text(json.dumps(dict(state='explicit_disable_captured', reason='User choice',
                                                    user_instruction='Do not use Jev.', decision_ref='user-message:disable')))
            run = self.cli('control.py', 'preflight', '--output', path, '--review-decision', decision_path)
            self.assertEqual(run.returncode, 0, run.stderr)
            record = confirm_fixture(json.loads(run.stdout)['run_record'])
            path = Path(directory) / 'confirmed.json'
            path.write_text(json.dumps(record))
            evidence.write_text(json.dumps(dict(synthetic_document(), run_record=record, jev_policy={'enabled': True})))
            rejected = self.cli('report.py', evidence, '--run-record', path)
            self.assertNotEqual(rejected.returncode, 0, 'captured disable cannot be silently overridden by scheduling')
            evidence.write_text(json.dumps(dict(synthetic_document(), run_record=record)))
            self.assertNotEqual(self.cli('selection.py', evidence, '--enabled').returncode, 0)
            altered = copy.deepcopy(record)
            altered['host_environment']['key_present'] = 0
            evidence.write_text(json.dumps(dict(synthetic_document(), run_record=altered)))
            self.assertNotEqual(self.cli('report.py', evidence, '--run-record', path).returncode, 0,
                                'numeric aliases in embedded record must not be repaired from original')

    def test_scope_change_uses_new_preflight_and_preserves_previous_record(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            previous = Path(directory) / 'previous.json'
            current = Path(directory) / 'current.json'
            change = Path(directory) / 'change.json'
            first = self.cli('control.py', 'preflight', '--output', previous)
            self.assertEqual(first.returncode, 0, first.stderr)
            original = previous.read_bytes()
            change.write_text(json.dumps(dict(reason='User expanded scope', decision_ref='user-message:expand',
                                              user_instruction='Use Full instead of Lean.')))
            run = self.cli('control.py', 'preflight', '--mode', 'full', '--previous-run-record', previous,
                           '--scope-change-decision', change, '--output', current)
            self.assertEqual(run.returncode, 0, run.stderr)
            old = json.loads(original)
            new = json.loads(run.stdout)['run_record']
            self.assertNotEqual(new['run_id'], old['run_id'])
            self.assertEqual(new['scope_change']['previous_run_id'], old['run_id'])
            self.assertEqual(new['scope_change']['previous_audit_profile'], old['audit_profile'])
            self.assertEqual(previous.read_bytes(), original)
            for flags in (['--previous-run-record', previous], ['--scope-change-decision', change],
                          ['--output', previous]):
                rejected = self.cli('control.py', 'preflight', '--mode', 'full', *flags)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, '')
                self.assertEqual(previous.read_bytes(), original)

    def test_saved_report_is_explicit_validated_history_not_raw_bypass(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'saved.json'
            legacy = json.loads((ROOT / 'tests/fixtures/v021-asvs-gap.json').read_text(encoding='utf-8'))
            path.write_text(json.dumps(legacy))
            run = self.cli('report.py', path, '--saved-report')
            self.assertEqual(run.returncode, 0, run.stderr)
            result = json.loads(run.stdout)
            self.assertEqual(result['report_origin'], 'historical_saved_report')
            self.assertEqual(result['completion_gate']['status'], 'partial')
            self.assertEqual(result['audit_profile']['mode'], 'full')
            path.write_text(run.stdout)
            self.assertEqual(self.cli('report.py', path, '--saved-report').stdout, run.stdout)
            self.assertNotEqual(self.cli('report.py', path).returncode, 0)
            self.assertIn('Historical saved report', self.cli('report.py', path, '--saved-report', '--format', 'markdown').stdout)
            for bad in (synthetic_document(), dict(result, completion_gate={'status': 'complete'})):
                path.write_text(json.dumps(bad))
                rejected = self.cli('report.py', path, '--saved-report')
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, '')

    def test_empty_custom_rejected_before_presence_and_reports(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = Path(directory) / 'profile.json'
            path.write_text(json.dumps(dict(mode='custom', selected_sources=[])))
            for operation in ('preflight', 'mode', 'audit'):
                run = self.cli('control.py', operation, '--profile-file', path)
                self.assertNotEqual(run.returncode, 0, 'empty custom cannot silently complete an audit')
                self.assertEqual(run.stdout, '')
            with self.assertRaises(ValueError):
                load_report().normalize(dict(synthetic_document(), audit_profile=dict(mode='custom', selected_sources=[])))

    def test_disable_needs_instruction_reference_and_still_checks_boolean(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            decision_path = Path(directory) / 'decision.json'
            shortcut = self.cli('control.py', 'preflight', '--jev-disabled')
            self.assertNotEqual(shortcut.returncode, 0, 'unsubstantiated disable shortcut must be removed')
            decision = dict(state='explicit_disable_captured', user_instruction='Do not use Jev for this audit.',
                            decision_ref='user-message:test-only', reason='User requested no secondary review')
            decision_path.write_text(json.dumps(decision))
            for present in (False, True):
                run = self.cli('control.py', 'preflight', '--review-decision', decision_path, present=present)
                self.assertEqual(run.returncode, 0, run.stderr)
                result = json.loads(run.stdout)
                self.assertIs(result['key_present'], present)
                self.assertEqual(result['key_availability'], 'key_present' if present else 'missing_key')
                self.assertEqual(result['run_record']['review_decision'], decision)
                self.assertIs(result['explicit_user_disable'], True)
                self.assertIn('not verified permission', result['run_record']['authority'])
                self.assertNotIn('presence was not checked', result['preflight_message'])
            for key in ('user_instruction', 'decision_ref', 'reason'):
                bad = dict(decision)
                bad.pop(key)
                decision_path.write_text(json.dumps(bad))
                run = self.cli('control.py', 'preflight', '--review-decision', decision_path)
                self.assertNotEqual(run.returncode, 0)
                self.assertEqual(run.stdout, '')

    def test_new_report_requires_preflight_record_and_embedded_roundtrip(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            evidence = Path(directory) / 'evidence.json'
            record_path = Path(directory) / 'run.json'
            evidence.write_text(json.dumps(synthetic_document()))
            naked = self.cli('report.py', evidence)
            self.assertNotEqual(naked.returncode, 0, 'raw evidence cannot create a new audit without preflight')
            self.assertEqual(naked.stdout, '')
            preflight = self.cli('control.py', 'preflight', '--output', record_path, present=True)
            self.assertEqual(preflight.returncode, 0, preflight.stderr)
            record = json.loads(preflight.stdout)['run_record']
            self.assertEqual(json.loads(record_path.read_text(encoding='utf-8')), record)
            self.assertIs(record['host_environment']['key_present'], True)
            record = confirm_fixture(record)
            record_path = Path(directory) / 'confirmed.json'
            record_path.write_text(json.dumps(record))
            run = self.cli('report.py', evidence, '--run-record', record_path)
            self.assertEqual(run.returncode, 0, run.stderr)
            result = json.loads(run.stdout)
            self.assertEqual(result['run_record'], record)
            self.assertEqual(result['audit_profile'], record['audit_profile'])
            evidence.write_text(run.stdout)
            repeat = self.cli('report.py', evidence)
            self.assertEqual(repeat.stdout, run.stdout)
            markdown = self.cli('report.py', evidence, '--format', 'markdown')
            self.assertEqual(markdown.returncode, 0, markdown.stderr)
            self.assertIn(record['run_id'], markdown.stdout)
            self.assertIn('Run record', markdown.stdout)

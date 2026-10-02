"""Genuine committed v0.2.1 saved reports retain historical Full scope."""
import copy
import json
from pathlib import Path
import subprocess
import sys
import unittest
from test_report import load_report

ROOT = Path(__file__).resolve().parents[1]


class LegacyTests(unittest.TestCase):
    def fixture(self, name):
        return json.loads((ROOT / 'tests/fixtures' / ('v021-' + name + '.json')).read_text())

    def test_saved_v021_complete_and_asvs_gap_migrate_full_after_validation(self):
        module = load_report()
        for name, status in [('complete', 'complete'), ('asvs-gap', 'partial')]:
            with self.subTest(name=name):
                original = self.fixture(name)
                result = module.normalize(original)
                self.assertEqual(result['audit_profile']['mode'], 'full')
                self.assertEqual(result['completion_gate']['status'], status)
                self.assertEqual(result['completion_migration']['legacy_gate'], original['completion_gate'])
                self.assertEqual(result['security_scorecard']['completion'], status)
                self.assertEqual(module.normalize(result), result)
                self.assertIn('## Completion policy migration', module.render_markdown(result))
                forged_migration = copy.deepcopy(result)
                forged_migration['completion_migration']['legacy_gate']['status'] = 'forged'
                with self.assertRaises(ValueError):
                    module.normalize(forged_migration)
                if status == 'partial':
                    self.assertIn('asvs', [r['id'] for r in result['security_scorecard']['blockers']])
                for script, args in [('report.py', ['--saved-report']), ('report.py', ['--saved-report', '--format', 'markdown']),
                                     ('control.py', ['status']), ('control.py', ['scorecard'])]:
                    path = ROOT / 'tests/fixtures' / ('v021-' + name + '.json')
                    flags = args[:1] + [str(path)] if script == 'control.py' else [str(path)] + args
                    run = subprocess.run([sys.executable, str(ROOT / 'skills/bauer/scripts' / script), *flags], capture_output=True)
                    self.assertEqual(run.returncode, 0, run.stderr)
                    self.assertIn(status.encode(), run.stdout)

    def test_migration_metadata_cannot_bypass_profile_validation(self):
        module = load_report()
        migrated = module.normalize(self.fixture('complete'))
        for profile in (None, [], 'full', {'mode': 'lean'}):
            forged = dict(migrated, audit_profile=profile)
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                module.normalize(forged)

    def test_forged_legacy_gate_rejects_before_migration(self):
        module = load_report()
        original = self.fixture('asvs-gap')
        for field, value in [('status', 'complete'), ('policy_version', 'bauer-completion-v999')]:
            forged = copy.deepcopy(original)
            forged['completion_gate'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.normalize(forged)
        forged = copy.deepcopy(original)
        forged['audit_profile'] = {'mode': 'lean'}
        with self.assertRaises(ValueError):
            module.normalize(forged)

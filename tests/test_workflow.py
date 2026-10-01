"""Synthetic workflow exercise; not a benchmark of agent discovery."""
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def test_reproduced_sql_injection_flows_through_report_cli(self):
        with sqlite3.connect(':memory:') as db:
            db.execute('CREATE TABLE accounts (id INTEGER, owner TEXT)')
            db.executemany('INSERT INTO accounts VALUES (?, ?)', [(1, 'alice'), (2, 'bob')])
            attack = '1 OR 1=1'
            vulnerable_rows = db.execute('SELECT id FROM accounts WHERE id = ' + attack).fetchall()
            fixed_rows = db.execute('SELECT id FROM accounts WHERE id = ?', (attack,)).fetchall()
        self.assertEqual(vulnerable_rows, [(1,), (2,)])
        self.assertEqual(fixed_rows, [])
        finding = dict(rule='sql-string-interpolation', path='synthetic.py', line=1,
                       severity='HIGH', title='Synthetic SQL injection', status='reproduced',
                       categories=['A05:2025'], evidence='Attacker predicate returns both synthetic accounts',
                       remediation='Bind the identifier as a query parameter',
                       verification='In-memory SQLite: injected predicate returned two rows; bound value returned zero',
                       preconditions='Synthetic fixture deliberately supplies attacker input to a SQL predicate')
        document = dict(scope='synthetic fixture, not a repository audit', sources=[], coverage=[],
                        limitations=['No agent discovery or OWASP full coverage exercised'], findings=[finding])
        with tempfile.TemporaryDirectory() as directory:
            packet = Path(directory) / 'evidence.json'
            packet.write_text(json.dumps(document), encoding='utf-8')
            outputs = []
            for _ in range(2):
                run = subprocess.run([sys.executable, str(ROOT / 'skills/bauer/scripts/report.py'), str(packet)],
                                     capture_output=True, text=True, timeout=10, check=True)
                self.assertEqual(run.stderr, '')
                outputs.append(run.stdout)
        self.assertEqual(outputs[0], outputs[1])
        report = json.loads(outputs[0])
        self.assertEqual(report['counts']['HIGH'], 1)
        self.assertEqual(report['findings'][0]['status'], 'reproduced')

    def test_manifests_and_runtime_support_files_match(self):
        for host in ('claude', 'codex'):
            manifest = json.loads((ROOT / ('.' + host + '-plugin/plugin.json')).read_text())
            self.assertEqual(manifest['name'], 'bauer')
            self.assertEqual(manifest['version'], '0.1.0')
        skill = (ROOT / 'skills/bauer/SKILL.md').read_text()
        self.assertTrue(skill.startswith('---\n'))
        description = next(line for line in skill.splitlines() if line.startswith('description: '))[13:]
        self.assertLessEqual(len(description), 60)
        for path in ('scripts/report.py', 'scripts/sources.py', 'scripts/jev.py',
                     'references/report.md', 'references/jev.md'):
            self.assertTrue((ROOT / 'skills/bauer' / path).is_file(), path)
        self.assertIn('scripts/jev.py', (ROOT / 'skills/bauer/references/jev.md').read_text())


if __name__ == '__main__':
    unittest.main()

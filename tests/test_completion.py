"""Offline completion-gate contract; records are supplied, not collected."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / 'skills/bauer/scripts'


def gate(document):
    path = SCRIPTS / 'completion.py'
    if not path.exists():
        raise AssertionError('completion gate is not implemented')
    spec = importlib.util.spec_from_file_location('bauer_completion', path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.evaluate(document)


class CompletionTests(unittest.TestCase):
    def test_completion_workflow_is_mandatory_and_scoped(self):
        for relative in ('skills/bauer/SKILL.md', 'skills/bauer/references/report.md', 'README.md'):
            text = (ROOT / relative).read_text()
            for required in ('completion_checks', 'completion_scope', 'unattempted',
                             'unknown', 'not_applicable', 'permission', 'partial'):
                with self.subTest(file=relative, term=required):
                    self.assertIn(required, text)
        self.assertIn('100 packages per invocation', (ROOT / 'skills/bauer/references/advisories.md').read_text())

    def test_report_json_and_markdown_gate_no_collection(self):
        spec = importlib.util.spec_from_file_location('bauer_report_completion', SCRIPTS / 'report.py')
        assert spec is not None and spec.loader is not None
        report = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report)
        document = dict(scope='offline fixture', sources=[], coverage=[], limitations=[], findings=[])
        normalized = report.normalize(document)
        self.assertEqual('partial', normalized['completion_gate']['status'])
        markdown = report.render_markdown(normalized)
        self.assertIn('## Completion and applicability', markdown)
        self.assertIn('| Obligation | Applicability | Outcome | Satisfied | Reason | Evidence |', markdown)
        self.assertIn('unattempted', markdown)
        self.assertEqual(normalized, report.normalize(normalized))
        forged = dict(document, completion_gate={'status': 'complete'})
        with self.assertRaises(ValueError):
            report.normalize(forged)
        document.update(self.complete_fixture())
        document['completion_checks'][0].update(status='blocked', reason='Permission required')
        normalized = report.normalize(document)
        self.assertEqual('partial', normalized['completion_gate']['status'])
        self.assertIn('Permission required', report.render_markdown(normalized))
        # No adapter, environment or network modules are reachable from the gate.
        import ast
        tree = ast.parse((SCRIPTS / 'completion.py').read_text())
        modules = {node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)}
        modules |= {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertFalse(modules & {'os', 'socket', 'subprocess', 'urllib', 'requests', 'jev'})

    def complete_fixture(self):
        ids = [s['id'] for s in json.loads((SCRIPTS.parent / 'references/security-sources.json').read_text())['sources']]
        ids += ['dependency_coverage', 'remote_configuration']
        return {'completion_checks': [dict(id=i, status='reviewed', applicability='applicable',
                    reason='Fixture scoped control examined', evidence='fixture-evidence.json#' + i) for i in ids],
                'completion_scope': dict(inventory_ids=[], approved_ids=[], queried_ids=[], excluded=[], blocked=[],
                    inventory_evidence='fixture-inventory.json', query_evidence='fixture-queries.json',
                    remote_targets=[], remote_scope_evidence='fixture-scope.json#no-hosted-services',
                    published_cve_ids=[], cve_assessment_evidence='fixture-adjudication.json')}

    def test_dependency_identity_coverage_not_headcounts(self):
        doc = self.complete_fixture()
        self.assertEqual('complete', gate(doc)['status'])
        scope = doc['completion_scope']
        scope.update(inventory_ids=['pkg-' + str(i) for i in range(715)],
                     approved_ids=['pkg-' + str(i) for i in range(90)],
                     queried_ids=['pkg-' + str(i) for i in range(90)])
        result = gate(doc)
        self.assertEqual('partial', result['status'])
        self.assertEqual(625, len(result['dependency_coverage']['unresolved_ids']))
        self.assertEqual(90, result['dependency_coverage']['queried_count'])
        scope['queried_ids'].append('unapproved')
        with self.assertRaises(ValueError):
            gate(doc)
        scope['queried_ids'].pop()
        scope['inventory_ids'].append('pkg-0')
        with self.assertRaises(ValueError):
            gate(doc)
        scope['inventory_ids'].pop()
        scope['excluded'] = [dict(id='pkg-' + str(i), reason='Specific fixture out-of-scope identity',
                                  evidence='fixture-scope.json#pkg-' + str(i)) for i in range(90, 715)]
        self.assertEqual('complete', gate(doc)['status'])
        scope['excluded'][0]['reason'] = ''
        with self.assertRaises(ValueError):
            gate(doc)
        doc.pop('completion_scope')
        self.assertEqual('partial', gate(doc)['status'])

    def test_dependency_nonapplicability_cannot_hide_queried_work(self):
        doc = self.complete_fixture()
        doc['completion_scope'].update(inventory_ids=['pkg-1'], approved_ids=['pkg-1'], queried_ids=['pkg-1'])
        row = next(r for r in doc['completion_checks'] if r['id'] == 'dependency_coverage')
        row.update(status='not_applicable', applicability='not_applicable', reason='No remaining queries')
        result = gate(doc)
        self.assertEqual('partial', result['status'])
        actual = next(r for r in result['obligations'] if r['id'] == 'dependency_coverage')
        self.assertFalse(actual['satisfied'])
        self.assertIn('contradicts', actual['gate_reason'])
        self.assertEqual('not_applicable', actual['status'])
        self.assertEqual(1, result['dependency_coverage']['queried_count'])

    def test_dependency_nonapplicability_boundaries(self):
        def fixture():
            doc = self.complete_fixture()
            row = next(r for r in doc['completion_checks'] if r['id'] == 'dependency_coverage')
            row.update(status='not_applicable', applicability='not_applicable', reason='Evidenced empty applicable scope')
            return doc

        self.assertEqual('complete', gate(fixture())['status'])
        doc = fixture()
        scope = doc['completion_scope']
        scope.update(inventory_ids=['excluded-1'], excluded=[dict(id='excluded-1',
                     reason='Outside audited scope', evidence='scope.json#excluded-1')])
        self.assertEqual('complete', gate(doc)['status'])
        # Approval itself is applicable work, even if subsequently excluded.
        scope['approved_ids'] = ['excluded-1']
        result = gate(doc)
        self.assertEqual('partial', result['status'])
        self.assertIn('contradicts', next(r for r in result['obligations']
                                        if r['id'] == 'dependency_coverage')['gate_reason'])
        doc = fixture()
        doc['completion_scope']['inventory_ids'] = ['unapproved-1']
        result = gate(doc)
        self.assertEqual('partial', result['status'])
        self.assertIn('contradicts', next(r for r in result['obligations']
                                        if r['id'] == 'dependency_coverage')['gate_reason'])
        doc['completion_scope']['queried_ids'] = ['unapproved-1']
        with self.assertRaises(ValueError):
            gate(doc)
        for status in ('checked', 'reviewed'):
            doc = self.complete_fixture()
            doc['completion_scope'].update(inventory_ids=['pkg-1', 'excluded-1'],
                approved_ids=['pkg-1'], queried_ids=['pkg-1'], excluded=[dict(id='excluded-1',
                    reason='Outside audited scope', evidence='scope.json#excluded-1')])
            next(r for r in doc['completion_checks'] if r['id'] == 'dependency_coverage')['status'] = status
            with self.subTest(status=status):
                self.assertEqual('complete', gate(doc)['status'])

    def test_osv_nonapplicability_with_queries_needs_source_specific_scope(self):
        doc = self.complete_fixture()
        doc['completion_scope'].update(inventory_ids=['pkg-1'], approved_ids=['pkg-1'], queried_ids=['pkg-1'])
        row = next(r for r in doc['completion_checks'] if r['id'] == 'osv')
        row.update(status='not_applicable', applicability='not_applicable', reason='No remaining queries')
        result = gate(doc)
        self.assertEqual('partial', result['status'])
        actual = next(r for r in result['obligations'] if r['id'] == 'osv')
        self.assertFalse(actual['satisfied'])
        self.assertIn('source-specific', actual['gate_reason'])
        # The generic query ledger cannot prove which source was queried.
        # Empty or entirely excluded scope does not imply an OSV query ran.
        doc['completion_scope'].update(inventory_ids=[], approved_ids=[], queried_ids=[])
        self.assertEqual('complete', gate(doc)['status'])
        doc['completion_scope'].update(inventory_ids=['excluded-1'], excluded=[dict(id='excluded-1',
            reason='Outside audited scope', evidence='scope.json#excluded-1')])
        self.assertEqual('complete', gate(doc)['status'])

    def test_remote_scope_and_published_cve_nonapplicability(self):
        doc = self.complete_fixture()
        for row in doc['completion_checks']:
            if row['id'] in ('cve', 'nvd', 'kev', 'epss'):
                row.update(status='not_applicable', applicability='not_applicable',
                           reason='Adjudicated inventory has no applicable published CVEs')
        self.assertEqual('complete', gate(doc)['status'])
        doc['completion_scope'].update(inventory_ids=['pkg-unqueried'])
        result = gate(doc)
        self.assertEqual('partial', result['status'])
        self.assertTrue(all(not r['satisfied'] for r in result['obligations'] if r['id'] in ('cve','nvd','kev','epss')))
        doc['completion_scope'].update(inventory_ids=[], published_cve_ids=['CVE-2026-12345'])
        self.assertEqual('partial', gate(doc)['status'])
        doc = self.complete_fixture()
        doc['completion_scope']['remote_targets'] = ['supabase:production', 'vercel:production']
        result = gate(doc)
        self.assertEqual('partial', result['status'])
        self.assertTrue({'remote:supabase:production', 'remote:vercel:production'} <= {r['id'] for r in result['obligations']})
        for target in doc['completion_scope']['remote_targets']:
            doc['completion_checks'].append(dict(id='remote:' + target, status='blocked', applicability='applicable',
                reason='Read-only project access not approved', evidence='scope.json#access-boundary'))
        self.assertEqual('partial', gate(doc)['status'])
        for row in doc['completion_checks']:
            if row['id'].startswith('remote:'):
                row.update(status='checked', evidence='readonly-settings-receipt.json#' + row['id'])
        self.assertEqual('complete', gate(doc)['status'])

    def test_record_validation_and_distinct_pending_states(self):
        def row(status='reviewed', applicability='applicable', **extra):
            return dict(id='asvs', status=status, applicability=applicability,
                        reason='Scope includes web session controls', evidence='scope.json#web', **extra)
        for status in ('blocked', 'not_tested', 'unattempted', 'unavailable', 'error'):
            actual = gate({'completion_checks': [row(status)]})['obligations']
            actual = next(r for r in actual if r['id'] == 'asvs')
            self.assertEqual(status, actual['status'])
            self.assertFalse(actual['satisfied'])
        for invalid in (dict(row(), reason=''), dict(row(), evidence=''),
                        row('not_applicable', 'unknown'), row('not_applicable', 'applicable'),
                        row('checked', 'invalid'), row('success')):
            with self.assertRaises(ValueError):
                gate({'completion_checks': [invalid]})
        with self.assertRaises(ValueError):
            gate({'completion_checks': [row(), row()]})
        for status, app in [('reviewed', 'applicable'), ('checked', 'applicable'),
                            ('not_applicable', 'not_applicable')]:
            rows = gate({'completion_checks': [row(status, app)]})['obligations']
            self.assertTrue(next(r for r in rows if r['id'] == 'asvs')['satisfied'])
        for status in ('not_tested', 'checked', 'reviewed'):
            rows = gate({'completion_checks': [row(status, 'unknown')]})['obligations']
            self.assertFalse(next(r for r in rows if r['id'] == 'asvs')['satisfied'])

    def test_missing_obligations_cannot_be_complete(self):
        result = gate({})
        registry = json.loads((SCRIPTS.parent / 'references/security-sources.json').read_text())
        self.assertEqual('partial', result['status'])
        self.assertEqual({s['id'] for s in registry['sources']} | {'dependency_coverage', 'remote_configuration'},
                         {r['id'] for r in result['obligations']})
        self.assertTrue(all(r['status'] == 'unattempted' for r in result['obligations']))
        self.assertTrue(all(r['record_supplied'] is False for r in result['obligations']))


if __name__ == '__main__':
    unittest.main()

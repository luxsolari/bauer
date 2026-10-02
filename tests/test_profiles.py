"""Versioned audit policy; entirely offline synthetic evidence."""
import copy
import json
import unittest
from test_report import load_report, synthetic_document
import test_completion


class ProfileTests(unittest.TestCase):
    def test_default_lean_full_and_visible_exclusions(self):
        report = load_report()
        doc = synthetic_document()
        doc.update(test_completion.CompletionTests().complete_fixture())
        result = report.normalize(doc)
        self.assertEqual(result['audit_profile']['mode'], 'lean')
        self.assertEqual(result['audit_profile']['version'], 'bauer-audit-profile-v1')
        self.assertEqual(result['audit_profile']['selected_sources'], ['cwe', 'osv', 'owasp-llm', 'owasp-web', 'vendor'])
        self.assertEqual(result['completion_gate']['status'], 'complete')
        for row in result['completion_gate']['obligations']:
            if row['id'] == 'asvs':
                self.assertEqual(row['status'], 'out_of_scope')
                self.assertEqual(row['supplied_record']['status'], 'reviewed')
                self.assertFalse(row['selected'])
                self.assertIn('ignored', row['reason'])
                self.assertIn('Ignored supplied record', report.render_markdown(result))
        self.assertEqual(report.normalize(result), result)
        full = report.normalize(dict(doc, audit_profile={'mode': 'full'}))
        self.assertTrue(all(row['selected'] for row in full['completion_gate']['obligations']))
        doc['completion_checks'] = [r for r in doc['completion_checks'] if r['id'] != 'asvs']
        self.assertEqual(report.normalize(doc)['completion_gate']['status'], 'complete')
        self.assertEqual(report.normalize(dict(doc, audit_profile={'mode': 'full'}))['completion_gate']['status'], 'partial')


    def test_custom_prerequisites_validation_and_nondroppable_core(self):
        report = load_report()
        for profile in [None, [], {'mode': 'FULL'}, {'version': 'v2'},
                        {'mode': 'lean', 'selected_sources': []},
                        {'mode': 'custom'}, {'mode': 'custom', 'selected_sources': ['unknown']},
                        {'mode': 'custom', 'selected_sources': ['osv', 'osv']},
                        {'mode': 'custom', 'selected_sources': ['kev']},
                        {'mode': 'custom', 'selected_sources': ['cve']},
                        {'mode': 'custom', 'selected_sources': ['osv', 'cve', 'epss'], 'skip_remote': True}]:
            with self.subTest(profile=profile), self.assertRaises(ValueError):
                report.normalize(dict(synthetic_document(), audit_profile=profile))
        doc = synthetic_document()
        doc.update(test_completion.CompletionTests().complete_fixture())
        doc['audit_profile'] = {'mode': 'custom', 'selected_sources': ['osv', 'cve', 'kev', 'epss']}
        self.assertEqual(report.normalize(doc)['completion_gate']['status'], 'complete')
        next(r for r in doc['completion_checks'] if r['id'] == 'cve').update(applicability='unknown')
        gate = report.normalize(doc)['completion_gate']
        self.assertEqual(gate['status'], 'partial')
        self.assertTrue(all(not r['satisfied'] for r in gate['obligations'] if r['id'] in ('kev', 'epss')))
        doc['audit_profile']['selected_sources'] = []
        with self.assertRaises(ValueError):
            report.normalize(doc)
        doc['audit_profile']['selected_sources'] = ['osv']
        doc['completion_scope']['inventory_ids'] = ['unapproved']
        self.assertEqual(report.normalize(doc)['completion_gate']['status'], 'partial')
        doc['completion_scope']['inventory_ids'] = []
        doc['completion_scope']['remote_targets'] = ['host']
        self.assertEqual(report.normalize(doc)['completion_gate']['status'], 'partial')


    def test_scorecard_priority_states_zeros_and_forgery(self):
        report = load_report()
        doc = synthetic_document()
        base = doc['findings'][0]
        doc['findings'] = [dict(base, rule='critical', severity='CRITICAL', status='candidate'),
                           dict(base, rule='high', severity='HIGH', remediation_state='fix_reported',
                                remediation_evidence={'fix_revision': 'abc', 'report_evidence': 'fix.json'})]
        result = report.normalize(doc)
        card = result['security_scorecard']
        self.assertEqual(card['next_action']['id'], result['findings'][0]['id'])
        self.assertEqual(card['next_action']['evidence_status'], 'candidate')
        self.assertEqual(card['remediation_counts'], {'open': 1, 'fix_reported': 1, 'fix_verified': 0})
        self.assertEqual(card['revision'], None)
        self.assertIn('default', card['remediation_defaults'])
        self.assertLess(report.render_markdown(result).index('## Security Scorecard'), report.render_markdown(result).index('## Severity counts'))
        doc['findings'].reverse()
        self.assertEqual(card, report.normalize(doc)['security_scorecard'])
        self.assertEqual(result, report.normalize(result))
        forged = copy.deepcopy(result)
        forged['security_scorecard']['completion'] = 'complete'
        with self.assertRaises(ValueError):
            report.normalize(forged)
        doc['findings'] = []
        card = report.normalize(doc)['security_scorecard']
        self.assertEqual(card['remediation_counts'], {'open': 0, 'fix_reported': 0, 'fix_verified': 0})
        self.assertEqual(card['next_action']['kind'], 'coverage_gap')
        self.assertEqual(card['severity_counts'], dict.fromkeys(report.SEVERITIES, 0))


    def test_remediation_verified_requires_actual_schema_evidence(self):
        report = load_report()
        doc = synthetic_document()
        finding = doc['findings'][0]
        for state, evidence in [('fixed', {}), ('fix_reported', {}), ('fix_verified', {}),
                                ('fix_verified', {'fix_revision': 'a', 'report_evidence': 'r'}),
                                ('fix_verified', {'fix_revision': 'a', 'report_evidence': 'r',
                                                  'verified_revision': 'b', 'verification_evidence': 'test.json', 'verification_result': 'passed'})]:
            finding.update(remediation_state=state, remediation_evidence=evidence)
            with self.subTest(state=state, evidence=evidence), self.assertRaises(ValueError):
                report.normalize(doc)
        finding.update(remediation_state='fix_verified', remediation_evidence={
            'fix_revision': 'a', 'report_evidence': 'fix.json', 'verified_revision': 'a',
            'verification_evidence': 'test.json#passed', 'verification_result': 'passed'})
        result = report.normalize(doc)
        self.assertEqual(result['security_scorecard']['remediation_counts']['fix_verified'], 1)
        self.assertEqual(result['security_scorecard']['next_action']['kind'], 'coverage_gap')
        self.assertEqual(result['counts']['HIGH'], 1)
        self.assertEqual(result, report.normalize(result))


    def test_scorecard_markdown_is_compact_and_keeps_evidence(self):
        report = load_report()
        result = report.normalize(synthetic_document())
        section = report.render_markdown(result).split('## Security Scorecard')[1].split('## Severity counts')[0]
        self.assertIn('| Obligation | Outcome | Reason | Evidence |', section)
        self.assertIn('Dependency counts', section)
        self.assertIn('Next action', section)
        self.assertNotIn('&#34;record&#95;supplied&#34;', section)
        self.assertIn(report.markdown_text(result['findings'][0]['evidence']), section)


    def test_profile_permutations_all_evidence_and_remediation_states(self):
        report = load_report()
        doc = synthetic_document()
        doc.update(test_completion.CompletionTests().complete_fixture())
        doc.update(audit_profile={'mode': 'custom', 'selected_sources': ['osv', 'cve', 'kev', 'epss']}, jev_policy={'enabled': True})
        base = doc['findings'][0]
        doc['findings'] = [dict(base, rule='open', status='candidate', severity='CRITICAL', jev={'status': 'declined'}),
            dict(base, rule='reported', status='supported', severity='HIGH', remediation_state='fix_reported',
                 remediation_evidence={'fix_revision': 'a', 'report_evidence': 'r'}, jev={'status': 'unavailable'}),
            dict(base, rule='verified', status='reproduced', remediation_state='fix_verified',
                 remediation_evidence={'fix_revision': 'a', 'report_evidence': 'r', 'verified_revision': 'a',
                                       'verification_evidence': 't', 'verification_result': 'passed'}, jev={'status': 'available'})]
        first = report.normalize(doc)['security_scorecard']
        self.assertEqual(first['evidence_counts'], dict(candidate=1, supported=1, reproduced=1))
        self.assertEqual(first['remediation_counts'], dict(open=1, fix_reported=1, fix_verified=1))
        self.assertEqual(len(first['jev_queue']), 3)
        self.assertEqual(len(first['jev_outcomes']), 3)
        for _ in range(3):
            doc['findings'] = doc['findings'][1:] + doc['findings'][:1]
            doc['completion_checks'].reverse()
            doc['audit_profile']['selected_sources'].reverse()
            self.assertEqual(report.normalize(doc)['security_scorecard'], first)
        doc['findings'] = [doc['findings'][0]]
        doc['findings'][0].update(remediation_state='fix_verified', remediation_evidence={
            'fix_revision': 'a', 'report_evidence': 'r', 'verified_revision': 'a',
            'verification_evidence': 't', 'verification_result': 'failed'})
        with self.assertRaises(ValueError):
            report.normalize(doc)
        doc['findings'] = []
        self.assertEqual(report.normalize(doc)['security_scorecard']['next_action']['kind'], 'none')


    def test_selected_prerequisite_requires_satisfied_core_ledger(self):
        report = load_report()
        doc = synthetic_document()
        doc.update(test_completion.CompletionTests().complete_fixture())
        doc['audit_profile'] = {'mode': 'full'}
        next(r for r in doc['completion_checks'] if r['id'] == 'dependency_coverage')['status'] = 'blocked'
        result = report.normalize(doc)
        for identifier in ('cve', 'nvd', 'kev', 'epss', 'ghsa', 'vendor'):
            self.assertFalse(next(r for r in result['completion_gate']['obligations'] if r['id'] == identifier)['satisfied'])


if __name__ == '__main__':
    unittest.main()

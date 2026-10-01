"""Tests for evidence report normalization; fixtures are synthetic."""
import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

SCRIPT = pathlib.Path(__file__).resolve().parents[1] / 'skills/bauer/scripts/report.py'

def load_report():
    spec = importlib.util.spec_from_file_location('report', SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_document() -> dict:
    return dict(scope='synthetic commit', sources=[], coverage=[], limitations=['Synthetic only'],
                findings=[dict(rule='unsafe-query', path='app.py', line=5, severity='HIGH',
                               title='Unsafe query', evidence='Input enters query', status='candidate',
                               categories=['A05:2025'], remediation='Bind parameters',
                               verification='Local trace; runtime not tested')])


class ReportTests(unittest.TestCase):
    def test_cli_resource_warning_is_generated_in_both_formats(self):
        warning = ('Security audits can be token-intensive: repository tracing, source queries, '
                   'repeated evidence review and report generation can consume substantial tokens. '
                   'Usage depends on repository scope and your host model; exact tokens or cost '
                   'cannot be predicted here. Optional Jev review may incur separate provider charges.')
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = pathlib.Path(directory) / 'synthetic.json'
            path.write_text(json.dumps(synthetic_document()), encoding='utf-8')
            def run(format):
                return subprocess.run([sys.executable, str(SCRIPT), str(path), '--format', format],
                                      capture_output=True, text=True, timeout=10)
            json_run, markdown_run = run('json'), run('markdown')
            self.assertEqual(json_run.returncode, 0, json_run.stderr)
            self.assertEqual(markdown_run.returncode, 0, markdown_run.stderr)
            report = json.loads(json_run.stdout)
            self.assertEqual(report.get('resource_note'), warning)
            self.assertIn('## Resource note\n\n' + warning, markdown_run.stdout)
            self.assertEqual(report['completion_gate']['status'], 'partial')
            self.assertNotIn('tokens_used', report)
            path.write_text(json_run.stdout, encoding='utf-8')
            self.assertEqual(run('json').stdout, json_run.stdout)
            path.write_text(json.dumps(dict(report, resource_note='No token cost')), encoding='utf-8')
            for format in ('json', 'markdown'):
                rejected = run(format)
                self.assertNotEqual(rejected.returncode, 0)
                self.assertEqual(rejected.stdout, '')

    def test_summary_table_has_all_five_levels_and_normalized_counts(self):
        module = load_report()
        all_levels = synthetic_document()
        base = all_levels['findings'][0]
        all_levels['findings'] = [dict(base, rule=level, severity=level, line=index + 1)
                                  for index, level in enumerate(module.SEVERITIES)]
        for document in (synthetic_document(), dict(synthetic_document(), findings=[]), all_levels):
            normalized = module.normalize(document)
            output = module.render_markdown(normalized)
            expected = '| Severity | Count |\n| --- | --- |\n' + '\n'.join(
                '| ' + level + ' | ' + str(normalized['counts'][level]) + ' |' for level in module.SEVERITIES)
            self.assertIn(expected, output)
            self.assertEqual(output.count('| Severity | Count |'), 1)

    def test_nested_metadata_renders_canonically(self):
        module = load_report()
        first = synthetic_document()
        second = synthetic_document()
        first['source_checks'] = [dict(id='test', status='checked', reason='fixture', extra={'a': 1, 'b': 2})]
        second['source_checks'] = [dict(id='test', status='checked', reason='fixture', extra={'b': 2, 'a': 1})]
        self.assertEqual(module.normalize(first), module.normalize(second))
        self.assertEqual(module.render_markdown(module.normalize(first)), module.render_markdown(module.normalize(second)))

    def test_url_like_text_uses_code_not_entities_that_linkifiers_can_decode(self):
        module = load_report()
        for value in ['https://example.org', 'www.example.org', 'audit@example.org',
                      '<img src="https://evil.invalid/x">', 'javascript:alert(1)',
                      'ftp://example.org', 'https&#58;//example.org']:
            with self.subTest(value=value):
                rendered = module.markdown_text(value)
                self.assertTrue(rendered.startswith('` ') and rendered.endswith(' `'))
                self.assertNotIn('https://', rendered)

    def test_cli_rejects_ambiguous_or_nonfinite_json_in_both_formats(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = pathlib.Path(directory) / 'synthetic.json'
            valid = json.dumps(synthetic_document())
            for content in [valid[:-1] + ', "scope": "duplicate"}',
                            valid[:-1] + ', "jev": {"confidence": NaN}}',
                            valid[:-1] + ', "jev": {"confidence": Infinity}}',
                            valid[:-1] + ', "jev": {"confidence": 1e999}}']:
                path.write_text(content, encoding='utf-8')
                for format in ('json', 'markdown'):
                    result = subprocess.run([sys.executable, str(SCRIPT), str(path), '--format', format],
                                            capture_output=True, text=True)
                    with self.subTest(content=content[-60:], format=format):
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, '')
                        self.assertEqual(result.stderr, 'bauer report: invalid input\n')

    def test_cli_invalid_files_json_data_and_arguments_do_not_disclose_input(self):
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = pathlib.Path(directory) / 'SECRET-input.json'
            documents = [b'SECRET not json', b'\xffSECRET', b'[]',
                         json.dumps(dict(synthetic_document(), findings=[dict(synthetic_document()['findings'][0], severity='SECRET')])).encode(),
                         json.dumps(dict(synthetic_document(), source_checks=[dict(id='SECRET', status='invalid', reason='SECRET')])).encode(),
                         ('[' * 2000 + 'SECRET').encode()]
            for contents in documents:
                path.write_bytes(contents)
                for format in ('json', 'markdown'):
                    result = subprocess.run([sys.executable, str(SCRIPT), str(path), '--format', format],
                                            capture_output=True, text=True)
                    with self.subTest(contents=contents[:40], format=format):
                        self.assertNotEqual(result.returncode, 0)
                        self.assertEqual(result.stdout, '')
                        self.assertEqual(result.stderr, 'bauer report: invalid input\n')
            for arguments in [[str(path.with_name('SECRET-missing.json'))], [directory],
                              [str(path), '--format', 'SECRET'], [str(path), '--SECRET']]:
                result = subprocess.run([sys.executable, str(SCRIPT), *arguments], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, '')
                self.assertNotIn('SECRET', result.stderr)
                self.assertNotIn('Traceback', result.stderr)

    def test_cli_formats_share_normalized_data_and_default_stays_json(self):
        module = load_report()
        document = synthetic_document()
        with tempfile.TemporaryDirectory(dir=os.environ.get('TMPDIR')) as directory:
            path = pathlib.Path(directory) / 'synthetic.json'
            path.write_text(json.dumps(document), encoding='utf-8')
            def run(*args):
                return subprocess.run([sys.executable, str(SCRIPT), str(path), *args],
                                      capture_output=True, text=True)
            default = run()
            explicit = run('--format', 'json')
            markdown = run('--format', 'markdown')
            self.assertEqual(default.returncode, 0)
            self.assertEqual(explicit.returncode, 0, explicit.stderr)
            self.assertEqual(default.stdout, explicit.stdout)
            self.assertEqual(default.stdout, run().stdout)
            self.assertEqual(json.loads(default.stdout), module.normalize(document))
            self.assertEqual(markdown.returncode, 0, markdown.stderr)
            self.assertEqual(markdown.stdout, module.render_markdown(json.loads(default.stdout)))
            self.assertEqual(markdown.stdout, run('--format', 'markdown').stdout)
            self.assertEqual(markdown.stderr, '')

    def test_markdown_neutralizes_active_content_controls_and_code_breakouts(self):
        module = load_report()
        payload = '<script>alert(1)</script> ![track](https://evil.invalid/img) <https://evil.invalid>\n# injected\r\x1b[31m\x00\u202e'
        document = synthetic_document()
        document['scope'] = payload
        document['limitations'] = [payload]
        finding = document['findings'][0]
        for key in ('title', 'rule', 'evidence', 'remediation', 'verification'):
            finding[key] = payload
        finding['path'] = 'src/odd`file<img>.py'
        finding['jev'] = {'<img src=x>': payload}
        document['coverage'] = [dict(id='A05:2025', status='not_tested', reason=payload, **{'<img>': payload})]
        document['source_checks'] = [dict(id=payload, status='unavailable', reason=payload)]
        normalized = module.normalize(document)
        rendered = module.render_markdown(normalized)
        self.assertEqual(normalized['scope'], payload, 'JSON must preserve supplied evidence')
        for unsafe in ['<script>', '<img', '<https', '![track]', '(https://', '\n# injected',
                       '\r', '\x1b', '\x00', '\u202e']:
            self.assertNotIn(unsafe, rendered)
        self.assertIn('&#60;script&#62;', rendered)
        self.assertIn('Location: `` src/odd`file&lt;img&gt;.py:5 ``', rendered)
        for path in [' leading.py', 'trailing.py ', 'src/```name.py', 'line\nname.py']:
            finding['path'] = path
            output = module.render_markdown(module.normalize(document))
            self.assertNotIn('\nname.py', output)
            self.assertIn('- Location: ', output)

    def test_markdown_renders_normalized_evidence_counts_gaps_and_checks(self):
        module = load_report()
        document = synthetic_document()
        document['coverage'] = [dict(id='A05:2025', status='not_tested', reason='No runtime')]
        document['sources'] = [dict(edition='2025', url='https://example.org/owasp',
                                    retrieved_at='2026-10-01T04:00:00Z', sha256='a' * 64)]
        for field, status in [('source_checks', 'unavailable'), ('framework_checks', 'not_applicable'),
                              ('supply_chain_checks', 'not_tested')]:
            document[field] = [dict(id=field, status=status, reason='Synthetic gap', version='SLSA 1.2',
                                    evidence='Snapshot absent')]
        document['findings'][0]['jev'] = {'status': 'review_only', 'confidence': 0.01}
        normalized = module.normalize(document)
        first = module.render_markdown(normalized)
        self.assertEqual(first, module.render_markdown(module.normalize(document)))
        for text in ['# Bauer audit report', '| CRITICAL | 0 |', '| HIGH | 1 |', '| MEDIUM | 0 |', '| LOW | 0 |',
                     '| INFORMATIONAL | 0 |', normalized['findings'][0]['id'], 'candidate (unconfirmed)',
                     'Evidence:', 'Input enters query', 'Remediation:', 'Bind parameters',
                     'Verification:', 'Local trace; runtime not tested', '## Remediation queue',
                     '## Coverage', '## Coverage gaps', 'No runtime', '## Limitations',
                     'Synthetic only', '## Sources', '2025', '## Source checks', '## Framework checks',
                     '## Supply-chain checks', 'SLSA 1', 'Snapshot absent', 'Jev (supplemental):']:
            self.assertIn(text, first)
        self.assertEqual(normalized['findings'][0]['severity'], 'HIGH')

    def test_optional_check_metadata_validates_without_year_coercion(self):
        module = load_report()
        for field in ('source_checks', 'framework_checks', 'supply_chain_checks'):
            entry = dict(id='ASVS-v5.0.0-1.1', status='checked' if field == 'source_checks' else 'reviewed',
                         reason='Synthetic', version='ASVS 5.0.0', url='https://example.org/reference',
                         retrieved_at='2026-10-01T04:00:00+00:00', sha256='a' * 64,
                         evidence='Synthetic snapshot reference')
            document = dict(synthetic_document(), **{field: [entry]})
            self.assertEqual(module.normalize(document)[field], [entry])
            for key, value in [('version', ''), ('version', 5), ('url', 'http://example.org'),
                               ('url', 'https://user:secret@example.org'), ('url', 'https:///missing'),
                               ('url', 'https://example.org/\nsecret'), ('retrieved_at', 'yesterday'),
                               ('retrieved_at', '2026-10-01T04:00:00'), ('retrieved_at', None),
                               ('sha256', 'bad'), ('sha256', 3), ('evidence', {}), ('evidence', ' ')]:
                with self.subTest(field=field, key=key, value=value), self.assertRaises(ValueError):
                    module.normalize(dict(document, **{field: [dict(entry, **{key: value})]}))

    def test_supplemental_checks_require_scoped_unique_ids_status_and_reason(self):
        module = load_report()
        for field, status in [('source_checks', 'checked'), ('framework_checks', 'reviewed'),
                              ('supply_chain_checks', 'reviewed')]:
            entry = dict(id='registry-control', status=status, reason='Synthetic review')
            document = dict(synthetic_document(), **{field: [entry]})
            self.assertEqual(module.normalize(document)[field], [entry])
            for entries in [None, {}, [None], [dict(entry, id='')], [dict(entry, id=1)],
                            [dict(entry, reason=' ')], [dict(entry, status='secure')],
                            [dict(entry, status='reviewed' if status == 'checked' else 'checked')],
                            [entry, entry]]:
                with self.subTest(field=field, entries=entries), self.assertRaises(ValueError):
                    module.normalize(dict(document, **{field: entries}))
        shared = dict(id='same', reason='Scoped independently')
        result = module.normalize(dict(synthetic_document(),
                                       source_checks=[dict(shared, status='checked')],
                                       framework_checks=[dict(shared, status='reviewed')],
                                       supply_chain_checks=[dict(shared, status='not_tested')]))
        self.assertEqual(result['source_checks'][0]['id'], 'same')

    def test_provenance_coverage_and_limitations_require_structured_entries(self):
        spec = importlib.util.spec_from_file_location('report', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        source = dict(edition='2025', url='https://top10.owasp.org/2025/',
                      retrieved_at='2026-10-01T04:00:00Z', sha256='a' * 64)
        coverage = dict(id='A05:2025', status='not_tested', reason='Runtime unavailable')
        d = dict(scope='commit', sources=[source], coverage=[coverage], limitations=['Partial audit'], findings=[])
        self.assertEqual(module.normalize(d)['coverage'], [coverage])
        for field, entries in [('sources', [None]), ('coverage', [False]), ('limitations', [{}]),
                               ('sources', [dict(source, sha256='bad')]),
                               ('sources', [dict(source, url='https://user:password@owasp.org/')]),
                               ('sources', [dict(source, retrieved_at='yesterday')]),
                               ('coverage', [dict(coverage, status='secure')]),
                               ('coverage', [dict(coverage, reason='')]),
                               ('coverage', [coverage, coverage])]:
            with self.subTest(field=field, entries=entries), self.assertRaises(ValueError):
                module.normalize(dict(d, **{field: entries}))

    def test_stable_order_and_all_severity_counts(self):
        self.assertTrue(SCRIPT.exists(), 'report implementation missing')
        spec = importlib.util.spec_from_file_location('report', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        finding = dict(rule='sql-injection', path='app.py', line=5, severity='HIGH',
                       title='Unsafe query', evidence='Input interpolated into SQL',
                       status='supported', categories=['A05:2025'],
                       remediation='Use parameterized queries', verification='Trace reviewed')
        document = dict(scope='fixture commit', sources=[], coverage=[], limitations=['fixture only'],
                        findings=[finding, dict(finding, rule='debug', severity='LOW', line=2)])
        first = module.normalize(document)
        second = module.normalize(dict(document, findings=list(reversed(document['findings']))))
        self.assertEqual(first, second)
        self.assertEqual(first['counts'], dict(CRITICAL=0, HIGH=1, MEDIUM=0, LOW=1, INFORMATIONAL=0))
        self.assertEqual(first['findings'][0]['severity'], 'HIGH')

    def test_rejects_duplicate_identity_and_invalid_evidence(self):
        spec = importlib.util.spec_from_file_location('report', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        f = dict(rule='r', path='a.py', line=1, severity='HIGH', title='t', evidence='e',
                 status='supported', categories=['A05:2025'], remediation='fix', verification='reviewed')
        d = dict(scope='commit', sources=[], coverage=[], limitations=[], findings=[f])
        with self.assertRaises(ValueError):
            module.normalize(dict(d, findings=[f, f]))
        for field, value in [('path', '../secret'), ('line', True), ('severity', 'high'),
                             ('evidence', ''), ('status', 'confirmed'), ('categories', ['A05'])]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                module.normalize(dict(d, findings=[dict(f, **{field: value})]))

    def test_jev_assessment_cannot_replace_severity_or_status(self):
        spec = importlib.util.spec_from_file_location('report', SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        f = dict(rule='r', path='a.py', line=1, severity='CRITICAL', title='t', evidence='e',
                 status='reproduced', categories=['LLM03:2026'], remediation='fix', verification='local test',
                 jev={'status': 'review_only', 'confidence': 0.01})
        result = module.normalize(dict(scope='commit', sources=[], coverage=[], limitations=[], findings=[f]))
        self.assertEqual(result['findings'][0]['status'], 'reproduced')
        self.assertEqual(result['counts']['CRITICAL'], 1)

if __name__ == '__main__':
    unittest.main()

"""The expanded source contract is executable agent guidance, not an API client."""
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class SourceContractTests(unittest.TestCase):
    def test_expanded_guidance_and_supply_chain_have_explicit_sources(self):
        path = ROOT / 'skills/bauer/references/security-sources.json'
        self.assertTrue(path.is_file(), 'expanded source registry missing')
        registry = json.loads(path.read_text(encoding='utf-8'))
        expected = {'owasp-web', 'owasp-llm', 'cwe', 'osv', 'ghsa', 'cve', 'nvd',
                    'kev', 'epss', 'vendor', 'asvs', 'slsa', 'scorecard'}
        self.assertEqual({s['id'] for s in registry['sources']}, expected)
        for source in registry['sources']:
            self.assertIn(source['mode'], ('helper', 'agent', 'conditional-agent'))
            self.assertTrue(source['purpose'])
            self.assertTrue(source['url'].startswith('https://'))
        skill = (ROOT / 'skills/bauer/SKILL.md').read_text(encoding='utf-8')
        for reference in ('references/advisories.md', 'references/supply-chain.md',
                          'references/security-sources.json'):
            self.assertIn(reference, skill)
            self.assertTrue((ROOT / 'skills/bauer' / reference).is_file())
        advisories = (ROOT / 'skills/bauer/references/advisories.md').read_text(encoding='utf-8')
        self.assertIn('withdrawn', advisories)
        self.assertIn('aliases', advisories)
        self.assertIn('inventory disclosure', advisories)
        supply = (ROOT / 'skills/bauer/references/supply-chain.md').read_text(encoding='utf-8')
        self.assertIn('not_tested', supply)
        self.assertIn('expected identity', supply)

if __name__ == '__main__':
    unittest.main()

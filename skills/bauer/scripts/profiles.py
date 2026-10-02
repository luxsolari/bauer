"""Versioned deterministic audit scope policy. No network or user configuration."""
import json
from pathlib import Path

VERSION = 'bauer-audit-profile-v1'
LEAN = ('cwe', 'osv', 'owasp-llm', 'owasp-web', 'vendor')
PREREQUISITES = {'cve': ('osv',), 'nvd': ('cve',), 'kev': ('cve',),
                 'epss': ('cve',), 'ghsa': ('osv',), 'vendor': ('osv',)}


def normalize(value=None):
    registry = json.loads((Path(__file__).resolve().parent.parent / 'references/security-sources.json').read_text(encoding='utf-8'))
    known = {source['id'] for source in registry['sources']}
    if value is None:
        value = {}
    if not isinstance(value, dict) or set(value) - {'mode', 'version', 'selected_sources'}:
        raise ValueError('invalid audit profile')
    mode = value.get('mode', 'lean')
    if mode not in ('lean', 'full', 'custom') or value.get('version', VERSION) != VERSION:
        raise ValueError('unsupported audit profile')
    expected = sorted(known if mode == 'full' else LEAN)
    selected = value.get('selected_sources', expected)
    if (not isinstance(selected, list) or any(not isinstance(s, str) or s not in known for s in selected)
            or len(set(selected)) != len(selected)):
        raise ValueError('invalid profile selections')
    if mode != 'custom' and sorted(selected) != expected:
        raise ValueError('contradictory profile selections')
    if mode == 'custom' and ('selected_sources' not in value or not selected):
        raise ValueError('custom requires at least one explicit selection')
    if any(not set(PREREQUISITES.get(source, ())) <= set(selected) for source in selected):
        raise ValueError('missing profile prerequisite; select explicitly')
    return dict(mode=mode, version=VERSION, selected_sources=sorted(selected))

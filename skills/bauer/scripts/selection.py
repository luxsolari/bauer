#!/usr/bin/env python3
"""Build a deterministic local Jev review queue from supplied audit evidence.

Python 3.9+, stdlib only. No network, credentials, packet construction, source
collection or code execution. --enabled schedules approval, not disclosure.
Policy/queue implementation lives in report.normalize to avoid circular imports.
"""
import argparse
import json
from pathlib import Path
import sys

from report import normalize, SEVERITIES, unique_object


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'bauer selection: invalid arguments\n')


def main(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--enabled', action='store_true')
    parser.add_argument('--min-severity', choices=SEVERITIES, default='MEDIUM')
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.evidence.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
        # Validate original metadata first; never overwrite malformed supplied policy.
        normalize(document)
        document = dict(document, jev_policy=dict(enabled=args.enabled, min_severity=args.min_severity))
        # A new CLI policy is explicit; regenerate derived metadata for that policy.
        document.pop('jev_selection', None)
        selection = normalize(document)['jev_selection']
        # Reject non-finite evidence even when it is not part of the queue.
        json.dumps(document, allow_nan=False)
        output = json.dumps(selection, indent=2, sort_keys=True, allow_nan=False) + '\n'
    except (OSError, ValueError, TypeError, RecursionError):
        print('bauer selection: invalid input', file=sys.stderr)
        return 1
    print(output, end='')
    return 0


if __name__ == '__main__':
    sys.exit(main())

#!/usr/bin/env python3
"""Build a deterministic local Jev review queue from supplied audit evidence.

Python 3.9+, stdlib only. No network, credentials, packet construction, source
collection or code execution. --enabled schedules approval, not disclosure.
Policy/queue implementation lives in report.normalize to avoid circular imports.
New input requires a confirmed --run-record or embedded record. Without a record,
only an existing fully validated saved gate is historical input, never raw evidence.
"""
import argparse
import json
from pathlib import Path
import sys

from report import normalize, normalize_new_evidence, normalize_saved, SEVERITIES, unique_object, bind_run_record


class SafeParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, 'bauer selection: invalid arguments\n')


def main(argv=None):
    parser = SafeParser(description=__doc__, allow_abbrev=False)
    parser.add_argument('evidence', type=Path)
    parser.add_argument('--enabled', action='store_true')
    parser.add_argument('--min-severity', choices=SEVERITIES, default='MEDIUM')
    parser.add_argument('--run-record', type=Path, help='Confirmed snapshot for new evidence; optional only with embedded confirmation or validated saved history')
    args = parser.parse_args(argv)
    try:
        document = json.loads(args.evidence.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
        if args.run_record is not None:
            record = json.loads(args.run_record.read_text(encoding='utf-8'), object_pairs_hook=unique_object)
            document = bind_run_record(document, record)
        # CLI boundary: confirmed new evidence or validated existing saved history.
        # Validate original metadata first; never overwrite malformed supplied policy.
        if isinstance(document, dict) and 'run_record' in document:
            document = normalize_new_evidence(document)
        else:
            document = normalize_saved(document)
        document = dict(document, jev_policy=dict(enabled=args.enabled, min_severity=args.min_severity))
        # A new CLI policy is explicit; regenerate all policy-dependent metadata.
        document.pop('jev_selection', None)
        document.pop('security_scorecard', None)
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

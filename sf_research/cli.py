"""Reproducible offline investigation CLI."""
import argparse
import json
import sys
from pathlib import Path
from .model import Event
from .evidence import Ledger
from .detection import Correlator


def ingest(source: Path, database: str, strict: bool = False):
    ledger = Ledger(database)
    engine = Correlator()
    accepted = 0
    rejected = []
    findings = 0
    try:
        with source.open(encoding='utf-8-sig') as stream:
            for line_number, line in enumerate(stream, 1):
                if not line.strip():
                    continue
                try:
                    event = Event.parse(json.loads(line))
                    if not ledger.append(event):
                        continue
                    accepted += 1
                    for finding in engine.process(event):
                        if ledger.save_finding(finding):
                            findings += 1
                except (ValueError, TypeError, KeyError) as exc:
                    rejected.append({'line': line_number, 'reason': str(exc)[:160]})
                    if strict:
                        raise ValueError(f'line {line_number}: {exc}') from exc
        return {'accepted': accepted, 'findings': findings, 'rejected': rejected,
                'verification': ledger.verify()}
    finally:
        ledger.close()


def main(argv=None):
    parser = argparse.ArgumentParser(prog='sf-research', description='SentinelForge offline security research engine')
    sub = parser.add_subparsers(dest='command', required=True)
    imp = sub.add_parser('ingest', help='ingest JSONL evidence and evaluate rules')
    imp.add_argument('input', type=Path)
    imp.add_argument('--db', default='evaluation/research.sqlite3')
    imp.add_argument('--strict', action='store_true')
    check = sub.add_parser('verify', help='verify evidence hash chain')
    check.add_argument('--db', default='evaluation/research.sqlite3')
    report = sub.add_parser('report', help='print explainable findings')
    report.add_argument('--db', default='evaluation/research.sqlite3')
    args = parser.parse_args(argv)
    if args.command == 'ingest':
        result = ingest(args.input, args.db, args.strict)
    else:
        ledger = Ledger(args.db)
        try:
            result = ledger.verify() if args.command == 'verify' else {'findings': ledger.findings()}
        finally:
            ledger.close()
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.command == 'verify' and not result['valid']:
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())

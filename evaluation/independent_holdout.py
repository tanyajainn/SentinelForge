"""Score SentinelForge's real detector against explicit, independently labelled episodes.

This is an evaluation harness, NOT a new detector. It never sends emails or
contacts any external addresses. Only synthetic or permissioned, redacted traces
should be used. Each episode gets an isolated temporary SQLite Store.

The provided example data are synthetic demonstration fixtures, not validation.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory

LABELS = {'attack', 'benign'}


def load_episodes(path: Path) -> list[dict]:
    rows = []
    ids = set()
    with path.open(encoding='utf-8-sig') as f:
        for line_no, line in enumerate(f, 1):
            if not line.strip():
                continue
            try:
                episode = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f'Line {line_no}: invalid JSON: {exc}') from exc
            if not isinstance(episode, dict):
                raise ValueError(f'Line {line_no}: expected JSON object')
            episode_id = episode.get('episode_id')
            if not isinstance(episode_id, str) or not episode_id or episode_id in ids:
                raise ValueError(f'Line {line_no}: missing/duplicate episode_id')
            ids.add(episode_id)
            if episode.get('label') not in LABELS:
                raise ValueError(f'Line {line_no}: label must be attack or benign')
            events = episode.get('events')
            if not isinstance(events, list) or not events or len(events) > 10000:
                raise ValueError(f'Line {line_no}: provide 1..10000 event objects')
            for event in events:
                if not isinstance(event, dict):
                    raise ValueError(f'Line {line_no}: events must be objects')
                if not isinstance(event.get('record_id'), int) or event['record_id'] < 1:
                    raise ValueError(f'Line {line_no}: record_id must be a positive integer')
            if len({e.get('channel') for e in events}) != 1:
                raise ValueError(f'Line {line_no}: each episode must use one Windows channel')
            sequence = [e['record_id'] for e in events]
            if sequence != sorted(set(sequence)):
                raise ValueError(f'Line {line_no}: record_id must be unique and ascending')
            rows.append(episode)
    if not rows:
        raise ValueError('No labelled episodes found')
    return rows


def confusion(predictions) -> dict:
    """Return reproducible per-episode confusion matrix and defined metrics."""
    counts = Counter()
    for label, alerted in predictions:
        if label not in LABELS or not isinstance(alerted, bool):
            raise ValueError('Expected (attack|benign, boolean) pairs')
        counts['tp' if label == 'attack' and alerted else
               'fn' if label == 'attack' else
               'fp' if alerted else 'tn'] += 1
    tp, fp, fn, tn = (counts[k] for k in ('tp', 'fp', 'fn', 'tn'))
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
    return {'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'precision': p, 'recall': r, 'f1': f1,
            'episodes': tp + fp + fn + tn}


def evaluate(episodes: list[dict]) -> dict:
    # Import source code only when evaluating, so pure metric tests can run on any OS.
    from sentinelforge.core import Store, Detector, Event

    records = []
    breakdown = defaultdict(list)
    for entry in episodes:
        with TemporaryDirectory(prefix='sf-holdout-') as directory:
            store = Store(str(Path(directory) / 'ep.sqlite3'))
            try:
                events = [Event(**data) for data in entry['events']]
                channel = events[0].channel
                alerts = store.ingest_batch(channel, events, Detector())
                detected = bool(alerts)
                rules = sorted(set(a.rule for a in alerts))
            finally:
                store.db.close()
        records.append({'episode_id': entry['episode_id'],
                        'label': entry['label'], 'alerted': detected,
                        'scenario': str(entry.get('scenario', 'unspecified')),
                        'rules': rules})
        breakdown[str(entry.get('scenario', 'unspecified'))].append(
            (entry['label'], detected))
    return {'overall': confusion((r['label'], r['alerted']) for r in records),
            'by_scenario': {s: confusion(rows) for s, rows in sorted(breakdown.items())},
            'episodes': records}


def main() -> int:
    parser = argparse.ArgumentParser(description='Measure the deployed detector on labelled JSONL episodes')
    parser.add_argument('--input', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--origin', required=True, choices=['synthetic_demo', 'independent_lab'],
                        help='Dataset provenance; do not mislabel synthetic examples as independent')
    args = parser.parse_args()
    episodes = load_episodes(args.input)
    result = evaluate(episodes)
    result['dataset'] = {'file': args.input.name,
                         'sha256': hashlib.sha256(args.input.read_bytes()).hexdigest(),
                         'origin': args.origin, 'labelled_episodes': len(episodes)}
    result['caution'] = ('Synthetic fixture scores are NOT real-world accuracy.' if args.origin == 'synthetic_demo'
                         else 'Independent-lab claims require documented authorized provenance and review.')
    serialized = json.dumps(result, indent=2)
    print(serialized)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(serialized + '\n', encoding='utf-8')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

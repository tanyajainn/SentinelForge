"""Compare failed-logon thresholds and check SQLite restart consistency."""
import argparse
import hashlib
import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinelforge.core import Detector, Event, Store


# Each scenario defines its label, failure count range, and gap range in seconds.
SCENARIOS = (
    ("quiet workstation", False, (0, 2), (5, 30)),
    ("mistyped password", False, (2, 5), (3, 20)),
    ("stale service credential", False, (6, 12), (20, 90)),
    ("short suspicious sequence", True, (3, 7), (3, 20)),
    ("rapid suspicious sequence", True, (8, 14), (2, 12)),
    ("sparse suspicious sequence", True, (4, 9), (160, 230)),
)


def corpus(seed, repetitions):
    rng = random.Random(seed)
    episodes = []
    for name, label, counts, gaps in SCENARIOS:
        for _ in range(repetitions):
            seconds = []
            t = 0
            for _ in range(rng.randint(*counts)):
                seconds.append(t)
                t += rng.randint(*gaps)
            episodes.append((name, label, seconds))
    return episodes


def records(seconds):
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    return [
        Event("Security", i, 4625, (start + timedelta(seconds=t)).isoformat(),
              "benchmark", "Synthetic failed logon")
        for i, t in enumerate(seconds, 1)
    ]


def continuous(events, threshold):
    detector = Detector(threshold=threshold)
    return [event.record_id for event in events if detector.process(event)]


def restarted(events, threshold, path):
    hits = []
    for i in range(0, len(events), 3):
        store = Store(str(path))
        try:
            batch = events[max(0, i - 1):i + 3]
            alerts = store.ingest_batch("Security", batch, Detector(threshold))
            hits.extend(a.evidence[-1]["record_id"] for a in alerts)
        finally:
            store.db.close()
    return hits


def metrics(labels, predictions):
    pairs = list(zip(labels, predictions, strict=True))
    tp = sum(y and p for y, p in pairs)
    fp = sum(not y and p for y, p in pairs)
    fn = sum(y and not p for y, p in pairs)
    tn = len(pairs) - tp - fp - fn

    def ratio(n, d):
        return n / d if d else None

    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=ratio(tp, tp + fp),
                recall=ratio(tp, tp + fn), f1=ratio(2 * tp, 2 * tp + fp + fn))


def score(episodes, threshold):
    labels = [label for _, label, _ in episodes]
    predictions = [bool(continuous(records(s), threshold)) for _, _, s in episodes]
    return metrics(labels, predictions)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=20261111)
    parser.add_argument("--repetitions", type=int, default=12)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    if args.repetitions < 1:
        parser.error("--repetitions must be positive")

    training = corpus(args.seed, args.repetitions)
    holdout = corpus(args.seed + 1, args.repetitions)
    sweep = {t: score(training, t) for t in (3, 5, 8)}
    selected = max(sweep, key=lambda t: (sweep[t]["f1"], -sweep[t]["fp"], t))

    rows = []
    with TemporaryDirectory() as folder:
        for i, (name, label, seconds) in enumerate(holdout):
            events = records(seconds)
            rows.append(dict(
                scenario=name, positive=label, seconds=seconds,
                direct_hits=continuous(events, selected),
                restart_hits=restarted(events, selected, Path(folder) / f"{i}.db"),
            ))

    labels = [row["positive"] for row in rows]
    policies = {
        "any_failure": metrics(labels, [bool(row["seconds"]) for row in rows]),
        "default_5": score(holdout, 5),
        "selected": metrics(labels, [bool(row["direct_hits"]) for row in rows]),
    }
    mismatches = sum(row["direct_hits"] != row["restart_hits"] for row in rows)
    result = dict(
        seed=args.seed, repetitions=args.repetitions, selected_threshold=selected,
        holdout_sha256=hashlib.sha256(json.dumps(holdout).encode()).hexdigest(),
        calibration=sweep, holdout=policies, restart_mismatches=mismatches, episodes=rows,
    )
    if args.json:
        args.json.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(f"Held-out episodes: {len(rows)} | Selected threshold: {selected}")
    for name, m in policies.items():
        print(f"{name:12} TP={m['tp']:2} FP={m['fp']:2} FN={m['fn']:2} F1={m['f1']:.3f}")
    print(f"Restart mismatches: {mismatches}")
    if args.json:
        print(f"Report: {args.json.resolve()}")
    if mismatches:
        raise SystemExit("Restart results differed from continuous detection.")


if __name__ == "__main__":
    main()

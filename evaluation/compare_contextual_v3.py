"""Offline, episode-level comparison of installed opt-in v3 and two benchmarks.

Uses actual Store.ingest_batch(..., contextual_v3=True), but an in-memory SQLite
DB per synthetic episode. Scores ONLY v3- prefixed alerts for v3, not legacy
alerts that the Store may also emit. No OS changes, email, network or live DB.

Run: python -m evaluation.compare_contextual_v3 --seeds 30 --repetitions 8
"""
from __future__ import annotations

import argparse
import json
import statistics
from collections import Counter
from pathlib import Path

from evaluation import contextual_benchmark as baseline
from evaluation import adversarial_logon_audit as adversarial
from sentinelforge.core import Store, Detector

POLICIES = ("current_source_ip", "experimental_contextual", "opt_in_v3_only")


def v3_episode(events, *, threshold=5, window=10):
    """Return whether v3 fired, plus its rule counts; never use user's DB."""
    store = Store(":memory:", contextual_v3=True)
    try:
        alerts = store.ingest_batch("Security", events, Detector(
            threshold=threshold, window_minutes=window))
        matches = [a for a in alerts if a.rule.startswith("v3-")]
        return bool(matches), Counter(a.rule for a in matches)
    finally:
        store.db.close()


def datasets():
    return {
        "original_contextual": (
            tuple((name, label) for name, label in baseline.SCENARIOS), baseline.fixture),
        "adversarial_challenge": (
            tuple((name, label) for name, (label, _) in adversarial.CASES.items()), adversarial.fixture),
    }


def compare(seeds=30, repetitions=8, base_seed=20261120, threshold=5, window=10):
    if not (1 <= seeds <= 100 and 1 <= repetitions <= 100 and
            1 <= threshold <= 100 and 1 <= window <= 120):
        raise ValueError("seeds/repetitions/threshold/window outside allowed range")
    summaries = {}
    for dataset_name, (cases, make_fixture) in datasets().items():
        counts = {policy: Counter() for policy in POLICIES}
        per_seed = {policy: [] for policy in POLICIES}
        scenario_counts = {policy: {name: Counter() for name, _ in cases}
                           for policy in POLICIES}
        emitted_rules = Counter()
        for seed in range(base_seed, base_seed + seeds):
            labels = []
            predictions = {p: [] for p in POLICIES}
            for name, label in cases:
                for iteration in range(repetitions):
                    events = make_fixture(name, seed, iteration)
                    current = baseline.predict("current_source_ip", events, threshold, window)
                    prototype = baseline.predict("experimental_contextual", events, threshold, window)
                    v3, rules = v3_episode(events, threshold=threshold, window=window)
                    emitted_rules.update(rules)
                    answers = {"current_source_ip": current,
                               "experimental_contextual": prototype,
                               "opt_in_v3_only": v3}
                    labels.append(label)
                    for policy, predicted in answers.items():
                        predictions[policy].append(predicted)
                        row = scenario_counts[policy][name]
                        row["episodes"] += 1
                        row["flagged"] += int(predicted)
                        row["fp"] += int(predicted and not label)
                        row["fn"] += int(label and not predicted)
            for policy, values in predictions.items():
                m = baseline.metric(labels, values)
                per_seed[policy].append(m)
                for field in ("tp", "fp", "fn", "tn"):
                    counts[policy][field] += m[field]
        outcomes = {}
        for policy in POLICIES:
            count = counts[policy]
            tp, fp, fn, tn = (count[k] for k in ("tp", "fp", "fn", "tn"))
            aggregate = {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
                         "precision": tp / (tp + fp) if tp + fp else None,
                         "recall": tp / (tp + fn) if tp + fn else None,
                         "f1": 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else None}
            spread = {}
            for field in ("precision", "recall", "f1"):
                series = [row[field] for row in per_seed[policy] if row[field] is not None]
                spread[field] = {"mean": statistics.mean(series) if series else None,
                                 "sd": statistics.stdev(series) if len(series) > 1 else 0.0}
            outcomes[policy] = {
                "aggregate": aggregate, "seed_statistics": spread,
                "by_scenario": {name: dict(row) for name, row in scenario_counts[policy].items()},
            }
        summaries[dataset_name] = {
            "scenarios": {name: label for name, label in cases},
            "results": outcomes,
            "v3_emitted_rules": dict(emitted_rules),
        }
    return {
        "warning": "Synthetic generator assumptions, not measured production accuracy",
        "assessment": "Opt-in v3 only; existing legacy alerts excluded from v3 score",
        "method": "One binary prediction per episode; in-memory Store.ingest_batch for v3; no live installation",
        "seeds": seeds, "repetitions": repetitions, "base_seed": base_seed,
        "threshold": threshold, "window_minutes": window, "datasets": summaries,
    }


def markdown(report):
    def fmt(v):
        return "N/A" if v["mean"] is None else f"{v['mean']:.3f} ± {v['sd']:.3f}"
    lines = ["# Contextual v3 — replay comparison", "",
        "**Research-only, synthetic cases. Not production precision or recall.**", "",
        f"{report['seeds']} seeds × {report['repetitions']} repetitions per case; "
        f"threshold {report['threshold']}, window {report['window_minutes']} minutes.", "",
        "Only `v3-` alerts count for v3. Existing v2 alerts also emitted during ingestion are excluded.",
        "The offline prototype is evaluated separately and is not deployed.", ""]
    for name, dataset in report["datasets"].items():
        lines += [f"## {name.replace('_', ' ').title()}", "",
          "| Policy | TP | FP | FN | TN | Precision (mean ± SD) | Recall (mean ± SD) | F1 (mean ± SD) |",
          "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for policy, payload in dataset["results"].items():
            m = payload["aggregate"]
            s = payload["seed_statistics"]
            lines.append(f"| {policy} | {m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
                         f"{fmt(s['precision'])} | {fmt(s['recall'])} | {fmt(s['f1'])} |")
        lines += ["", "### Per-scenario errors", "",
          "| Policy | Scenario | Label | Flagged | FP | FN |",
          "|---|---|---|---:|---:|---:|"]
        for policy, payload in dataset["results"].items():
            for scenario, row in payload["by_scenario"].items():
                lines.append(f"| {policy} | {scenario} | "
                             f"{'attack' if dataset['scenarios'][scenario] else 'benign'} | "
                             f"{row['flagged']}/{row['episodes']} | {row['fp']} | {row['fn']} |")
        lines += ["", "v3 advisory rule emissions (may exceed episode count): "
                  + (", ".join(f"`{rule}`={n}" for rule, n in sorted(dataset["v3_emitted_rules"].items())) or "none"), ""]
    lines += ["## Limits", "",
       "- Labels reflect authored fixtures, not independently authenticated malicious/authorized intent.",
       "- Results vary with arbitrary scenario prevalence; no operational false-positive rate is inferred.",
       "- Existing v2 alerts remain active when v3 is opted in; counting both will change user-visible alert volume.",
       "- SQLite `:memory:` matches transaction logic but does not test disk persistence/restart, retention under heavy load or Windows collection.",
       "- Future decision: review false positives by scenario, run disk-backed restart and overlap tests, and only then decide on live rollout.", ""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--repetitions", type=int, default=8)
    parser.add_argument("--base-seed", type=int, default=20261120)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--out", type=Path, default=Path("evaluation/results/v3_comparison"))
    args = parser.parse_args()
    report = compare(seeds=args.seeds, repetitions=args.repetitions,
                     base_seed=args.base_seed, threshold=args.threshold, window=args.window)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.out / "results.md").write_text(markdown(report), encoding="utf-8")
    for name, data in report["datasets"].items():
        print(name)
        for policy, result in data["results"].items():
            m = result["aggregate"]
            print(f"  {policy}: TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} F1={m['f1']:.3f}")
    print("Report:", (args.out / "results.md").resolve())


if __name__ == "__main__":
    main()

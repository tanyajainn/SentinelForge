"""Adversarial synthetic 4625 evaluation. No Windows or network operations.

Report known hard negatives, evasions and source-field quality problems.
The fixture labels are hypotheses, NOT validated attack ground truth.

python -m evaluation.adversarial_logon_audit --seeds 30 --repetitions 8
"""
from __future__ import annotations

import argparse
from datetime import timedelta
import json
from pathlib import Path
import random
import statistics

from evaluation import contextual_benchmark as baseline
from sentinelforge.core import Event

CASES = {
    "slow_password_spray": (True, "Attack spread across accounts over a long period"),
    "low_rate_distributed": (True, "One account from many sources, outside fast correlation window"),
    "private_ip_targeted": (True, "Repeated failures from one RFC1918 address; policy may decline attribution"),
    "fast_benign_shared_nat": (False, "Many users mistype credentials quickly behind one NAT"),
    "stale_service_credential": (False, "Authorized service misconfiguration repeatedly fails"),
    "missing_ip_benign": (False, "Distinct users with no source field should not be one attributed source"),
    "benign_account_multiple_ips": (False, "One user through several legitimate egress IP addresses"),
    "password_reset_typos": (False, "One person makes repeated legitimate mistakes"),
}


def fixture(name: str, seed: int, repetition: int) -> list[Event]:
    if name not in CASES:
        raise ValueError(f"Unknown case: {name}")
    rng = random.Random(f"adversarial:{name}:{seed}:{repetition}")
    items = []
    if name == "slow_password_spray":
        for i in range(18):
            items.append((i * 210 + rng.randint(0, 15), f"staff_{i:03}", "8.8.8.8"))
    elif name == "low_rate_distributed":
        for i in range(18):
            items.append((i * 200 + rng.randint(0, 15), "target", f"9.9.9.{i + 1}"))
    elif name == "private_ip_targeted":
        for i in range(12):
            items.append((i * 12 + rng.randint(0, 2), "target", "10.1.2.3"))
    elif name == "fast_benign_shared_nat":
        for i in range(15):
            items.append((i * 9 + rng.randint(0, 4), f"staff_{i:03}", "8.8.8.8"))
    elif name == "stale_service_credential":
        for i in range(12):
            items.append((i * 20 + rng.randint(0, 4), "svc_backup", "8.8.8.8"))
    elif name == "missing_ip_benign":
        for i in range(12):
            items.append((i * 16 + rng.randint(0, 3), f"staff_{i:03}", None))
    elif name == "benign_account_multiple_ips":
        for i in range(12):
            items.append((i * 12 + rng.randint(0, 3), "traveling_user", f"9.9.9.{i + 1}"))
    elif name == "password_reset_typos":
        for i in range(9):
            items.append((i * 19 + rng.randint(0, 3), "staff_member", "8.8.8.8"))
    items.sort(key=lambda x: x[0])
    return [Event(channel="Security", record_id=index, event_id=4625,
                  timestamp=(baseline.START + timedelta(seconds=seconds)).isoformat(),
                  provider="AdversarialSyntheticFixture", message="Synthetic 4625, not a real attack",
                  target_domain="LAB", target_username=user, source_ip=ip, logon_type=3)
            for index, (seconds, user, ip) in enumerate(items, 1)]


def evaluate(seeds: int, repetitions: int, base_seed: int, threshold: int,
             window: int) -> dict:
    if not all(x >= 1 for x in (seeds, repetitions, threshold, window)):
        raise ValueError("All numeric parameters must be positive")
    results = {}
    for policy in baseline.POLICIES:
        seed_scores = []
        by_case = {case: {"episodes": 0, "flagged": 0, "fp": 0, "fn": 0}
                   for case in CASES}
        for seed in range(base_seed, base_seed + seeds):
            truths, predictions = [], []
            for name, (label, _) in CASES.items():
                for rep in range(repetitions):
                    predicted = baseline.predict(policy, fixture(name, seed, rep), threshold, window)
                    truths.append(label)
                    predictions.append(predicted)
                    row = by_case[name]
                    row["episodes"] += 1
                    row["flagged"] += int(predicted)
                    row["fp"] += int(predicted and not label)
                    row["fn"] += int(label and not predicted)
            seed_scores.append(baseline.metric(truths, predictions))
        confusion = {key: sum(row[key] for row in seed_scores)
                     for key in ("tp", "fp", "fn", "tn")}
        stats = {}
        for key in ("precision", "recall", "f1"):
            vals = [row[key] for row in seed_scores if row[key] is not None]
            stats[key] = {"mean": statistics.mean(vals) if vals else None,
                          "sd": statistics.stdev(vals) if len(vals) >= 2 else 0.0}
        results[policy] = {"confusion": confusion, "seed_statistics": stats,
                           "scenarios": by_case}
    return {"disclaimer": "Synthetic counterexamples, not independent validation or production accuracy",
            "seeds": seeds, "repetitions": repetitions, "base_seed": base_seed,
            "threshold": threshold, "window_minutes": window,
            "cases": {key: {"label": pos, "description": description}
                      for key, (pos, description) in CASES.items()},
            "policies": results}


def markdown_report(data: dict) -> str:
    def fmt(score):
        return "N/A" if score["mean"] is None else f"{score['mean']:.3f} ± {score['sd']:.3f}"
    out = ["# SentinelForge — adversarial synthetic stress test", "",
           "**Not production accuracy.** All event traces and labels are constructed hypotheses.",
           "This dataset is deliberately difficult and must not replace the original benchmark.", "",
           f"Settings: {data['seeds']} seeds, {data['repetitions']} episodes/case/seed, "
           f"{data['window_minutes']}-minute window, threshold {data['threshold']}.", "",
           "| Policy | TP | FP | FN | TN | Precision (mean ± SD) | Recall (mean ± SD) | F1 (mean ± SD) |",
           "|---|---:|---:|---:|---:|---:|---:|---:|",]
    for name, payload in data["policies"].items():
        c, s = payload["confusion"], payload["seed_statistics"]
        out.append(f"| {name} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | "
                   f"{fmt(s['precision'])} | {fmt(s['recall'])} | {fmt(s['f1'])} |")
    out += ["", "## Error breakdown", "",
            "| Policy | Scenario | True label | Flagged | FP | FN |",
            "|---|---|---|---:|---:|---:|"]
    for name, payload in data["policies"].items():
        for case, row in payload["scenarios"].items():
            out.append(f"| {name} | {case} | "
                       f"{'attack' if data['cases'][case]['label'] else 'benign'} | "
                       f"{row['flagged']}/{row['episodes']} | {row['fp']} | {row['fn']} |")
    out += ["", "## Interpretation", "",
            "- Fast legitimate shared-NAT failures can resemble password spraying.",
            "- Slow spraying and distributed guessing can stay below short-window thresholds.",
            "- Repeated wrong service credentials and genuine password mistakes are ambiguous without authorization context.",
            "- Private IPs and missing source fields expose different attribution policy choices; no network addresses are contacted.",
            "- Benign source-IP rotation can resemble a distributed attack against one account.",
            "- Equal case prevalence and reused templates make the metrics **illustrative only**.",
            "- This evaluates `Detector.process()` and an offline prototype on synthetic events;"
            " it does not test `Store` persistence, Windows collection, or email delivery.",
            "", "## Research action", "",
            "Document false positives and false negatives; design a conservative risk-tiered advisory system",
            "with explicit unknown-source handling, authorization enrichment and persistent bounded history.",
            "Keep automatic blocking disabled. Collect independent real evidence before deployment.", ""]
    return "\n".join(out)


def verify(data: dict) -> None:
    # CI must confirm the benchmark *includes* the counterexamples and all outputs
    # are well-formed. It must NOT freeze known false-positive/negative rates.
    assert set(data["cases"]) == set(CASES)
    assert set(data["policies"]) == set(baseline.POLICIES)
    expected = data["seeds"] * data["repetitions"] * len(CASES)
    for payload in data["policies"].values():
        assert sum(payload["confusion"].values()) == expected
        for name, row in payload["scenarios"].items():
            assert row["episodes"] == data["seeds"] * data["repetitions"], name
            assert row["fp"] <= row["flagged"] <= row["episodes"], name
            assert row["fn"] <= row["episodes"] - row["flagged"], name


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--repetitions", type=int, default=8)
    parser.add_argument("--base-seed", type=int, default=20261220)
    parser.add_argument("--threshold", type=int, default=5)
    parser.add_argument("--window", type=int, default=10)
    parser.add_argument("--out", type=Path,
                        default=Path("evaluation/results/adversarial_logon"))
    parser.add_argument("--ci-check", action="store_true")
    args = parser.parse_args()
    if not (1 <= args.seeds <= 100 and 1 <= args.repetitions <= 100 and
            1 <= args.threshold <= 100 and 1 <= args.window <= 120):
        parser.error("Parameters out of range")
    report = evaluate(args.seeds, args.repetitions, args.base_seed, args.threshold, args.window)
    if args.ci_check:
        verify(report)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    (args.out / "results.md").write_text(markdown_report(report), encoding="utf-8")
    print(f"Synthetic adversarial episodes per policy: {args.seeds * args.repetitions * len(CASES)}")
    for name, value in report["policies"].items():
        c = value["confusion"]
        f1 = value["seed_statistics"]["f1"]["mean"]
        print(f"{name}: TP={c['tp']} FP={c['fp']} FN={c['fn']} TN={c['tn']} F1={f1:.3f}")
    print("Report:", (args.out / "results.md").resolve())


if __name__ == "__main__":
    main()

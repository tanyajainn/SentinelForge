"""Controlled synthetic 4625 benchmark: legacy, current and experimental policies.

No network access, OS event generation, account changes, or production writes.
Reproduce: python -m evaluation.contextual_benchmark --seeds 30 --repetitions 8
"""
from __future__ import annotations

import argparse
from collections import deque
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import random
import statistics

from sentinelforge.core import Detector, Event

SCENARIOS = (
    ("isolated_mistakes", False),
    ("shared_nat_benign", False),
    ("stale_service_credential", False),
    ("targeted_brute_force", True),
    ("password_spraying", True),
    ("distributed_brute_force", True),
)
POLICIES = ("legacy_channel", "current_source_ip", "experimental_contextual")
WINDOWS = (5, 10, 20)
THRESHOLDS = (3, 5, 8)
START = datetime(2026, 11, 20, 0, 0, tzinfo=timezone.utc)


def fixture(name: str, seed: int, iteration: int) -> list[Event]:
    """Emit event-accurate identity/source and timestamps for one labelled episode."""
    rng = random.Random(f"{seed}:{iteration}:{name}")
    entries = []
    if name == "isolated_mistakes":
        entries = [(rng.randrange(20, 120), "user_a", "8.8.8.8") for _ in range(rng.randint(0, 2))]
    elif name == "shared_nat_benign":
        # Different people behind one public NAT; 1 failure each, >60s apart.
        t = 0
        for i in range(16):
            entries.append((t, f"staff_{i:02}", "8.8.8.8"))
            t += rng.randint(70, 95)
    elif name == "stale_service_credential":
        # Authorized misconfiguration is still indistinguishable from brute force
        # when the only observations are event 4625, time, account and IP.
        t = 0
        for _ in range(rng.randint(8, 12)):
            entries.append((t, "svc_backup", "8.8.8.8"))
            t += rng.randint(20, 40)
    elif name == "targeted_brute_force":
        entries = [(rng.randint(0, 160), "user_a", "8.8.8.8") for _ in range(12)]
    elif name == "password_spraying":
        for i in range(12):
            for _ in range(rng.randint(1, 2)):
                entries.append((rng.randint(0, 180), f"user_{i:02}", "8.8.8.8"))
    elif name == "distributed_brute_force":
        for i in range(12):
            for _ in range(rng.randint(1, 2)):
                entries.append((rng.randint(0, 180), "user_a", f"9.9.9.{i + 1}"))
    else:
        raise ValueError(f"Unknown scenario: {name}")
    entries.sort(key=lambda entry: entry[0])
    return [Event(channel="Security", record_id=j, event_id=4625,
                  timestamp=(START + timedelta(seconds=t)).isoformat(),
                  provider="SyntheticBenchmark", message="Synthetic 4625 only",
                  target_username=user, target_domain="LAB", source_ip=ip,
                  logon_type=3) for j, (t, user, ip) in enumerate(entries, 1)]


def predict(policy: str, events: list[Event], threshold: int, window_minutes: int) -> bool:
    """Binary episode outcome; instantiate state anew to avoid episode leakage."""
    if policy == "current_source_ip":
        detector = Detector(threshold=threshold, window_minutes=window_minutes)
        return any(bool(detector.process(event)) for event in events)

    if policy == "legacy_channel":
        q = deque()
        window = timedelta(minutes=window_minutes)
        for event in events:
            now = datetime.fromisoformat(event.timestamp)
            q.append(now)
            while q and now - q[0] > window:
                q.popleft()
            if len(q) >= threshold:
                return True
        return False

    if policy != "experimental_contextual":
        raise ValueError(f"Unknown policy: {policy}")
    # OFFLINE RESEARCH PROTOTYPE; it is NOT deployed by SentinelForge.
    # A pair burst, rapid cross-account spraying from one IP, or rapid
    # cross-source failures against one account can trigger a finding.
    pair_history, ip_history, account_history = {}, {}, {}
    window = timedelta(minutes=window_minutes)
    fast_window = timedelta(minutes=min(4, window_minutes))
    diversity_min = max(5, threshold)
    for event in events:
        now = datetime.fromisoformat(event.timestamp)
        user = f"{event.target_domain}\\{event.target_username}".casefold()
        ip = event.source_ip
        pair = pair_history.setdefault((ip, user), deque())
        ip_q = ip_history.setdefault(ip, deque())
        account_q = account_history.setdefault(user, deque())
        pair.append(now)
        ip_q.append((now, user))
        account_q.append((now, ip))
        while pair and now - pair[0] > window:
            pair.popleft()
        while ip_q and now - ip_q[0][0] > fast_window:
            ip_q.popleft()
        while account_q and now - account_q[0][0] > fast_window:
            account_q.popleft()
        if len(pair) >= threshold:
            return True
        if len({account for _, account in ip_q}) >= diversity_min:
            return True
        if len({source for _, source in account_q}) >= diversity_min:
            return True
    return False


def metric(labels: list[bool], predictions: list[bool]) -> dict:
    tp = sum(y and p for y, p in zip(labels, predictions, strict=True))
    fp = sum(not y and p for y, p in zip(labels, predictions, strict=True))
    fn = sum(y and not p for y, p in zip(labels, predictions, strict=True))
    tn = len(labels) - tp - fp - fn
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": tp / (tp + fp) if tp + fp else None,
            "recall": tp / (tp + fn) if tp + fn else None,
            "f1": 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None}


def evaluate(seed_count: int, repetitions: int, base_seed: int) -> dict:
    experiments = []
    for window in WINDOWS:
        for threshold in THRESHOLDS:
            for policy in POLICIES:
                per_seed = []
                breakdown = {name: {"episodes": 0, "flagged": 0, "fp": 0, "fn": 0}
                             for name, _ in SCENARIOS}
                for seed in range(base_seed, base_seed + seed_count):
                    labels, predictions = [], []
                    for name, label in SCENARIOS:
                        for iteration in range(repetitions):
                            result = predict(policy, fixture(name, seed, iteration), threshold, window)
                            labels.append(label)
                            predictions.append(result)
                            scenario = breakdown[name]
                            scenario["episodes"] += 1
                            scenario["flagged"] += int(result)
                            scenario["fp"] += int(result and not label)
                            scenario["fn"] += int(not result and label)
                    per_seed.append(metric(labels, predictions))
                # Sum the confusion matrices, then calculate micro-averaged scores.
                tp = sum(x["tp"] for x in per_seed)
                fp = sum(x["fp"] for x in per_seed)
                fn = sum(x["fn"] for x in per_seed)
                tn = sum(x["tn"] for x in per_seed)
                prec = tp / (tp + fp) if tp + fp else None
                recall = tp / (tp + fn) if tp + fn else None
                f1 = 2 * tp / (2 * tp + fp + fn) if 2 * tp + fp + fn else None
                aggregate = dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=prec, recall=recall, f1=f1)
                stats = {}
                for name in ("precision", "recall", "f1"):
                    values = [m[name] for m in per_seed if m[name] is not None]
                    stats[name] = {"mean": statistics.mean(values) if values else None,
                                   "sd": statistics.stdev(values) if len(values) > 1 else 0.0}
                experiments.append(dict(policy=policy, window_minutes=window,
                                        threshold=threshold, aggregate=aggregate,
                                        per_seed_stats=stats, scenario_breakdown=breakdown,
                                        per_seed=per_seed))
    return {"design": "Synthetic labelled episode benchmark; never production accuracy",
            "seed_count": seed_count, "base_seed": base_seed,
            "repetitions_per_scenario_per_seed": repetitions,
            "scenarios": [{"name": n, "positive": p} for n, p in SCENARIOS],
            "windows_minutes": WINDOWS, "thresholds": THRESHOLDS,
            "policies": POLICIES, "experiments": experiments}


def markdown_report(report: dict) -> str:
    lines = ["# SentinelForge contextual 4625 research benchmark", "",
             "All results below are **synthetic**. Labels are generator assumptions,",
             "not independently validated attacks. The experimental policy is **not deployed**.", "",
             f"Seeds: {report['seed_count']}; repetitions per scenario per seed: "
             f"{report['repetitions_per_scenario_per_seed']}.", "",
             "| Window | Threshold | Policy | TP | FP | FN | TN | Precision (mean ± SD) | Recall (mean ± SD) | F1 (mean ± SD) |",
             "|---:|---:|---|---:|---:|---:|---:|---:|---:|---:|"]
    for item in report["experiments"]:
        m = item["aggregate"]
        def fmt(name):
            s = item["per_seed_stats"][name]
            return "N/A" if s["mean"] is None else f"{s['mean']:.3f} ± {s['sd']:.3f}"
        lines.append(f"| {item['window_minutes']} | {item['threshold']} | {item['policy']} | "
                     f"{m['tp']} | {m['fp']} | {m['fn']} | {m['tn']} | "
                     f"{fmt('precision')} | {fmt('recall')} | {fmt('f1')} |")
    lines += ["", "## Scenario-level results (10 min, threshold 5)", "",
              "| Policy | Scenario | Episodes | Flagged | FP | FN |",
              "|---|---|---:|---:|---:|---:|"]
    for item in report["experiments"]:
        if item["window_minutes"] != 10 or item["threshold"] != 5:
            continue
        for name, v in item["scenario_breakdown"].items():
            lines.append(f"| {item['policy']} | {name} | {v['episodes']} | "
                         f"{v['flagged']} | {v['fp']} | {v['fn']} |")
    lines += ["", "## Interpretation and threats to validity", "",
              "- The **legacy** column reproduces a historical channel-wide sliding window as a comparison; it is not the current deployed implementation.",
              "- **Current source-IP** runs the actual `Detector.process()` for synthetic events with public IP addresses. Its grouping can confuse many users behind one NAT and miss one user attacked from many addresses.",
              "- **Experimental contextual** is a research-only policy: same-IP/same-account bursts; many accounts from one IP within four minutes; or many IPs against one account within four minutes. No production detector or SQLite schema was changed by this experiment.",
              "- The shared-NAT fixture is deliberately slow and the spraying fixture deliberately rapid; timing makes these synthetic classes separable, but real attackers can go slowly and benign systems can fail quickly.",
              "- The stale-service fixture remains a likely false positive because authorization state is invisible in event 4625. No model can reliably identify intent from only username, IP and time.",
              "- Seeded variations are repeated samples of **the same synthetic generator**, not 30 independent organizations or an empirical confidence interval. Seed SD does not imply generalization.",
              "- Scoring uses one binary decision per episode. It does not measure alert volume, event capture, end-to-end latency, SMTP delivery or deployed detector restart persistence.",
              "- Scenario prevalence is balanced by design, so synthetic precision does not estimate operational precision. Avoid treating higher F1 as a justification for silent production policy changes.",
              "", "## Reproduce", "",
              "```powershell", "python -m evaluation.contextual_benchmark --seeds 30 --repetitions 8 --out evaluation/results/contextual_benchmark", "```", "",
              "Use the same windows, thresholds and seeds to compare policies. Keep the test corpus fixed when changing detector code.", ""]
    return "\n".join(lines)


def verify_guardrails(report: dict) -> None:
    # Only fixture-specific research contracts. They are *not* production accuracy requirements.
    for item in report["experiments"]:
        if item["policy"] != "experimental_contextual":
            continue
        rows = item["scenario_breakdown"]
        for scenario in ("password_spraying", "distributed_brute_force", "targeted_brute_force"):
            assert rows[scenario]["flagged"] == rows[scenario]["episodes"], (item, scenario)
        assert rows["shared_nat_benign"]["fp"] == 0, item


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=30)
    parser.add_argument("--repetitions", type=int, default=8)
    parser.add_argument("--base-seed", type=int, default=20261120)
    parser.add_argument("--out", type=Path, default=Path("evaluation/results/contextual_benchmark"))
    parser.add_argument("--ci-check", action="store_true")
    args = parser.parse_args()
    if not 1 <= args.seeds <= 100 or not 1 <= args.repetitions <= 100:
        parser.error("seeds and repetitions must be 1–100")
    result = evaluate(args.seeds, args.repetitions, args.base_seed)
    if args.ci_check:
        verify_guardrails(result)
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / "results.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    (args.out / "results.md").write_text(markdown_report(result), encoding="utf-8")
    print(f"Synthetic episodes per policy/configuration: {args.seeds * args.repetitions * len(SCENARIOS)}")
    for item in result["experiments"]:
        if item["window_minutes"] == 10 and item["threshold"] == 5:
            m = item["aggregate"]
            print(f"{item['policy']}: TP={m['tp']} FP={m['fp']} FN={m['fn']} "
                  f"TN={m['tn']} F1={m['f1']:.3f}")
    print("Report:", (args.out / "results.md").resolve())


if __name__ == "__main__":
    main()

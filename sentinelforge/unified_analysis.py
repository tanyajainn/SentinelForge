"""SentinelForge v2: offline, explainable multi-signal security analysis.

Input: JSONL telemetry supplied by an authorized test environment.
No collection, firewall, quarantine, or notification side effects.
"""
from __future__ import annotations

import argparse
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class Finding:
    category: str
    severity: str
    score: int
    reasons: list[str]
    recommended_action: str


def analyze(event: dict) -> Finding | None:
    kind = event.get("type")
    reasons = []
    score = 0
    category = ""

    if kind == "authentication":
        category = "authentication"
        failures = max(0, int(event.get("failures", 0)))
        distinct_accounts = max(0, int(event.get("distinct_accounts", 1)))
        remote = event.get("logon_type") == 10
        known_service = event.get("known_service_account") is True
        successful_login = event.get("success_after_failures") is True

        if failures >= 20:
            score += 35
            reasons.append("20+ failed authentication attempts")
        elif failures >= 10:
            score += 25
            reasons.append("10+ failed authentication attempts")
        elif failures >= 5:
            score += 15
            reasons.append("5+ failed authentication attempts")

        if distinct_accounts >= 5:
            score += 35
            reasons.append("Failures across multiple accounts")

        if remote:
            score += 15
            reasons.append("Remote interactive authentication")

        if known_service:
            score -= 25
            reasons.append("Known service account: possible stale credentials")

        if successful_login and not known_service:
            score += 20
            reasons.append("Successful login following failures; investigate")

    elif kind == "process":
        category = "process"
        parent = str(event.get("parent", "")).lower()
        name = str(event.get("name", "")).lower()
        command = str(event.get("command_line", "")).lower()

        office = {"winword.exe", "excel.exe", "powerpnt.exe"}
        shells = {"powershell.exe", "pwsh.exe", "cmd.exe"}

        if parent in office and name in shells:
            score += 65
            reasons.append("Office application launched a command shell")

        if name in {"powershell.exe", "pwsh.exe"}:
            if "-enc " in command or "-encodedcommand" in command:
                score += 30
                reasons.append("Encoded PowerShell command indicator")

        if event.get("unsigned_binary") is True:
            score += 15
            reasons.append("Binary reported as unsigned")

    elif kind == "defender":
        category = "defender"
        event_id = int(event.get("event_id", 0))

        scores = {
            1116: (85, "Microsoft Defender malware detection"),
            1117: (35, "Microsoft Defender remediation event"),
            1118: (90, "Microsoft Defender remediation failure"),
            5001: (90, "Defender real-time protection disabled"),
            5007: (25, "Defender configuration changed"),
            5013: (70, "Defender blocked a settings change"),
        }

        if event_id in scores:
            score, reason = scores[event_id]
            reasons.append(reason)

    elif kind == "network":
        category = "network"

        # The caller must supply independently collected network metadata.
        outbound_mb = max(0, float(event.get("outbound_mb", 0)))
        baseline_mb = max(0, float(event.get("baseline_mb", 0)))

        if baseline_mb > 0 and outbound_mb > baseline_mb * 10:
            score += 45
            reasons.append("Outbound volume exceeds baseline by 10x")

        if event.get("new_destination") is True:
            score += 20
            reasons.append("Previously unseen destination")

        if event.get("sensitive_process") is True:
            score += 20
            reasons.append("Sensitive process associated with network activity")

    else:
        return None

    score = max(0, min(100, score))

    # Do not emit alerts for weak, isolated indicators.
    if score < 40:
        return None

    severity = "high" if score >= 70 else "medium"

    return Finding(
        category=category,
        severity=severity,
        score=score,
        reasons=reasons,
        recommended_action=(
            "Verify the evidence and investigate the affected host. "
            "Do not automatically block, quarantine, or delete."
        ),
    )



def analyze_authentication_with_fallback(event: dict, threshold: int = 5):
    """Preserve legacy threshold detection when enrichment is unavailable.

    Input must represent failures within the configured observation window.
    This is an offline compatibility policy, not a new live detector.
    """
    if event.get("type") != "authentication":
        return analyze(event)

    finding = analyze(event)
    if finding is not None:
        return finding

    if not isinstance(event.get("failures"), int):
        return None

    failures = event["failures"]
    if failures < threshold:
        return None

    # Missing enrichment cannot justify suppressing an existing alert.
    return Finding(
        category="authentication",
        severity="medium",
        score=40,
        reasons=[
            f"{failures} failed logins meet legacy threshold {threshold}",
            "Additional context is insufficient to establish malicious intent",
        ],
        recommended_action=(
            "Investigate authentication history and account context. "
            "Do not automatically block."
        ),
    )

def evaluate_ml(path: Path):
    """Optional experimental classifier, never used for live response."""
    try:
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.metrics import precision_score, recall_score, f1_score
        from sklearn.model_selection import GroupShuffleSplit
    except ImportError:
        print("ML skipped: install scikit-learn to evaluate a classifier")
        return

    rows = [
        json.loads(line)
        for line in path.read_text(encoding="utf-8-sig").splitlines()
        if line.strip()
    ]

    required = {"failures", "distinct_accounts", "logon_type",
                "known_service_account", "label", "group"}

    if len(rows) < 40 or any(not required <= row.keys() for row in rows):
        print("ML skipped: need 40+ labeled rows with required fields")
        return

    x = [
        [
            float(row["failures"]),
            float(row["distinct_accounts"]),
            float(row["logon_type"]),
            int(bool(row["known_service_account"])),
        ]
        for row in rows
    ]
    y = [int(row["label"]) for row in rows]
    groups = [str(row["group"]) for row in rows]

    if len(set(groups)) < 4:
        print("ML skipped: insufficient independent groups")
        return

    train, test = next(
        GroupShuffleSplit(
            n_splits=1, test_size=0.25, random_state=42
        ).split(x, y, groups)
    )

    if len(set(y[i] for i in train)) < 2:
        print("ML skipped: training split lacks both classes")
        return

    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=5,
        random_state=42,
        class_weight="balanced",
    )
    model.fit([x[i] for i in train], [y[i] for i in train])

    truth = [y[i] for i in test]
    predicted = model.predict([x[i] for i in test])

    print("EXPERIMENTAL ML RESULTS")
    print("Precision:", round(precision_score(
        truth, predicted, zero_division=0
    ), 4))
    print("Recall:", round(recall_score(
        truth, predicted, zero_division=0
    ), 4))
    print("F1:", round(f1_score(
        truth, predicted, zero_division=0
    ), 4))
    print("Test samples:", len(test))
    print("No model deployed or saved.")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path)
    parser.add_argument("--ml-data", type=Path)
    args = parser.parse_args()

    if not args.input and not args.ml_data:
        parser.error("Specify --input or --ml-data")

    if args.input:
        findings = []
        for line_number, line in enumerate(
            args.input.read_text(encoding="utf-8-sig").splitlines(), 1
        ):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("Expected JSON object")
                result = analyze(event)
                if result:
                    findings.append(asdict(result))
            except (ValueError, TypeError) as exc:
                raise SystemExit(
                    f"Invalid input at line {line_number}: {exc}"
                )

        print(json.dumps({
            "findings": findings,
            "count": len(findings),
            "categories": dict(Counter(
                item["category"] for item in findings
            )),
            "mode": "offline_analysis_only",
        }, indent=2))

    if args.ml_data:
        evaluate_ml(args.ml_data)


if __name__ == "__main__":
    main()

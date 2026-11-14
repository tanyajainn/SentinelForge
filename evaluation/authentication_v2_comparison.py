"""Compare v1 and context-aware v2 on the same synthetic episodes.

The existing corpus contains no source IP, account identity or service
verification. Missing fields remain missing; labels are not used as features.
"""
import json
from pathlib import Path

from sentinelforge.authentication_v2 import analyze_episode
from sentinelforge.core import Detector, Event


SOURCE = Path("evaluation/results/detection_accuracy.json")
OUTPUT = Path("evaluation/results/authentication_v2_comparison.json")


def metrics(labels, predictions):
    tp = sum(a and p for a, p in zip(labels, predictions))
    fp = sum(not a and p for a, p in zip(labels, predictions))
    fn = sum(a and not p for a, p in zip(labels, predictions))
    tn = sum(not a and not p for a, p in zip(labels, predictions))

    precision = tp / (tp + fp) if tp + fp else None
    recall = tp / (tp + fn) if tp + fn else None

    return {
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "precision": precision,
        "recall": recall,
        "f1": (
            2 * tp / (2 * tp + fp + fn)
            if 2 * tp + fp + fn else None
        ),
    }


def main():
    data = json.loads(SOURCE.read_text(encoding="utf-8-sig"))
    labels = []
    old_predictions = []
    new_predictions = []
    details = []

    for episode in data["episodes"]:
        seconds = episode["seconds"]
        actual = bool(episode["positive"])

        events = [
            {
                "event_id": 4625,
                "timestamp": (
                    __import__("datetime").datetime(
                        2026, 1, 1,
                        tzinfo=__import__("datetime").timezone.utc
                    )
                    + __import__("datetime").timedelta(seconds=t)
                ).isoformat(),
                "source_ip": None,
                "target_username": None,
                "logon_type": None,
            }
            for t in seconds
        ]

        # Run the original v1 detector with its default threshold/window.
        old = Detector()
        old_hit = False

        for i, event in enumerate(events, 1):
            original = Event(
                channel="Security",
                record_id=i,
                event_id=4625,
                timestamp=event["timestamp"],
                provider="benchmark",
                message="Synthetic failed logon",
            )
            if old.process(original):
                old_hit = True

        new_hit = bool(analyze_episode(events))

        labels.append(actual)
        old_predictions.append(old_hit)
        new_predictions.append(new_hit)

        details.append({
            "scenario": episode["scenario"],
            "actual": actual,
            "v1": old_hit,
            "v2": new_hit,
            "failure_count": len(seconds),
        })

    report = {
        "dataset": str(SOURCE),
        "episodes": len(labels),
        "limitations": [
            "Synthetic authentication scenarios",
            "No real account or source-IP attribution",
            "No verified service-account metadata",
            "V2 is an offline prototype, not the installed agent",
            "Not independent real-world validation",
        ],
        "v1": metrics(labels, old_predictions),
        "v2": metrics(labels, new_predictions),
        "details": details,
    }

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_text(
        json.dumps(report, indent=2) + "\n",
        encoding="utf-8",
    )

    print("\n=== SENTINELFORGE V1 VS V2 ===")
    for name in ("v1", "v2"):
        result = report[name]
        print(
            f"{name.upper()}: "
            f"TP={result['tp']} FP={result['fp']} "
            f"TN={result['tn']} FN={result['fn']} "
            f"Precision={result['precision']} "
            f"Recall={result['recall']} "
            f"F1={result['f1']}"
        )

    print("\nReport:", OUTPUT)
    print("90% precision is a target, not a guaranteed result.")


if __name__ == "__main__":
    main()

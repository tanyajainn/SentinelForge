"""SentinelForge v0.95: reproducible synthetic benchmark audit.

Does not alter detection policy, monitoring, SMTP, or local databases.
Run: python -m evaluation.release_audit --out reports/release-audit
"""
import argparse
import html
import json
import statistics
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from evaluation import logon_benchmark as base

THRESHOLDS = (3, 5, 8)


def evaluate_one(seed, repetitions):
    # Train and holdout deliberately use disjoint random seeds. The threshold
    # is selected on training alone and not tuned using holdout labels.
    training = base.corpus(seed, repetitions)
    holdout = base.corpus(seed + 1, repetitions)
    calibrations = {t: base.score(training, t) for t in THRESHOLDS}
    chosen = max(THRESHOLDS, key=lambda t: (
        calibrations[t]['f1'], -calibrations[t]['fp'], t))
    predictions = [bool(base.continuous(base.records(times), chosen))
                   for _, _, times in holdout]
    labels = [label for _, label, _ in holdout]
    metrics = base.metrics(labels, predictions)
    rows = []
    for (scenario, positive, times), predicted in zip(holdout, predictions, strict=True):
        rows.append({'scenario': scenario, 'label': positive,
                     'predicted': predicted, 'failed_logons': len(times)})
    return {'seed': seed, 'chosen_threshold': chosen, 'metrics': metrics,
            'episodes': rows, 'calibration': calibrations}


def summarize(runs):
    if not runs:
        raise ValueError('At least one evaluation run is required')
    merged = [episode for run in runs for episode in run['episodes']]
    scenario = defaultdict(list)
    for entry in merged:
        scenario[entry['scenario']].append(entry)
    breakdown = {}
    for name, entries in sorted(scenario.items()):
        positives = sum(x['label'] for x in entries)
        predicted = sum(x['predicted'] for x in entries)
        incorrect = sum(x['label'] != x['predicted'] for x in entries)
        breakdown[name] = {'episodes': len(entries), 'positive': positives,
                           'flagged': predicted, 'errors': incorrect,
                           'false_positives': sum(not x['label'] and x['predicted'] for x in entries),
                           'false_negatives': sum(x['label'] and not x['predicted'] for x in entries)}
    labels = [x['label'] for x in merged]
    predictions = [x['predicted'] for x in merged]
    f1s = [run['metrics']['f1'] for run in runs]
    p = [run['metrics']['precision'] for run in runs]
    r = [run['metrics']['recall'] for run in runs]
    aggregate = base.metrics(labels, predictions)
    return {'runs': len(runs), 'aggregate': aggregate,
            'seed_f1_min': min(f1s), 'seed_f1_max': max(f1s),
            'seed_f1_mean': statistics.mean(f1s),
            'seed_precision_min': min(x for x in p if x is not None),
            'seed_recall_min': min(x for x in r if x is not None),
            'scenario_breakdown': breakdown,
            'selected_thresholds': {str(t): sum(run['chosen_threshold'] == t for run in runs)
                                    for t in THRESHOLDS}}


def render(result):
    summary = result['summary']
    cells = ''.join(
        '<tr>' + ''.join('<td>' + html.escape(str(value)) + '</td>' for value in
          [key, v['episodes'], v['flagged'], v['false_positives'], v['false_negatives']]) + '</tr>'
        for key, v in summary['scenario_breakdown'].items())
    m = summary['aggregate']
    def pct(v):
        return 'N/A' if v is None else f'{v * 100:.1f}%'
    return f'''<!doctype html><html lang="en"><meta charset="utf-8">
<title>SentinelForge | Detection Evaluation</title>
<style>body{{background:#0c1320;color:#eef4ff;font:16px/1.6 system-ui;margin:0}}
main{{max-width:1020px;margin:auto;padding:44px 22px}}
small,p{{color:#acbed3}}h1{{font-size:2.2rem}}h2{{margin-top:36px}}
.cards{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px}}
.card{{background:#152237;border:1px solid #29405a;border-radius:15px;padding:20px}}
.card strong{{display:block;font-size:1.7rem;color:#69e6bc}}
table{{width:100%;border-collapse:collapse}}th,td{{padding:12px;text-align:left;border-bottom:1px solid #35475b}}
.wrap{{overflow:auto}}.note{{border-left:3px solid #f2bc74;padding:12px 18px;background:#192337}}
@media print{{body{{background:#fff;color:#152237}}small,p{{color:#455667}}.card{{background:#f0f3f7}}}}
</style><main><small>RESEARCH / PORTFOLIO EVALUATION — SYNTHETIC FIXTURES</small>
<h1>SentinelForge: Detection Evidence</h1><p>Generated {html.escape(result['generated_utc'])} · {summary['runs']} independent synthetic seed pairs</p>
<div class="cards"><div class="card"><small>Aggregate precision</small><strong>{pct(m['precision'])}</strong></div>
<div class="card"><small>Aggregate recall</small><strong>{pct(m['recall'])}</strong></div>
<div class="card"><small>Aggregate F1</small><strong>{m['f1']:.3f}</strong></div>
<div class="card"><small>False positives</small><strong>{m['fp']}</strong></div></div>
<h2>Per-scenario error analysis</h2><div class="wrap"><table><thead><tr>
<th>Scenario</th><th>Episodes</th><th>Flagged</th><th>False positives</th><th>False negatives</th></tr></thead>
<tbody>{cells}</tbody></table></div>
<h2>Seed variation</h2><p>F1 across seeds: {summary['seed_f1_min']:.3f}–{summary['seed_f1_max']:.3f};
minimum precision {pct(summary['seed_precision_min'])}; minimum recall {pct(summary['seed_recall_min'])}.</p>
<div class="note"><strong>Do not interpret as production accuracy.</strong>
The six scenarios are synthetic; labels reflect generator assumptions. Random seeds create new
samples of the same generator, not independently sourced real activity. No logon source,
account identity or logon type is present in this benchmark. Precision on live traffic may
be markedly different. A healthy detector does not guarantee an endpoint is safe.</div>
<h2>Release recommendation</h2><p>Keep the existing production threshold unchanged.
Gather authorized labeled Windows activity across different users/devices and split by device/time.
Improve source/account-aware correlation, then validate with a sealed independent test set.
Do not automate blocking from this synthetic evaluation.</p></main></html>'''


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seed', type=int, default=20261111)
    parser.add_argument('--runs', type=int, default=8)
    parser.add_argument('--repetitions', type=int, default=12)
    parser.add_argument('--out', type=Path, default=Path('reports/release-audit'))
    args = parser.parse_args()
    if not 1 <= args.runs <= 100 or not 1 <= args.repetitions <= 1000:
        parser.error('Runs must be 1–100 and repetitions 1–1000')
    # 2 per run ensures no overlap of (train, holdout) seeds between runs.
    runs = [evaluate_one(args.seed + 2 * i, args.repetitions)
            for i in range(args.runs)]
    result = {'generated_utc': datetime.now(timezone.utc).isoformat(),
              'method': 'Synthetic scenario benchmark; per-run threshold calibration only',
              'summary': summarize(runs), 'individual_runs': runs}
    args.out.mkdir(parents=True, exist_ok=True)
    (args.out / 'evaluation.json').write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    (args.out / 'evaluation.html').write_text(render(result), encoding='utf-8')
    m = result['summary']['aggregate']
    print(f"Synthetic episodes: {sum(len(x['episodes']) for x in runs)} | Seeds: {args.runs}")
    print(f"TP={m['tp']} FP={m['fp']} FN={m['fn']} TN={m['tn']} | "
          f"Precision={m['precision']:.3f} Recall={m['recall']:.3f} F1={m['f1']:.3f}")
    print('Report:', (args.out / 'evaluation.html').resolve())


if __name__ == '__main__':
    main()

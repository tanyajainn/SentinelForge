"""Read-only unified SentinelForge development supervisor.

Keeps original installed security monitor untouched. Runs existing research
runtime and legacy bridge as subprocesses, supervises exit/restart, and writes
structured health snapshots. Does not deliver notifications or modify firewall.
"""
from __future__ import annotations
import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


def utcnow():
    return datetime.now(timezone.utc).isoformat()


def commands(python, source, evidence, interval):
    return {
        'sensor': [python, '-m', 'sentinelforge.unified_runtime', '--duration', '0', '--interval', str(interval)],
        'bridge': [python, '-m', 'sentinelforge.continuous_bridge', '--source', source, '--destination', evidence, '--interval', str(max(2, interval))],
    }


def write_health(path, status):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + '.tmp')
    temporary.write_text(json.dumps(status, indent=2), encoding='utf-8')
    os.replace(temporary, path)


def run(args):
    source = Path(args.source).resolve()
    if not source.is_file():
        raise FileNotFoundError(f'Legacy security database missing: {source}')
    evidence = Path(args.evidence).resolve()
    evidence.parent.mkdir(parents=True, exist_ok=True)
    health = Path(args.health).resolve()
    if args.interval < 2 or args.duration < 0:
        raise ValueError('interval must be >=2 and duration >=0')
    python = sys.executable
    specs = commands(python, str(source), str(evidence), args.interval)
    processes = {}
    restarts = {key: 0 for key in specs}
    stopped = False
    def stop(*_):
        nonlocal stopped
        stopped = True
    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    start = time.monotonic()
    # A finite-duration run is suitable for smoke tests. 0 means run until stopped.
    try:
        while not stopped and (args.duration == 0 or time.monotonic() - start < args.duration):
            for key, command in specs.items():
                proc = processes.get(key)
                if proc is None or proc.poll() is not None:
                    if proc is not None:
                        restarts[key] += 1
                        if restarts[key] > args.max_restarts:
                            raise RuntimeError(f'{key} exceeded restart budget')
                    processes[key] = subprocess.Popen(command, cwd=str(Path(args.repo).resolve()),
                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                        creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            write_health(health, {
                'timestamp': utcnow(), 'mode': 'read_only_research',
                'components': {key: {'pid': proc.pid, 'running': proc.poll() is None,
                                    'restarts': restarts[key]} for key, proc in processes.items()},
                'original_security_monitor': 'unchanged',
                'macos_native_support': 'not_validated',
            })
            time.sleep(min(1, args.interval))
    finally:
        for proc in processes.values():
            if proc.poll() is None:
                proc.terminate()
        for proc in processes.values():
            try:
                proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
        write_health(health, {'timestamp': utcnow(), 'status': 'stopped',
                              'original_security_monitor': 'unchanged'})


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--repo', default='.')
    parser.add_argument('--source', required=True)
    parser.add_argument('--evidence', required=True)
    parser.add_argument('--health', required=True)
    parser.add_argument('--interval', type=int, default=15)
    parser.add_argument('--duration', type=int, default=20)
    parser.add_argument('--max-restarts', type=int, default=3)
    args = parser.parse_args()
    run(args)


if __name__ == '__main__':
    main()

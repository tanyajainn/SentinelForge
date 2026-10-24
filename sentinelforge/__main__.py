from __future__ import annotations
import argparse
import json
import os
import platform
import sys
import time
import getpass
import shutil
import subprocess
import traceback
import contextlib
from datetime import datetime, timezone
from dataclasses import asdict
from pathlib import Path
from .core import Store, Detector, Event, Alert
from .windows import CHANNELS, fetch
from .notify import notify_ntfy
from .channels import enabled_channels, check_config, send


def deliver(store, url, token, max_deliveries=25):
    if not url:
        return
    for alert_id, alert in store.pending(max_deliveries):
        try:
            notify_ntfy(alert, url, token)
            store.delivery_result(alert_id)
            print(f'NOTIFIED alert #{alert_id}', flush=True)
        except Exception as exc:
            store.delivery_result(alert_id, str(exc)[:400])
            print(f'NOTIFICATION FAILED alert #{alert_id}: {exc}', file=sys.stderr, flush=True)
            break  # avoid hammering the endpoint during an outage


def scan(store, detector, max_events, quiet=False):
    failed = []
    count = 0
    for channel in CHANNELS:
        cursor = store.cursor(channel)
        try:
            events = fetch(channel, cursor, max_events=max_events)
        except Exception as exc:
            failed.append(channel)
            print(f'ERROR {channel}: {exc}', file=sys.stderr, flush=True)
            continue
        if len(events) == max_events:
            print(f'INFO {channel}: reached {max_events} event cap; remaining matching events will be read in subsequent scans', file=sys.stderr)
        for ev in events:
            for alert in detector.process(ev):
                store.save_alert(alert)
                count += 1
                if not quiet:
                    print(json.dumps(asdict(alert)), flush=True)
            store.advance(channel, ev.record_id)
    return count, failed


def config_path():
    return Path.home() / 'SentinelForgeData' / 'notifications.json'

def load_config():
    path=config_path()
    return json.loads(path.read_text(encoding='utf-8')) if path.exists() else None


TASK_NAME = 'SentinelForge Security Monitor'
SERVICE = 'SentinelForge-Gmail'


def _powershell(script):
    result = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                            capture_output=True, text=True, timeout=45,
                            creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout).strip() or 'Windows Task Scheduler failed')
    return result.stdout.strip()


def _task_command(command):
    name = TASK_NAME.replace("'", "''")
    return _powershell(f"{command} -TaskName '{name}' -ErrorAction Stop")


def load_gmail_credentials(config):
    """Populate sender credentials for both the interactive CLI and background agent."""
    if not config or config.get('mode') != 'email':
        return False
    sender = config.get('gmail_from', '').strip()
    if not sender:
        return False
    try:
        import keyring
        password = keyring.get_password(SERVICE, sender)
    except Exception as exc:
        print(f'Gmail credential lookup failed: {type(exc).__name__}', file=sys.stderr, flush=True)
        return False
    if not password:
        os.environ.pop('SENTINELFORGE_GMAIL_FROM', None)
        os.environ.pop('SENTINELFORGE_GMAIL_APP_PASSWORD', None)
        return False
    os.environ['SENTINELFORGE_GMAIL_FROM'] = sender
    os.environ['SENTINELFORGE_GMAIL_APP_PASSWORD'] = password
    return True


def setup():
    if os.name != 'nt':
        raise SystemExit('Setup requires Windows.')
    if not getattr(sys, 'frozen', False):
        raise SystemExit('Portable setup requires the packaged SentinelForge.exe and SentinelForgeAgent.exe.')
    source = Path(sys.executable).resolve()
    agent_source = source.with_name('SentinelForgeAgent.exe')
    if not agent_source.is_file():
        raise SystemExit('SentinelForgeAgent.exe is missing. Extract both executables from the release ZIP.')
    import keyring
    print('SentinelForge first-time setup (Windows user account)')
    recipient = input('Security alert recipient email: ').strip()
    sender = input('Sending Gmail address: ').strip()
    if not recipient or '@' not in recipient or not sender.lower().endswith('@gmail.com'):
        raise SystemExit('A valid recipient and Gmail sender are required.')
    password = getpass.getpass('Gmail App Password (hidden; stored in Windows Credential Manager): ').replace(' ', '')
    if not password:
        raise SystemExit('Gmail App Password is required.')
    keyring.set_password(SERVICE, sender, password)
    # Never save or print the password; the agent retrieves it under the same Windows account.
    data = config_path().parent
    data.mkdir(parents=True, exist_ok=True)
    config_path().write_text(json.dumps({'mode': 'email', 'email_to': recipient,
                                        'gmail_from': sender}, indent=2), encoding='utf-8')
    target = Path(os.environ['LOCALAPPDATA']) / 'SentinelForge' / 'bin'
    target.mkdir(parents=True, exist_ok=True)
    installed_exe = target / 'SentinelForge.exe'
    installed_agent = target / 'SentinelForgeAgent.exe'
    if source != installed_exe.resolve():
        shutil.copy2(source, installed_exe)
    if agent_source != installed_agent.resolve():
        shutil.copy2(agent_source, installed_agent)
    store = Store(str(data / 'events.sqlite3'))
    if not store.is_baselined():
        count = store.baseline()
        print(f'Historical alerts excluded from email (through #{count}).')
    store.db.close()
    # Register a user-scoped, persistent task without embedding any credentials.
    # Quoted paths are encoded as PowerShell single-quoted literals.
    exe_path = str(installed_agent).replace("'", "''")
    user = (os.environ.get('USERDOMAIN', '') + '\\' + os.environ.get('USERNAME', '')).replace("'", "''")
    task = TASK_NAME.replace("'", "''")
    script = f"""$ErrorActionPreference='Stop'
$action=New-ScheduledTaskAction -Execute '{exe_path}'
$trigger=New-ScheduledTaskTrigger -AtLogOn -User '{user}'
$settings=New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName '{task}' -Action $action -Trigger $trigger -Settings $settings -Description 'SentinelForge local Windows security monitoring' -Force | Out-Null
Start-ScheduledTask -TaskName '{task}'
"""
    try:
        _powershell(script)
    except Exception as exc:
        print('Configuration saved, but automatic startup could not be installed:', exc, file=sys.stderr)
        raise SystemExit(2)
    print('Installed successfully. Monitoring runs in the background at login.')
    print('Use SentinelForge.exe status to check operation.')


def agent():
    if os.name != 'nt':
        raise SystemExit('The agent requires Windows.')
    data = config_path().parent
    data.mkdir(parents=True, exist_ok=True)
    with (data / 'monitor.log').open('a', encoding='utf-8', buffering=1) as logfile:
        with contextlib.redirect_stdout(logfile), contextlib.redirect_stderr(logfile):
            print('SentinelForge background agent started', flush=True)
            detector = Detector(threshold=5)
            store = Store(str(data / 'events.sqlite3'))
            try:
                while True:
                    try:
                        config = load_config()
                        if config and not load_gmail_credentials(config):
                            print('Gmail credentials unavailable for this Windows user.', flush=True)
                        count, failed = scan(store, detector, 500, quiet=True)
                        # Delivery must not stop because an unrelated event-log channel is temporarily unavailable.
                        # Enqueued alerts and self-tests should still be retried.
                        if config:
                            deliver_channels(store, config)
                        print(f'Scan complete: {count} alerts, {len(failed)} inaccessible channels', flush=True)
                    except Exception:
                        traceback.print_exc()
                    time.sleep(10)
            finally:
                store.db.close()


def task_action(command):
    if os.name != 'nt':
        raise SystemExit('Task control requires Windows.')
    if command == 'start':
        _task_command('Start-ScheduledTask')
    elif command == 'stop':
        _task_command('Stop-ScheduledTask')
    elif command == 'uninstall':
        try:
            _task_command('Stop-ScheduledTask')
        except Exception:
            pass
        _task_command('Unregister-ScheduledTask -Confirm:$false')
        print('Background task removed. Security history and Gmail credentials preserved.')
        return
    print(f'Task {command} command completed.')


# SENTINELFORGE_SMTP_BACKOFF_V1
def deliver_channels(store, config, max_deliveries=25):
    """Deliver queued alerts with persistent SMTP retry protection."""
    import json
    import os
    import time
    from pathlib import Path

    if not config or not store.is_baselined():
        return

    try:
        check_config(config)
    except ValueError as exc:
        print("NOTIFICATIONS PAUSED:", exc, flush=True)
        return

    state_path = config_path().parent / "smtp_retry_state.json"

    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        state = {}

    now = time.time()
    if now < float(state.get("next_attempt", 0)):
        return

    def save_state(data):
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, state_path)

    for channel in enabled_channels(config):
        for alert_id, alert in store.channel_pending(channel, max_deliveries):
            try:
                send(channel, alert, config)
                store.channel_result(alert_id, channel)
                save_state({"failures": 0, "next_attempt": 0})
                state = {"failures": 0, "next_attempt": 0}
                print(f"NOTIFIED {channel} alert #{alert_id}", flush=True)

            except Exception as exc:
                error = str(exc)[:400]
                store.channel_result(alert_id, channel, error)

                failures = int(state.get("failures", 0)) + 1
                delay = min(14400, 300 * (2 ** min(failures - 1, 5)))

                # Gmail's temporary SMTP authentication lockout:
                # do not attempt login again for at least an hour.
                if ("454" in error or
                    "too many login attempts" in error.lower() or
                    "authentication" in error.lower()):
                    delay = max(delay, 3600)

                save_state({
                    "failures": failures,
                    "next_attempt": time.time() + delay
                })

                print(
                    f"EMAIL QUEUED alert #{alert_id}; "
                    f"SMTP retry paused for {delay // 60} minutes. "
                    f"Reason: {error}",
                    flush=True
                )
                return


def run_self_test(store, timeout=75, sleep=time.sleep, monotonic=time.monotonic):
    """Enqueue a benign alert and let the already-running agent deliver it.

    Intentionally does not call SMTP itself: confirms agent/database/SMTP integration.
    Never resets notification baseline or modifies Windows event log cursors.
    """
    config = load_config()
    if not config or config.get('mode') != 'email':
        raise RuntimeError('Email notifications are not configured. Run setup first.')
    if not store.is_baselined():
        raise RuntimeError('Historical notification baseline not set. Refusing test.')
    if not load_gmail_credentials(config):
        raise RuntimeError('Gmail App Password missing from Windows Credential Manager.')
    stamp = datetime.now(timezone.utc).isoformat()
    test_alert = Alert(
        rule='sentinelforge-self-test', severity='info',
        title='TEST ONLY - SentinelForge automatic delivery',
        timestamp=stamp,
        evidence=[dict(channel='SentinelForge Test', record_id=0,
                       event_id=0, timestamp=stamp, provider='SentinelForge',
                       message='Synthetic self-test; NOT a security incident.')]
    )
    alert_id = store.save_alert(test_alert)
    print(f'SELF-TEST alert #{alert_id} queued. Waiting for the installed background agent...', flush=True)
    end = monotonic() + timeout
    while monotonic() < end:
        row = store.db.execute(
            "SELECT status, last_error FROM notification_state WHERE alert_id=? AND channel='email'",
            (alert_id,)
        ).fetchone()
        if row and row[0] == 'sent':
            print(f'PASS: background agent submitted test email for alert #{alert_id}. Confirm its arrival in the inbox.')
            return True
        if row and row[0] == 'failed':
            print(f'FAIL: email attempt for test alert #{alert_id}: {row[1]}', file=sys.stderr)
            return False
        sleep(2)
    print(f'FAIL: alert #{alert_id} was not marked sent within {timeout} seconds. Check agent and monitor.log.', file=sys.stderr)
    return False


def main():
    parser = argparse.ArgumentParser(description='SentinelForge: local Windows detection and email alerting')
    parser.add_argument('command', nargs='?', default='status', choices=['export-csv','dashboard','scan','watch','demo','status','notify-pending','setup','baseline-notifications','agent','start','stop','uninstall','self-test'])
    parser.add_argument('--db', default=str(Path.home() / 'SentinelForgeData' / 'events.sqlite3'))
    parser.add_argument('--threshold', type=int, default=5)
    parser.add_argument('--interval', type=int, default=60, help='watch polling interval in seconds (minimum 30)')
    parser.add_argument('--max-events', type=int, default=500)
    parser.add_argument('--quiet', action='store_true')
    args = parser.parse_args()
    if args.command == 'export-csv':
        from .reporting import export_csv
        output, count = export_csv(args.db)
        print(f'Exported {count} evidence rows to: {output}')
        print('Source database unchanged.')
        return

    if args.command == 'dashboard':
        from dashboard import Handler
        from http.server import ThreadingHTTPServer
        import webbrowser

        address = 'http://127.0.0.1:8765'
        server = ThreadingHTTPServer(('127.0.0.1', 8765), Handler)
        print(f'SentinelForge dashboard: {address}', flush=True)
        webbrowser.open(address)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return

    if args.command == 'setup':
        setup()
        return
    if args.command == 'agent':
        agent()
        return
    if args.command in ('start','stop','uninstall'):
        task_action(args.command)
        return
    if args.command == 'demo':
        detector = Detector(threshold=args.threshold)
        for i in range(args.threshold):
            ev = Event('Security', 100+i, 4625, '2026-10-24T12:00:00+00:00', 'Microsoft-Windows-Security-Auditing', 'Synthetic failed logon for demonstration')
            for alert in detector.process(ev):
                print(json.dumps(asdict(alert), indent=2))
        return
    if args.command == 'status':
        print('Platform:', platform.platform())
        print('Database:', args.db)
        print('HTTPS notifications configured:', bool(os.getenv('SENTINELFORGE_NTFY_URL')))
        print('Channels:', ', '.join(CHANNELS))
        store = Store(args.db)
        total, pending = store.counts()
        print(f'Alerts stored: {total}')
        print('Legacy undelivered counter:', pending, '(includes historical baseline-excluded alerts)')
        config=load_config()
        print('Notification mode:', config['mode'] if config else 'not configured')
        print('Gmail credentials available:', load_gmail_credentials(config) if config else False)
        if os.name == 'nt':
            try:
                task_state = _powershell("(Get-ScheduledTask -TaskName 'SentinelForge Security Monitor' -ErrorAction Stop).State")
                print('Background task:', task_state)
            except Exception:
                print('Background task: not installed')
        print('Historical notification baseline:', 'set' if store.is_baselined() else 'NOT SET')
        if config and store.is_baselined():
            for channel in enabled_channels(config): print(f'{channel} new undelivered:',store.channel_counts(channel))
        store.db.close()
        return
    store = Store(args.db)
    url = os.getenv('SENTINELFORGE_NTFY_URL','')
    token = os.getenv('SENTINELFORGE_NTFY_TOKEN','')
    if args.command == 'baseline-notifications':
        try: count=store.baseline()
        except RuntimeError as exc: sys.exit(str(exc))
        print(f'Historical notification baseline set at alert ID {count}. Existing alerts preserved; future alerts eligible.')
        store.db.close()
        return
    if args.command == 'self-test':
        try:
            ok = run_self_test(store)
        except Exception as exc:
            print(f'SELF-TEST ERROR: {exc}', file=sys.stderr)
            ok = False
        finally:
            store.db.close()
        if not ok:
            sys.exit(2)
        return
    if args.command == 'notify-pending':
        config = load_config()
        load_gmail_credentials(config)
        deliver_channels(store, config)
        store.db.close()
        return
    if os.name != 'nt':
        sys.exit('Live scanning requires Windows. Use demo on other systems.')
    if args.interval < 30 or args.max_events < 1:
        parser.error('--interval must be >=30 and --max-events >=1')
    detector = Detector(threshold=args.threshold)
    try:
        while True:
            count, failed = scan(store, detector, args.max_events, args.quiet)
            # Existing pending alerts can be delivered even when a Windows log cannot be read.
            config = load_config()
            load_gmail_credentials(config)
            deliver_channels(store, config)
            print(f'Scan complete: {count} alerts, {len(failed)} inaccessible channels', flush=True)
            if args.command == 'scan':
                if failed:
                    sys.exit(2)
                break
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print('Monitoring stopped.')
    finally:
        store.db.close()

if __name__ == '__main__':
    main()


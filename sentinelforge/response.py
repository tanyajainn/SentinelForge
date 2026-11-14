"""Opt-in, manually attributed Windows Firewall response. Never called by the monitor."""
from __future__ import annotations
import argparse
import ipaddress
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

PREFIX = 'SentinelForge-Response-'


def validate_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError('Only individual IPv4 addresses are supported')
    if (not address.is_global or
            address.is_multicast or
            address.is_reserved or
            address.is_unspecified or
            address.is_loopback or
            address.is_link_local):
        raise ValueError('Refusing non-global/private/reserved address')
    return str(address)


def data_dir() -> Path:
    return Path.home() / 'SentinelForgeData'


def audit(event: dict) -> None:
    directory = data_dir()
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / 'firewall_response_audit.jsonl'
    record = {'utc': datetime.now(timezone.utc).isoformat(), **event}
    with path.open('a', encoding='utf-8') as f:
        f.write(json.dumps(record, sort_keys=True) + '\n')


def powershell(script: str) -> str:
    if os.name != 'nt':
        raise RuntimeError('Firewall modifications require Windows')
    p = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', script],
                       capture_output=True, text=True, timeout=35)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout).strip()[:500] or 'Firewall command failed')
    return p.stdout.strip()


def require_admin() -> None:
    if os.name != 'nt':
        raise RuntimeError('Windows required')
    import ctypes
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise PermissionError('Open an elevated PowerShell window for apply/rollback')


def create_rule(ip: str, reason: str, confirmation: str) -> str:
    ip = validate_ip(ip)
    if confirmation != f'BLOCK {ip}':
        raise ValueError(f'Explicit confirmation required: --confirm "BLOCK {ip}"')
    if not reason.strip():
        raise ValueError('A nonempty incident reason is required')
    require_admin()
    rule = PREFIX + uuid.uuid4().hex
    # All dynamic data interpolated into PowerShell is strictly validated.
    script = (f"$ErrorActionPreference='Stop'; New-NetFirewallRule -DisplayName '{rule}' "
              f"-Direction Inbound -Action Block -RemoteAddress '{ip}' -Profile Any "
              f"-Enabled True | Out-Null")
    powershell(script)
    audit({'action': 'block', 'ip': ip, 'rule': rule, 'reason': reason[:300]})
    return rule


def list_rules() -> list[dict]:
    script = ("$ErrorActionPreference='Stop'; "
              "@(Get-NetFirewallRule -DisplayName 'SentinelForge-Response-*' -ErrorAction SilentlyContinue "
              "| ForEach-Object { $r=$_; $f=$_ | Get-NetFirewallAddressFilter; "
              "[pscustomobject]@{name=$r.DisplayName;address=($f.RemoteAddress -join ',');enabled=[string]$r.Enabled} }) "
              "| ConvertTo-Json -Compress")
    raw = powershell(script)
    if not raw or raw == 'null':
        return []
    parsed = json.loads(raw)
    return [parsed] if isinstance(parsed, dict) else parsed


def rollback(rule: str, confirmation: str) -> None:
    if not rule.startswith(PREFIX) or not rule[len(PREFIX):].isalnum() or len(rule) != len(PREFIX) + 32:
        raise ValueError('Invalid SentinelForge rule ID')
    if confirmation != f'REMOVE {rule}':
        raise ValueError(f'Explicit confirmation required: --confirm "REMOVE {rule}"')
    require_admin()
    powershell(f"$ErrorActionPreference='Stop'; Remove-NetFirewallRule -DisplayName '{rule}' -ErrorAction Stop")
    audit({'action': 'rollback', 'rule': rule})


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='SentinelForge opt-in firewall response (never automatic)')
    sub = parser.add_subparsers(dest='command', required=True)
    plan = sub.add_parser('plan', help='Safe dry-run; makes no changes')
    plan.add_argument('--ip', required=True)
    apply = sub.add_parser('apply', help='Create a blocking rule after explicit approval')
    apply.add_argument('--ip', required=True)
    apply.add_argument('--reason', required=True)
    apply.add_argument('--confirm', required=True)
    sub.add_parser('list', help='List SentinelForge-managed firewall rules')
    undo = sub.add_parser('rollback', help='Remove one SentinelForge-managed rule')
    undo.add_argument('--rule', required=True)
    undo.add_argument('--confirm', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'plan':
            ip = validate_ip(args.ip)
            print(f'DRY RUN ONLY: would block inbound traffic from {ip}. No firewall changes.')
            print('Source IP must be independently verified; failed-logon counts alone are insufficient.')
        elif args.command == 'apply':
            rule = create_rule(args.ip, args.reason, args.confirm)
            print(f'BLOCKED {args.ip}; rule: {rule}')
            print('To undo: python -m sentinelforge.response rollback --rule ' + rule +
                  ' --confirm "REMOVE ' + rule + '"')
        elif args.command == 'list':
            print(json.dumps(list_rules(), indent=2))
        elif args.command == 'rollback':
            rollback(args.rule, args.confirm)
            print('Rule removed:', args.rule)
        return 0
    except (ValueError, PermissionError, RuntimeError) as exc:
        print('ERROR:', exc, file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

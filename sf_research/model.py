"""Strict portable event schema and normalization utilities."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import re
from typing import Any

KINDS = {'process', 'authentication', 'network', 'security_control', 'file'}
MAX_TEXT = 2048


def utc_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError('timestamp must be a string')
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError as exc:
        raise ValueError('invalid ISO 8601 timestamp') from exc
    if dt.tzinfo is None:
        raise ValueError('timestamp must include timezone')
    return dt.astimezone(timezone.utc)


def safe_text(value: Any, max_len: int = MAX_TEXT) -> str:
    if value is None:
        return ''
    return str(value).replace('\x00', '')[:max_len]


def normalize_ip(value: Any) -> str:
    if not value:
        return ''
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return ''


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)


@dataclass(frozen=True)
class Event:
    event_id: str
    timestamp: str
    host_id: str
    os: str
    kind: str
    source: str
    attributes: dict

    @classmethod
    def parse(cls, raw: dict) -> 'Event':
        if not isinstance(raw, dict):
            raise ValueError('event must be a JSON object')
        required = ('event_id', 'timestamp', 'host_id', 'os', 'kind', 'source', 'attributes')
        if any(k not in raw for k in required):
            raise ValueError('missing required event field')
        kind = safe_text(raw['kind'], 64)
        if kind not in KINDS:
            raise ValueError('unsupported event kind')
        os_name = safe_text(raw['os'], 32).lower()
        if os_name not in {'windows', 'macos', 'linux', 'synthetic'}:
            raise ValueError('unsupported operating system')
        attributes = raw['attributes']
        if not isinstance(attributes, dict) or len(attributes) > 64:
            raise ValueError('attributes must be an object of <=64 entries')
        for key, value in attributes.items():
            if not isinstance(key, str) or len(key) > 128:
                raise ValueError('invalid attribute key')
            if isinstance(value, (dict, list)):
                raise ValueError('nested attributes are not supported')
            if isinstance(value, str) and len(value) > 8192:
                raise ValueError('attribute value too long')
        stamp = utc_time(raw['timestamp']).isoformat()
        ident = safe_text(raw['event_id'], 128)
        host = safe_text(raw['host_id'], 128)
        source = safe_text(raw['source'], 128)
        if not ident or not host or not source:
            raise ValueError('empty event identity')
        return cls(ident, stamp, host, os_name, kind, source, dict(attributes))

    def to_dict(self) -> dict:
        return asdict(self)


def fingerprint(event: Event) -> str:
    return hashlib.sha256(canonical_json(event.to_dict()).encode('utf-8')).hexdigest()


def host_token(hostname: str, salt: str) -> str:
    if not salt:
        raise ValueError('nonempty salt required')
    return hashlib.sha256((salt + '\0' + hostname).encode('utf-8')).hexdigest()[:24]

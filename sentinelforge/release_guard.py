"""Release artifact SHA-256 manifest validation, using Python's standard library.

Checks integrity (not publisher authenticity). A separately authenticated manifest,
code signing, and trusted artifact delivery are required for provenance.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

FILES = ('SentinelForge.exe', 'SentinelForgeAgent.exe')
MANIFEST = 'SentinelForge-checksums.json'
CHUNK = 1024 * 1024


def _artifact_path(folder: Path, filename: str) -> Path:
    if filename not in FILES:
        raise ValueError(f'Unexpected artifact name: {filename!r}')
    path = folder / filename
    if path.is_symlink() or not path.is_file():
        raise ValueError(f'Missing or linked artifact: {filename}')
    if path.stat().st_size == 0:
        raise ValueError(f'Empty artifact: {filename}')
    return path


def _digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(CHUNK), b''):
            sha.update(chunk)
    return sha.hexdigest()


def create_manifest(folder: str | Path) -> dict:
    root = Path(folder)
    artifacts = {}
    for filename in FILES:
        path = _artifact_path(root, filename)
        artifacts[filename] = {'sha256': _digest(path), 'size': path.stat().st_size}
    return {'format': 1, 'algorithm': 'sha256', 'artifacts': artifacts}


def verify_manifest(folder: str | Path, manifest: dict) -> None:
    root = Path(folder)
    if not isinstance(manifest, dict) or set(manifest) != {'format', 'algorithm', 'artifacts'}:
        raise ValueError('Invalid manifest fields')
    if manifest['format'] != 1 or manifest['algorithm'] != 'sha256':
        raise ValueError('Unsupported manifest')
    artifacts = manifest['artifacts']
    if not isinstance(artifacts, dict) or set(artifacts) != set(FILES):
        raise ValueError('Unexpected artifact set')
    for filename in FILES:
        item = artifacts[filename]
        if not isinstance(item, dict) or set(item) != {'sha256', 'size'}:
            raise ValueError(f'Invalid manifest entry: {filename}')
        if type(item['size']) is not int or item['size'] <= 0:
            raise ValueError(f'Invalid artifact size: {filename}')
        sha = item['sha256']
        if not isinstance(sha, str) or len(sha) != 64 or any(c not in '0123456789abcdef' for c in sha):
            raise ValueError(f'Invalid SHA-256: {filename}')
        path = _artifact_path(root, filename)
        if path.stat().st_size != item['size'] or _digest(path) != sha:
            raise ValueError(f'Integrity failure: {filename}')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description='SentinelForge release integrity tool')
    parser.add_argument('operation', choices=['create', 'verify'])
    parser.add_argument('--folder', default='dist')
    args = parser.parse_args(argv)
    root = Path(args.folder)
    manifest_path = root / MANIFEST
    try:
        if args.operation == 'create':
            if manifest_path.is_symlink():
                raise ValueError('Manifest destination cannot be a symbolic link')
            manifest = create_manifest(root)
            # Writing only to output dist; never modifies any installed binary.
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
            print(f'Created integrity manifest: {manifest_path}')
        else:
            if manifest_path.is_symlink() or not manifest_path.is_file():
                raise ValueError('Manifest missing or linked')
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            verify_manifest(root, manifest)
            print('PASS: both release artifacts match manifest')
        print('NOTE: Checksums prove consistency only, not publisher identity or safety.')
        return 0
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        print(f'FAIL: {exc}')
        return 2


if __name__ == '__main__':
    raise SystemExit(main())

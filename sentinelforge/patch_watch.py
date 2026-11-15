"""Check watched npm manifests against GitHub-reviewed security advisories."""
import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import Request, urlopen


def advisories(name, version):
    page = 1
    while True:
        query = urlencode(dict(ecosystem="npm", type="reviewed", affects=f"{name}@{version}",
                               per_page=100, page=page))
        req = Request("https://api.github.com/advisories?" + query,
                      headers={"Accept": "application/vnd.github+json", "User-Agent": "SentinelForge"})
        with urlopen(req, timeout=20) as response:
            rows = json.load(response)
        for row in rows:
            if not row.get("withdrawn_at"):
                yield row
        if len(rows) < 100:
            return
        page += 1


def check(manifest, root, notify):
    pkg = json.loads(manifest.read_text(encoding="utf-8-sig"))
    name, version = pkg["name"], pkg["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][\w.+-]+)?", version):
        raise ValueError(f"Invalid installed version in {manifest}")
    matches = list(advisories(name, version))
    for row in matches:
        ghsa = row["ghsa_id"]
        if not re.fullmatch(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", ghsa):
            raise ValueError("Invalid advisory ID")
        key = hashlib.sha256(json.dumps([str(manifest), name, version, ghsa, row["updated_at"]]).encode()).hexdigest()
        marker = root / key
        if marker.exists():
            continue
        fixes = sorted({v["first_patched_version"] for v in row["vulnerabilities"]
                        if v["package"]["name"] == name and v.get("first_patched_version")})
        details = ", ".join(fixes) or "See vendor guidance"
        message = (f"{row['severity'].upper()}: {name} {version}\n{row['summary']}\n"
                   f"Fixes listed across release lines: {details}\n"
                   f"Check the advisory for your release line: https://github.com/advisories/{ghsa}")
        if notify(message):
            marker.touch()
    return f"{name} {version}: {len(matches)} applicable advisories"


def popup(message):
    env = dict(os.environ, SF_PATCH_MESSAGE=message)
    cmd = "$r=(New-Object -ComObject WScript.Shell).Popup($env:SF_PATCH_MESSAGE,60,'SentinelForge update alert',48); if($r -ne 1){exit 1}"
    return subprocess.run(["powershell.exe", "-NoProfile", "-Command", cmd], env=env).returncode == 0


def main():
    root = Path.home() / "SentinelForgeData" / "patch-watch"
    root.mkdir(parents=True, exist_ok=True)
    status = []
    failed = False
    try:
        paths = (root / "manifests.txt").read_text(encoding="utf-8-sig").splitlines()
        for path in filter(str.strip, paths):
            manifest = Path(path.strip())
            try:
                status.append(check(manifest, root, popup) if manifest.is_file()
                              else f"No installation found at {manifest}")
            except Exception as exc:
                failed = True
                status.append(f"Check failed for {manifest}: {exc}")
    finally:
        (root / "status.txt").write_text("\n".join([datetime.now(timezone.utc).isoformat(), *status]), encoding="utf-8")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())

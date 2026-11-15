"""Monitor changes to launch configuration files visible to the current Mac user."""
import argparse
import hashlib
import plistlib
import sqlite3
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from .core import Store, Alert

ROOTS = [Path.home() / "Library/LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")]
DATA = Path.home() / "SentinelForgeData"
LABEL = "org.sentinelforge.monitor"


def collect(store, roots):
    stamp = datetime.now(timezone.utc).isoformat()
    for root in roots:
        try:
            try:
                entries = list(root.iterdir())
            except FileNotFoundError:
                entries = []
            files = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in entries
                     if p.suffix == ".plist" and p.is_file()}
        except OSError as exc:
            store.record_channel_check(str(root), str(exc))
            continue
        with store.db:
            store.db.execute("CREATE TABLE IF NOT EXISTS mac_files (root TEXT,name TEXT,digest TEXT,PRIMARY KEY(root,name))")
            store.db.execute("CREATE TABLE IF NOT EXISTS mac_roots(root TEXT PRIMARY KEY)")
            directory = str(root)
            prior = dict(store.db.execute("SELECT name,digest FROM mac_files WHERE root=?", (directory,)))
            if store.db.execute("SELECT 1 FROM mac_roots WHERE root=?", (directory,)).fetchone():
                for name in sorted(files.keys() | prior.keys()):
                    if files.get(name) == prior.get(name):
                        continue
                    action = "added" if name not in prior else "removed" if name not in files else "modified"
                    store._insert_alert(Alert("mac-launch-"+action, "medium", "Launch configuration "+action,
                                              stamp, [{"path":str(root/name),"action":action}]))
            store.db.execute("INSERT OR IGNORE INTO mac_roots VALUES(?)", (directory,))
            store.db.execute("DELETE FROM mac_files WHERE root=?", (directory,))
            store.db.executemany("INSERT INTO mac_files VALUES(?,?,?)", [(directory,n,h) for n,h in files.items()])
        store.record_channel_check(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["watch","install"])
    args = parser.parse_args()
    if sys.platform != "darwin":
        parser.error("Requires macOS")
    DATA.mkdir(exist_ok=True)
    if args.command == "install":
        import os
        dest = ROOTS[0] / (LABEL+".plist")
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(plistlib.dumps(dict(Label=LABEL, RunAtLoad=True, KeepAlive=True,
            WorkingDirectory=str(Path(__file__).resolve().parents[1]),
            ProgramArguments=[sys.executable,"-m","sentinelforge.macos","watch"],
            StandardErrorPath=str(DATA/"mac-monitor.log"))))
        domain = f"gui/{os.getuid()}"
        subprocess.run(["/bin/launchctl","bootout",domain+"/"+LABEL],capture_output=True)
        subprocess.run(["/bin/launchctl","bootstrap",domain,str(dest)],check=True)
        return
    store = Store(str(DATA/"events.sqlite3"))
    while True:
        collect(store, ROOTS)
        time.sleep(60)


if __name__ == "__main__":
    main()

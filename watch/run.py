#!/usr/bin/env python3
"""
security-watch -- run the whole pipeline locally over an arbitrary window.

The daily watch is automated; this is for the on-demand case, typically a
weekly catch-up:

    python watch/run.py --days 7

Collection needs open network access. That is true on a workstation but not
inside the routine's sandbox, which is why the daily collection runs in GitHub
Actions instead.

Everything lands in watch/out/manual/, deliberately away from watch/out/ where
the daily pipeline looks: correlate.py picks the most recently modified
feed-*.json, so a weekly feed sitting there would be picked up by the next
morning's routine and reported as if it were the day's news.

Stdlib only.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

WATCH_DIR = Path(__file__).resolve().parent
MANUAL_DIR = WATCH_DIR / "out" / "manual"


def run_step(label: str, args) -> bool:
    print(f"\n=== {label} ===", flush=True)
    result = subprocess.run([sys.executable, *[str(a) for a in args]])
    if result.returncode != 0:
        print(f"\n[!] Echec : {label} (code {result.returncode})", file=sys.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Genere un rapport a la demande sur une fenetre donnee.")
    parser.add_argument("--days", type=int, default=7,
                        help="fenetre en jours (defaut : 7)")
    parser.add_argument("--synthesis", type=Path, default=None,
                        help="synthese Markdown a injecter, si tu en as redige une")
    parser.add_argument("--output", type=Path, default=None,
                        help="rapport de sortie (defaut : watch/out/manual/report-<date>.md)")
    parser.add_argument("--sources", nargs="*", default=None,
                        help="restreint la collecte a ces sources")
    args = parser.parse_args()

    MANUAL_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).date().isoformat()
    feed = MANUAL_DIR / f"feed-{args.days}j.json"
    correlation = MANUAL_DIR / f"correlation-{args.days}j.json"
    output = args.output or (MANUAL_DIR / f"report-{stamp}-{args.days}j.md")

    collect = [WATCH_DIR / "collect.py", "--days", args.days, "--output", feed]
    if args.sources:
        collect += ["--sources", *args.sources]
    if not run_step(f"Collecte sur {args.days} jour(s)", collect):
        return 1

    if not run_step("Correlation avec les snapshots",
                    [WATCH_DIR / "correlate.py", "--feed", feed, "--output", correlation]):
        return 1

    report = [WATCH_DIR / "report.py", "--correlation", correlation, "--output", output]
    if args.synthesis:
        report += ["--synthesis", args.synthesis]
    if not run_step("Rapport", report):
        return 1

    print(f"\n  Rapport : {output}")
    print("  Ce rapport reste local : il n'est ni commite ni publie en issue.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
security-watch -- turn an audit into an issue, reporting only what is new.

Findings already raised in a previous issue are dropped. If nothing is new, no
issue is produced at all: a report you have already read is noise, and noise is
what makes people stop reading the ones that matter.

State lives in the issues themselves, not in a file and not in the target
repository. Each issue carries a machine-readable block listing the findings it
raised; the next run reads those blocks back. Two consequences worth knowing:

  - Whatever you do with an issue is respected. Close it as wontfix and the
    finding stays known, so it will not come back.
  - Deleting an issue makes its findings new again. That is the intended
    escape hatch when you want something re-raised.

The lookback window bounds how far back issues are read. Past it, an
unaddressed finding resurfaces -- deliberately, as a reminder.

    gh issue list --label "Security report" --state all --limit 200 \
       --json body,createdAt,number > previous.json
    python watch/publish.py --findings findings.json --previous previous.json

Stdlib only. Does not call gh itself, so it stays testable offline.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit import SEVERITY_RANK, group_by_package, group_images, render  # noqa: E402
from scanner import force_utf8_output  # noqa: E402

MARKER_START = "<!-- security-watch:findings"
MARKER_END = "-->"
MARKER_RE = re.compile(
    re.escape(MARKER_START) + r"\s*(\[.*?\])\s*" + re.escape(MARKER_END), re.DOTALL)

DEFAULT_LOOKBACK_DAYS = 90
SEVERITY_FLOOR = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def finding_key(finding, package, installed, image=None):
    """Identity of a finding for deduplication.

    The installed version is part of the key on purpose: if a bump lands and
    the advisory still applies to the new version, that is worth raising again
    rather than silently swallowing.

    The image is appended only when there is one, so a dependency key stays
    exactly what it was: changing the shape would make every past issue
    unreadable and raise the whole backlog again.
    """
    key = f"{finding.get('id')}@{package}@{installed}"
    # The same flaw in two base images is two images to change, not a duplicate.
    return f"{key}@{image}" if image else key


def known_keys(previous, lookback_days):
    """Findings already raised, from issues created within the window."""
    cutoff = datetime.now(timezone.utc) - timedelta(days=lookback_days)
    keys, considered, skipped = set(), 0, 0

    for issue in previous or []:
        created = issue.get("createdAt") or issue.get("created_at")
        try:
            when = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            when = None
        if when and when < cutoff:
            skipped += 1
            continue

        considered += 1
        match = MARKER_RE.search(issue.get("body") or "")
        if not match:
            continue
        try:
            keys.update(json.loads(match.group(1)))
        except json.JSONDecodeError:
            continue

    return keys, considered, skipped


def main():
    force_utf8_output()
    parser = argparse.ArgumentParser(
        description="Publie un rapport d'audit en ne remontant que les nouveautes.")
    parser.add_argument("--findings", type=Path, required=True,
                        help="JSON produit par audit.py --out-json")
    parser.add_argument("--previous", type=Path, default=None,
                        help="JSON des issues existantes (gh issue list --json body,createdAt)")
    parser.add_argument("--lookback", type=int,
                        default=int(os.environ.get("SECWATCH_LOOKBACK_DAYS",
                                                   DEFAULT_LOOKBACK_DAYS)),
                        help=f"jours d'historique d'issues relus (defaut : {DEFAULT_LOOKBACK_DAYS})")
    parser.add_argument("--min-severity", default=os.environ.get("SECWATCH_MIN_SEVERITY", "LOW"),
                        choices=SEVERITY_FLOOR,
                        help="ne remonte que ce niveau et au-dessus (defaut : LOW)")
    parser.add_argument("--out-md", type=Path, default=None,
                        help="corps de l'issue (defaut : stdout)")
    parser.add_argument("--out-title", type=Path, default=None,
                        help="fichier ou ecrire le titre de l'issue")
    args = parser.parse_args()

    audit = json.loads(args.findings.read_text(encoding="utf-8"))
    previous = []
    if args.previous and args.previous.is_file():
        try:
            previous = json.loads(args.previous.read_text(encoding="utf-8")) or []
        except json.JSONDecodeError:
            print("[!] --previous illisible : tout sera considere comme nouveau.",
                  file=sys.stderr)

    seen, considered, skipped = known_keys(previous, args.lookback)
    floor = SEVERITY_RANK.get(args.min_severity, 3)

    fresh, current_keys = [], []

    def harvest(packages, scope, image=None):
        for package in packages or []:
            for finding in package.get("findings") or []:
                key = finding_key(finding, package.get("package"),
                                  package.get("installed"), image)
                current_keys.append(key)
                if key in seen:
                    continue
                if SEVERITY_RANK.get(finding.get("severity", "UNKNOWN"), 99) > floor:
                    continue
                fresh.append(dict(finding,
                                  package=package.get("package"),
                                  installed=package.get("installed"),
                                  fixed=package.get("fixed"),
                                  scope=scope,
                                  image=image))

    harvest(audit.get("packages"), "dependency")
    for section in audit.get("images") or []:
        harvest(section.get("packages"), "image", section.get("ref"))

    repo = audit.get("repo") or {}
    name = repo.get("name") or "depot"
    print(f"[*] {len(current_keys)} constat(s) au total, {len(seen)} deja connu(s) "
          f"({considered} issue(s) relue(s), {skipped} hors fenetre de {args.lookback} j)",
          file=sys.stderr)
    print(f"[*] {len(fresh)} nouveau(x) constat(s)", file=sys.stderr)

    github_output = os.environ.get("GITHUB_OUTPUT")
    if not fresh:
        print("[+] Rien de nouveau : aucune issue ne sera creee.", file=sys.stderr)
        if github_output:
            with open(github_output, "a", encoding="utf-8") as handle:
                handle.write("has_new=false\n")
        return 0

    groups = group_by_package(fresh)
    fresh_images = [f for f in fresh if f.get("scope") == "image"]
    # Only the images that still carry something new keep a section: an image
    # whose findings were all reported before has nothing to say today.
    still_open = [section for section in (audit.get("images") or [])
                  if any(f.get("image") == section.get("ref") for f in fresh_images)]
    scanned_at = audit.get("scanned_at") or datetime.now(timezone.utc).isoformat()
    body = render(name, repo, groups, [], audit.get("errors") or [],
                  scanned_at, audit.get("ecosystems") or [],
                  group_images(fresh_images, still_open))

    total_all = len(current_keys)
    body += (
        f"\n\n*Ce rapport ne liste que les constats jamais remontes. "
        f"Le depot en porte {total_all} au total ; les autres figurent deja dans "
        f"une issue des {args.lookback} derniers jours.*\n"
        f"\n{MARKER_START}\n"
        # Same arguments as the harvest above, image included: a key written
        # here that the next run recomputes differently never matches, and the
        # finding comes back every single day.
        + json.dumps(sorted({finding_key(f, f["package"], f["installed"], f.get("image"))
                             for f in fresh}))
        + f"\n{MARKER_END}\n"
    )

    date = str(scanned_at)[:10].replace("-", "/")
    # "nouveau" takes an x in the plural, not an s.
    label = "nouveau constat" if len(fresh) <= 1 else "nouveaux constats"
    title = f"{date} - {name} - {len(fresh)} {label}"

    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(body, encoding="utf-8")
        print(f"[+] Corps : {args.out_md}", file=sys.stderr)
    else:
        print(body)

    if args.out_title:
        args.out_title.write_text(title, encoding="utf-8")
    print(f"[+] Titre : {title}", file=sys.stderr)

    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write("has_new=true\n")
            handle.write(f"title={title}\n")
            handle.write(f"count={len(fresh)}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())

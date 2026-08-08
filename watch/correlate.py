#!/usr/bin/env python3
"""
security-watch -- cross-references advisory feeds against machine snapshots.

Joins what was published (watch/out/feed-*.json) with what you actually run
(snapshots/*.json) and ranks the result by level of certainty.

This is where the system earns its keep: without the join, a watch report is a
list of a hundred CVEs a day that nobody reads.

Design rule: never conclude "not affected" by default. A version range we
cannot parse goes to `to_review`, not to the bin.

Stdlib only. Output: watch/out/correlation-<date>.json
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

WATCH_DIR = Path(__file__).resolve().parent
ROOT_DIR = WATCH_DIR.parent
OUT_DIR = WATCH_DIR / "out"
SNAPSHOT_DIR = ROOT_DIR / "snapshots"

# Past this age a snapshot describes a machine that has probably changed. The
# report flags it: a freshness warning beats a false sense of calm.
SNAPSHOT_STALE_DAYS = 14

SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "UNKNOWN": 5}

# GHSA ecosystem -> matching Trivy types
ECOSYSTEM_ALIASES = {
    "npm": {"npm", "node-pkg", "yarn", "pnpm"},
    "nuget": {"nuget", "dotnet-core"},
    "pip": {"pip", "python-pkg"},
    "go": {"gomod", "golang"},
    "maven": {"jar", "pom"},
    "rubygems": {"gemspec", "bundler"},
    "cargo": {"cargo"},
}


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


# --------------------------------------------------------------------------
# Version comparison
# --------------------------------------------------------------------------

VERSION_RE = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-+.]?(.*))?$")


def parse_version(raw):
    """'1.2.3-rc.1' -> ((1,2,3), 'rc.1'). None when unparseable."""
    if not raw:
        return None
    match = VERSION_RE.match(str(raw).strip())
    if not match:
        return None
    numbers = tuple(int(part) for part in match.group(1).split("."))
    return numbers, (match.group(2) or "")


def prerelease_key(pre: str):
    """Split a prerelease per semver rules.

    A numeric identifier always sorts below an alphanumeric one, and
    'rc.2' < 'rc.10' -- numeric, not lexical. A string comparison would invert
    that and produce a silently wrong verdict.
    """
    parts = []
    for token in re.split(r"[.\-+]", pre):
        if not token:
            continue
        if token.isdigit():
            parts.append((0, int(token), ""))
        else:
            parts.append((1, 0, token))
    return parts


def compare_versions(left, right):
    """-1 / 0 / 1. A prerelease sorts below the release of the same number."""
    left_num, left_pre = left
    right_num, right_pre = right

    length = max(len(left_num), len(right_num))
    padded_left = left_num + (0,) * (length - len(left_num))
    padded_right = right_num + (0,) * (length - len(right_num))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1

    # Same numbers: the absence of a prerelease wins.
    if not left_pre and not right_pre:
        return 0
    if not left_pre:
        return 1
    if not right_pre:
        return -1

    left_key, right_key = prerelease_key(left_pre), prerelease_key(right_pre)
    if left_key == right_key:
        return 0
    return -1 if left_key < right_key else 1


CLAUSE_RE = re.compile(r"^\s*(>=|<=|>|<|=|==)?\s*(.+?)\s*$")


def version_in_range(installed_raw, range_raw):
    """Does the installed version fall inside the vulnerable range?

    Returns True / False / None. `None` means "undeterminable" and must be
    treated as "needs review", never as "not affected".
    """
    installed = parse_version(installed_raw)
    if installed is None or not range_raw:
        return None

    for clause in str(range_raw).split(","):
        match = CLAUSE_RE.match(clause)
        if not match:
            return None
        operator = match.group(1) or "="
        bound = parse_version(match.group(2))
        if bound is None:
            return None

        result = compare_versions(installed, bound)
        satisfied = {
            ">=": result >= 0,
            ">": result > 0,
            "<=": result <= 0,
            "<": result < 0,
            "=": result == 0,
            "==": result == 0,
        }[operator]
        if not satisfied:
            return False
    return True


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def snapshot_age_days(scanned_at):
    """Snapshot age in days, or None when the date is unreadable."""
    if not scanned_at:
        return None
    try:
        when = datetime.fromisoformat(str(scanned_at))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (datetime.now(timezone.utc) - when).total_seconds() / 86400)


def load_snapshots(directory: Path):
    """Load snapshots and surface their coverage gaps.

    Each snapshot's internal errors (failed NuGet restore, container VM down)
    must reach the final report: without them a partial scan would present
    itself as full coverage.

    Freshness is handled the same way. A three-month-old snapshot describes a
    machine that no longer exists, and a quiet report built on it is a false
    calm.
    """
    snapshots, errors, limitations = [], [], []
    for path in sorted(directory.glob("*.json")):
        data = load_json(path)
        if data is None:
            errors.append(f"snapshot illisible : {path.name}")
            continue

        machine = data.get("machine") or {}
        label = machine.get("label") or (data.get("host") or {}).get("name") or path.stem
        scanned_at = (data.get("scan") or {}).get("finished_at")
        age = snapshot_age_days(scanned_at)

        snapshots.append({
            "label": label,
            "role": machine.get("role"),
            "file": path.name,
            "scanned_at": scanned_at,
            "age_days": round(age, 1) if age is not None else None,
            "stale": age is not None and age > SNAPSHOT_STALE_DAYS,
            "os": (data.get("host") or {}).get("distro_name")
                  or (data.get("host") or {}).get("os"),
            "android": data.get("android"),
            "findings": len(data.get("findings") or []),
            "data": data,
        })

        if age is None:
            errors.append(f"[{label}] date de scan illisible — fraicheur inconnue")
        elif age > SNAPSHOT_STALE_DAYS:
            errors.append(
                f"[{label}] snapshot vieux de {age:.0f} jours — relance `scan.ps1` "
                f"ou `scan.sh` sur ce poste, les constats peuvent etre perimes")

        for error in (data.get("errors") or []):
            errors.append(f"[{label}] {error}")

        # Declared structural gaps. Kept apart from errors so a permanent,
        # accepted limitation never reads as something that broke today.
        for entry in (data.get("limitations") or []):
            limitations.append({"machine": label, **entry})

    if not snapshots:
        errors.append(f"aucun snapshot dans {directory}")
    return snapshots, errors, limitations


def index_snapshots(snapshots):
    """Build the lookup indexes across every machine."""
    by_cve = {}       # identifier (CVE or GHSA) -> [occurrences]
    by_package = {}   # lowercase package name -> [occurrences]
    software = []     # installed software / system packages, all machines

    for snapshot in snapshots:
        host = snapshot["label"]
        inventory = snapshot["data"]
        for finding in (inventory.get("findings") or []):
            occurrence = {
                "host": host,
                "scope": finding.get("scope"),
                "repo": finding.get("repo"),
                "image": finding.get("image"),
                "target": finding.get("target"),
                "package": finding.get("package"),
                "installed": finding.get("installed"),
                "fixed": finding.get("fixed"),
                "severity": finding.get("severity"),
                "ecosystem": finding.get("ecosystem"),
            }
            identifier = finding.get("id")
            if identifier:
                by_cve.setdefault(identifier, []).append(occurrence)

            name = (finding.get("package") or "").lower()
            if name:
                by_package.setdefault(name, []).append(occurrence)

        # Windows software and pacman packages share one index: in both cases
        # matching happens by name, for lack of reliable system-side version
        # matching.
        for item in (inventory.get("installed_software") or []):
            software.append({"host": host, **item})

    return by_cve, by_package, software


def ecosystem_matches(advisory_ecosystem, finding_ecosystem):
    if not advisory_ecosystem or not finding_ecosystem:
        return True  # when unsure, do not filter out
    accepted = ECOSYSTEM_ALIASES.get(advisory_ecosystem.lower(), {advisory_ecosystem.lower()})
    return finding_ecosystem.lower() in accepted


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------

def priority(advisory, tier):
    """Deterministic score. The report follows it; the AI layer cannot renegotiate it."""
    score = 0
    if advisory.get("exploited"):
        score += 1000
    score += {"confirmed": 500, "probable": 300, "to_review": 100}.get(tier, 0)
    epss = advisory.get("epss_score")
    if isinstance(epss, (int, float)):
        score += epss * 200
    cvss = advisory.get("cvss")
    if isinstance(cvss, (int, float)):
        score += cvss * 10
    score += SEVERITY_WEIGHT.get((advisory.get("severity") or "UNKNOWN").upper(), 5)
    return round(score, 2)


def identifiers_of(advisory):
    ids = [advisory.get("id")] + list(advisory.get("aliases") or [])
    return [i for i in ids if i]


def correlate(feed, by_cve, by_package, software):
    confirmed, probable, to_review, context = [], [], [], []

    software_index = [(entry, f"{entry.get('name', '')}".lower()) for entry in software]

    for advisory in (feed.get("advisories") or []):
        identifiers = identifiers_of(advisory)

        # -- Level 1: identifier already present in a snapshot.
        # Trivy did the version matching, so exposure is established.
        matches = []
        for identifier in identifiers:
            matches += by_cve.get(identifier, [])
        if matches:
            why = "identifiant deja remonte par le scan local"
            # One CVE gets packaged by several distributions, so an Arch
            # advisory can match a Debian package inside a container image. The
            # finding stays true, but its origin has to be stated.
            found_in = sorted({m.get("ecosystem") for m in matches if m.get("ecosystem")})
            declared = (advisory.get("ecosystem") or "").lower()
            if declared and found_in and declared not in found_in:
                why += f" — meme CVE, empaquetee ailleurs ({', '.join(found_in)})"
            confirmed.append({
                "tier": "confirmed",
                "advisory": advisory,
                "why": why,
                "matches": matches,
                "priority": priority(advisory, "confirmed"),
            })
            continue

        # -- Level 2: the package is present, so evaluate the version range.
        # This catches advisories too recent for the Trivy database.
        package_hits, uncertain_hits = [], []
        for package in (advisory.get("packages") or []):
            name = (package.get("name") or "").lower()
            if not name:
                continue
            for occurrence in by_package.get(name, []):
                if not ecosystem_matches(package.get("ecosystem"), occurrence.get("ecosystem")):
                    continue
                verdict = version_in_range(occurrence.get("installed"),
                                           package.get("vulnerable_range"))
                enriched = {**occurrence,
                            "vulnerable_range": package.get("vulnerable_range"),
                            "first_patched": package.get("first_patched")}
                if verdict is True:
                    package_hits.append(enriched)
                elif verdict is None:
                    uncertain_hits.append({**enriched, "reason": "plage de versions non interpretable"})

        if package_hits:
            probable.append({
                "tier": "probable",
                "advisory": advisory,
                "why": "paquet present et version dans la plage vulnerable",
                "matches": package_hits,
                "priority": priority(advisory, "probable"),
            })
            continue

        if uncertain_hits:
            to_review.append({
                "tier": "to_review",
                "advisory": advisory,
                "why": "paquet present, plage de versions non interpretable",
                "matches": uncertain_hits,
                "priority": priority(advisory, "to_review"),
            })
            continue

        # -- Level 3: match on installed software name (mostly KEV).
        # Deliberately fuzzy: a lead to check, not a verdict.
        product = f"{advisory.get('product') or ''}".lower().strip()
        if product and len(product) > 3:
            candidates = [entry for entry, name in software_index if product in name]
            if candidates:
                to_review.append({
                    "tier": "to_review",
                    "advisory": advisory,
                    "why": f"logiciel installe dont le nom evoque '{product}' -- a confirmer manuellement",
                    "matches": candidates[:5],
                    "priority": priority(advisory, "to_review"),
                })
                continue

        # -- Level 4: no link to any snapshot.
        # Only actively exploited entries are kept: context, not noise.
        if advisory.get("exploited"):
            context.append({
                "tier": "context",
                "advisory": advisory,
                "why": "activement exploite, sans lien etabli avec ton inventaire",
                "matches": [],
                "priority": priority(advisory, "context"),
            })

    for bucket in (confirmed, probable, to_review, context):
        bucket.sort(key=lambda item: item["priority"], reverse=True)

    return confirmed, probable, to_review, context


# --------------------------------------------------------------------------
# Per-topic digest
# --------------------------------------------------------------------------

# Windows, Android and Arch do not resolve against lockfiles: their advisories
# match nothing and would be dropped by the correlation. The digest surfaces
# them anyway, as informational watch -- which is precisely what one wants to
# know about those subjects.
TOPICS = [
    ("cisa-kev", "Exploité activement"),
    ("ghsa", "Node / .NET"),
    ("msrc", "Windows / Microsoft"),
    ("arch", "Arch Linux"),
    ("containers", "Docker / Podman"),
    ("android", "Android"),
    ("certfr_avis", "CERT-FR"),
    ("certfr_alerte", "CERT-FR (alertes)"),
]


def parse_dt_safe(value):
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


def build_topics(feed, matched_ids, top_n=5):
    """Count and sample advisories per topic, matched or not."""
    buckets = {key: [] for key, _ in TOPICS}
    for advisory in (feed.get("advisories") or []):
        source = advisory.get("source")
        if source in buckets:
            buckets[source].append(advisory)

    topics = []
    for key, label in TOPICS:
        items = buckets.get(key) or []
        if not items:
            continue
        items.sort(key=lambda a: priority(a, "context"), reverse=True)

        severities = {}
        for advisory in items:
            level = (advisory.get("severity") or "UNKNOWN").upper()
            severities[level] = severities.get(level, 0) + 1

        topics.append({
            "key": key,
            "label": label,
            "total": len(items),
            "by_severity": severities,
            # A dateless source describes a current state, not new items: the
            # report must not announce it as "published today".
            "dateless": bool(items[0].get("dateless")),
            "matched": sum(1 for a in items
                           if any(i in matched_ids for i in identifiers_of(a))),
            "top": [{
                "id": a.get("id"),
                "title": a.get("title"),
                "severity": (a.get("severity") or "UNKNOWN").upper(),
                "cvss": a.get("cvss"),
                "epss": a.get("epss_score"),
                "exploited": bool(a.get("exploited")),
                "url": a.get("url"),
                "matched": any(i in matched_ids for i in identifiers_of(a)),
            } for a in items[:top_n]],
        })
    return topics


def check_android(snapshots, feed):
    """Compare the declared Android patch level to the latest bulletin seen.

    No PC can compute a phone's exposure. It can, however, tell whether the
    declared patch level lags what has been published -- the only genuinely
    actionable signal available here.
    """
    declared = [{"machine": s["label"], **(s["android"] or {})}
                for s in snapshots if s.get("android")]
    if not declared:
        return None

    dates = [parse_dt_safe(a.get("published"))
             for a in (feed.get("advisories") or []) if a.get("source") == "android"]
    dates = [d for d in dates if d]
    if not dates:
        return {"declared": declared, "latest_bulletin": None, "behind": []}

    latest = max(dates)
    behind = []
    for entry in declared:
        patch = parse_dt_safe(entry.get("security_patch"))
        if patch and patch < latest:
            behind.append({
                "machine": entry.get("machine"),
                "device": entry.get("device"),
                "declared_patch": entry.get("security_patch"),
                "days_behind": round((latest - patch).total_seconds() / 86400),
            })
    return {"declared": declared,
            "latest_bulletin": latest.date().isoformat(),
            "behind": behind}


def main():
    parser = argparse.ArgumentParser(description="Croise les flux avec les snapshots.")
    parser.add_argument("--feed", type=Path, default=None,
                        help="fichier de flux (defaut : le plus recent dans watch/out)")
    parser.add_argument("--snapshot-dir", type=Path, default=SNAPSHOT_DIR)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    feed_path = args.feed
    if feed_path is None:
        # By modification time: an alphabetical sort would put "feed-test.json"
        # after "feed-2026-08-07.json".
        candidates = sorted(OUT_DIR.glob("feed-*.json"), key=lambda p: p.stat().st_mtime)
        if not candidates:
            print("ERREUR : aucun flux dans watch/out. Lance d'abord watch/collect.py.",
                  file=sys.stderr)
            return 2
        feed_path = candidates[-1]

    feed = load_json(feed_path)
    if feed is None:
        print(f"ERREUR : flux illisible : {feed_path}", file=sys.stderr)
        return 2

    snapshots, snapshot_errors, limitations = load_snapshots(args.snapshot_dir)
    if not snapshots:
        print(f"ERREUR : aucun snapshot dans {args.snapshot_dir}. "
              "Lance d'abord scan.ps1 (Windows) ou scan.sh (Linux).", file=sys.stderr)
        return 2

    by_cve, by_package, software = index_snapshots(snapshots)
    confirmed, probable, to_review, context = correlate(feed, by_cve, by_package, software)

    matched_ids = {identifier
                   for bucket in (confirmed, probable, to_review)
                   for item in bucket
                   for identifier in identifiers_of(item["advisory"])}
    topics = build_topics(feed, matched_ids)
    android = check_android(snapshots, feed)

    result = {
        "schema": 1,
        "correlated_at": now_iso(),
        "feed": {"file": feed_path.name, "collected_at": feed.get("collected_at"),
                 "window": feed.get("window"), "advisories": len(feed.get("advisories") or [])},
        "machines": [{key: snapshot[key] for key in
                      ("label", "role", "os", "scanned_at", "age_days", "stale",
                       "android", "findings", "file")}
                     for snapshot in snapshots],
        "confirmed": confirmed,
        "probable": probable,
        "to_review": to_review,
        "context": context,
        "topics": topics,
        "android": android,
        "limitations": limitations,
        "stats": {
            "confirmed": len(confirmed),
            "probable": len(probable),
            "to_review": len(to_review),
            "context": len(context),
            "indexed_identifiers": len(by_cve),
            "indexed_packages": len(by_package),
            "indexed_software": len(software),
            "stale_snapshots": sum(1 for s in snapshots if s["stale"]),
        },
        "errors": snapshot_errors + (feed.get("errors") or []),
    }

    output = args.output or (OUT_DIR / f"correlation-{datetime.now(timezone.utc).date().isoformat()}.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")

    print()
    print(f"  Flux      : {feed_path.name} ({result['feed']['advisories']} entrees)")
    print("  Machines  :")
    for machine in result["machines"]:
        age = ("jamais" if machine["age_days"] is None
               else f"il y a {machine['age_days']:.0f} j")
        flag = "  [PERIME]" if machine["stale"] else ""
        role = f" — {machine['role']}" if machine.get("role") else ""
        print(f"    {machine['label']}{role} : {machine['findings']} constats, "
              f"scanne {age}{flag}")
    print()
    print(f"  Confirme     {len(confirmed):>3}   exposition etablie par le scan local")
    print(f"  Probable     {len(probable):>3}   paquet present, version dans la plage vulnerable")
    print(f"  A verifier   {len(to_review):>3}   correspondance partielle")
    print(f"  Contexte     {len(context):>3}   exploite activement, sans lien etabli")
    print()

    if topics:
        print("  Veille par sujet :")
        for topic in topics:
            kind = " (etat courant)" if topic["dateless"] else ""
            hit = f", dont {topic['matched']} qui te touchent" if topic["matched"] else ""
            print(f"    {topic['label']:<22} {topic['total']:>4}{kind}{hit}")
        print()

    if android and android.get("behind"):
        for late in android["behind"]:
            print(f"  Android : {late['device'] or 'appareil'} declare au "
                  f"{late['declared_patch']}, soit {late['days_behind']} j de retard "
                  f"sur le bulletin du {android['latest_bulletin']}")
        print()

    for item in (confirmed + probable + to_review)[:10]:
        advisory = item["advisory"]
        flag = "[EXPLOITE] " if advisory.get("exploited") else ""
        targets = sorted({m.get("repo") or m.get("image") or m.get("name") or "?"
                          for m in item["matches"]})
        print(f"  {item['priority']:>7.1f}  {flag}{advisory.get('id')} "
              f"{(advisory.get('title') or '')[:60]}")
        print(f"           -> {', '.join(targets[:4])}")
    print()
    print(f"  Correlation ecrite : {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

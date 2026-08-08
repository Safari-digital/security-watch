#!/usr/bin/env python3
"""
Grouping tests -- what the report is allowed to claim.

Two failures this guards against, both of which read as confident output
rather than as an error:

  - the same advisory counted once per file it was found in, which inflates
    every total by the shape of the repository rather than by its exposure;
  - "no patch published" written over a source that never publishes patch
    versions, which turns silence into an all-clear.

Run:  python watch/test_report.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit import group_by_package, merge_occurrences, render  # noqa: E402


def finding(**overrides):
    base = {
        "scope": "dependency",
        "id": "CVE-2026-1",
        "package": "Some.Package",
        "installed": "1.0.0",
        "fixed": None,
        "severity": "HIGH",
        "cvss": None,
        "title": None,
        "url": None,
        "detector": "trivy",
        "target": "a.json",
    }
    base.update(overrides)
    return base


def one_group(findings):
    groups = group_by_package(findings)
    return groups[0] if groups else None


def check_merge(failures):
    merged = merge_occurrences([
        finding(target="proj-a"),
        finding(target="proj-b"),
        finding(target="proj-c"),
    ])
    if len(merged) != 1:
        failures.append(f"merge_occurrences : {len(merged)} entree(s), attendu 1")
    elif sorted(merged[0]["targets"]) != ["proj-a", "proj-b", "proj-c"]:
        failures.append(f"merge_occurrences : emplacements = {merged[0]['targets']}")

    # Distinct advisories on one package stay distinct.
    merged = merge_occurrences([finding(id="CVE-2026-1"), finding(id="CVE-2026-2")])
    if len(merged) != 2:
        failures.append(f"merge_occurrences : {len(merged)} advisory(s), attendu 2")

    # The worst severity wins, whatever order the sources came in.
    merged = merge_occurrences([finding(severity="MEDIUM"), finding(severity="CRITICAL")])
    if merged[0]["severity"] != "CRITICAL":
        failures.append(f"merge_occurrences : severite = {merged[0]['severity']}")

    # Two sources on one advisory: keep whichever detail exists.
    merged = merge_occurrences([
        finding(detector="dotnet-sdk", title=None, cvss=None, fixed=None),
        finding(detector="trivy", title="Un titre", cvss=7.5, fixed="1.0.1"),
    ])
    if merged[0]["title"] != "Un titre" or merged[0]["fixed"] != "1.0.1":
        failures.append(f"merge_occurrences : detail perdu -> {merged[0]}")


def check_counts(failures):
    """Repetition across files must not change the totals."""
    once = one_group([finding(target="a")])
    thrice = one_group([finding(target="a"), finding(target="b"), finding(target="c")])
    if len(once["findings"]) != len(thrice["findings"]):
        failures.append(
            f"group_by_package : {len(thrice['findings'])} constat(s) pour un seul avis")


def check_fix_unknown(failures):
    # A source that never names a fix: silence means unknown.
    group = one_group([finding(detector="dotnet-sdk", fixed=None)])
    if not group["fix_unknown"]:
        failures.append("fix_unknown : faux alors que dotnet-sdk n'indique jamais de correctif")

    # Trivy would have named one, so its silence does mean none published.
    group = one_group([finding(detector="trivy", fixed=None)])
    if group["fix_unknown"]:
        failures.append("fix_unknown : vrai alors que Trivy aurait indique un correctif")

    # A known fix is never an unknown.
    group = one_group([finding(detector="dotnet-sdk", fixed="2.0.0")])
    if group["fix_unknown"] or group["fixed"] != "2.0.0":
        failures.append(f"fix_unknown : correctif connu mal classe -> {group['fixed']}")

    # One source naming a fix settles it for the whole group.
    group = one_group([
        finding(id="CVE-2026-1", detector="dotnet-sdk", fixed=None),
        finding(id="CVE-2026-2", detector="trivy", fixed="2.0.0"),
    ])
    if group["fix_unknown"]:
        failures.append("fix_unknown : vrai alors qu'une source a nomme un correctif")


def check_render(failures):
    """The wording is the whole point: an unknown must not read as an absence."""
    groups = group_by_package([finding(detector="dotnet-sdk", fixed=None)])
    text = render("depot", {}, groups, [], [], "2026-08-09T00:00:00+00:00", ["dotnet"])
    if "aucun correctif publié" in text:
        failures.append("render : 'aucun correctif publie' sur un correctif non renseigne")
    if "correctif à vérifier" not in text:
        failures.append("render : l'incertitude sur le correctif n'est pas affichee")

    groups = group_by_package([finding(detector="trivy", fixed=None)])
    text = render("depot", {}, groups, [], [], "2026-08-09T00:00:00+00:00", ["npm"])
    if "aucun correctif publié" not in text:
        failures.append("render : absence reelle de correctif non signalee")

    # An advisory spread over several places says so once, not N times.
    groups = group_by_package([finding(target=f"p{i}") for i in range(4)])
    text = render("depot", {}, groups, [], [], "2026-08-09T00:00:00+00:00", ["dotnet"])
    # Counted on the bullet, not on the raw string: the identifier also appears
    # inside the advisory URL on the same line.
    bullets = [line for line in text.splitlines() if line.startswith("- [CVE-2026-1]")]
    if len(bullets) != 1:
        failures.append(f"render : advisory repete sur {len(bullets)} ligne(s)")
    if "4 emplacements" not in text:
        failures.append("render : la dispersion n'est pas indiquee")


def main():
    failures = []
    check_merge(failures)
    check_counts(failures)
    check_fix_unknown(failures)
    check_render(failures)

    total = 5 + 1 + 4 + 4
    if failures:
        print(f"ECHEC : {len(failures)} probleme(s) sur {total} cas")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"OK : {total}/{total} cas passent")
    return 0


if __name__ == "__main__":
    sys.exit(main())

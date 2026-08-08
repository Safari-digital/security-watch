#!/usr/bin/env python3
"""
security-watch -- audit one repository, no time window, no AI.

Produces the deterministic pre-report: everything the repository is exposed to
right now, from its lockfiles and manifests. This is deliberately different
from the daily watch, which reports what was *published* over a window. A
repository carries vulnerabilities older than any window, so a scan of the
actual dependency tree is the only way to see the whole picture.

Two consumers, same output:
  - CI on the target repository, feeding a GitHub issue
  - a human, running it locally on a repository that has no CI of its own

Nothing here is rewritten by a model. The summary is added afterwards, by the
routine or by hand, on top of an artefact that is already true.

    python watch/audit.py --repo ../some-project
    python watch/audit.py --repo . --out-md report.md --out-json findings.json

Requires Trivy on PATH. Stdlib only otherwise.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))

from agent import (  # noqa: E402
    SEVERITY_ORDER,
    SEVERITY_RANK,
    detect_ecosystems,
    run,
    scan_dotnet,
    summarize,
    trivy_scan_repo,
    trivy_version,
    which,
)

SEVERITY_LABEL = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM",
                  "LOW": "LOW", "UNKNOWN": "?"}


def advisory_url(finding):
    """Canonical source first, scanner reference only as a fallback.

    Trivy's PrimaryURL points at Aqua's own database. Fine as a reference, but
    a report should send the reader to NVD or the GitHub advisory, which are
    the upstream records.
    """
    identifier = str(finding.get("id") or "")
    if identifier.startswith("GHSA-"):
        return f"https://github.com/advisories/{identifier}"
    if identifier.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{identifier}"
    return finding.get("url")


def worst_rank(findings):
    return min(SEVERITY_RANK.get(f.get("severity", "UNKNOWN"), 99) for f in findings)


# Sources that report where a vulnerability is, but never which release fixes
# it. `dotnet list package` is one: absent a fix from it, silence means the
# source did not say, not that no patch exists.
FIXLESS_DETECTORS = {"dotnet-sdk"}


def merge_occurrences(items):
    """One entry per advisory, not one per file it was found in.

    An advisory legitimately turns up in every project that consumes the
    package. Kept apart, one upgrade reads as eleven identical bullet points
    and every count downstream is inflated by the shape of the repository.
    """
    merged = {}
    for finding in items:
        kept = merged.get(str(finding.get("id")))
        if kept is None:
            merged[str(finding.get("id"))] = kept = dict(finding, targets=[])
        target = finding.get("target")
        if target and target not in kept["targets"]:
            kept["targets"].append(target)
        if SEVERITY_RANK.get(finding.get("severity", "UNKNOWN"), 99) < \
                SEVERITY_RANK.get(kept.get("severity", "UNKNOWN"), 99):
            kept["severity"] = finding.get("severity")
        # Two sources describing one advisory rarely carry the same detail:
        # Trivy has a title, a CVSS and a fixed version the SDK does not.
        for field in ("title", "cvss", "url", "fixed"):
            if not kept.get(field) and finding.get(field):
                kept[field] = finding.get(field)
    return list(merged.values())


def group_by_package(findings):
    """One entry per (package, installed version), worst severity first.

    Grouping by package rather than by advisory is what makes the report
    actionable: the unit of work is a version bump, not a CVE.
    """
    groups = {}
    for finding in findings:
        if finding.get("scope") != "dependency":
            continue
        groups.setdefault((finding.get("package"), finding.get("installed")), []).append(finding)

    ordered = []
    for (package, installed), items in groups.items():
        items = merge_occurrences(items)
        items.sort(key=lambda f: SEVERITY_RANK.get(f.get("severity", "UNKNOWN"), 99))
        fixes = sorted({str(f["fixed"]) for f in items if f.get("fixed")})
        detectors = {f.get("detector") for f in items if f.get("detector")}
        ordered.append({
            "package": package,
            "installed": installed,
            "fixed": fixes[0] if fixes else None,
            # Same discipline as version_in_range: an unknown stays an unknown.
            # Only a source that would have named a fix makes its absence mean
            # there is none.
            "fix_unknown": not fixes and bool(detectors) and detectors <= FIXLESS_DETECTORS,
            "findings": items,
            "rank": worst_rank(items),
        })
    # Worst severity first, then most findings: the biggest wins float up.
    ordered.sort(key=lambda g: (g["rank"], -len(g["findings"]), str(g["package"])))
    return ordered


def git_context(repo: Path):
    def git(*args):
        code, out, _ = run(["git", "-C", str(repo), *args], timeout=20)
        return out.strip() if code == 0 else None

    return {
        "branch": git("rev-parse", "--abbrev-ref", "HEAD"),
        "commit": git("rev-parse", "--short", "HEAD"),
        "committed_at": git("log", "-1", "--format=%cI"),
        "remote": git("config", "--get", "remote.origin.url"),
    }


def render(repo_name, context, groups, iac, errors, scanned_at, ecosystems):
    counts = summarize([f for g in groups for f in g["findings"]])
    total = sum(len(g["findings"]) for g in groups)
    lines = []
    add = lines.append

    add(f"# Audit sécurité — {repo_name} — {scanned_at[:10]}")
    add("")
    head = f"*{total} constat(s) sur les dépendances, répartis sur {len(groups)} paquet(s).*"
    add(head)
    add("")

    add("| Périmètre | Branche | Commit | Critical | High | Medium | Low |")
    add("|---|---|---|---|---|---|---|")
    add(f"| `{repo_name}` | `{context.get('branch') or '?'}` "
        f"| `{context.get('commit') or '?'}` "
        + "".join(f"| {counts.get(s, 0)} " for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"))
        + "|")
    add("")
    if ecosystems:
        add(f"Écosystèmes détectés : {', '.join(f'`{e}`' for e in ecosystems)}")
        add("")

    if not groups:
        add("## Rien à traiter")
        add("")
        add("Aucune dépendance vulnérable détectée dans l'arbre actuel.")
        add("")
    else:
        add(f"## À traiter ({total})")
        add("")
        add("*Groupé par paquet : l'unité de travail est une montée de version, "
            "pas une CVE.*")
        add("")
        for group in groups:
            if group["fixed"]:
                target = f"**{group['fixed']}**"
            elif group.get("fix_unknown"):
                # Never "no patch published" on a source that does not publish
                # patch versions: that would turn silence into an all-clear.
                target = "**correctif à vérifier** *(non indiqué par la source)*"
            else:
                target = "**aucun correctif publié**"
            add(f"### {group['package']} {group['installed']} → {target}")
            add("")
            for finding in group["findings"]:
                url = advisory_url(finding)
                identifier = str(finding.get("id"))
                link = f"[{identifier}]({url})" if url else identifier
                severity = SEVERITY_LABEL.get(finding.get("severity"), "?")
                mark = f"**{severity}**" if severity == "CRITICAL" else severity
                cvss = f" · CVSS {finding['cvss']}" if finding.get("cvss") else ""
                spread = len(finding.get("targets") or [])
                where = f" · {spread} emplacements" if spread > 1 else ""
                title = (finding.get("title") or "").strip()
                add(f"- {link} · {mark}{cvss}{where}"
                    + (f" — {title[:130]}" if title else ""))
            add("")

    if iac:
        add("## Configuration")
        add("")
        add("*Hygiène de conteneur et d'infrastructure, hors dépendances.*")
        add("")
        for finding in sorted(iac, key=lambda f: SEVERITY_RANK.get(f.get("severity", "UNKNOWN"), 99)):
            add(f"- `{finding.get('id')}` · {SEVERITY_LABEL.get(finding.get('severity'), '?')} "
                f"— {(finding.get('title') or '').strip()[:110]}"
                + (f" (`{finding.get('target')}`)" if finding.get("target") else ""))
        add("")

    add("## Couverture")
    add("")
    if errors:
        add("Cet audit est **partiel**. Ce qui n'a pas pu être analysé :")
        add("")
        for error in errors:
            add(f"- {error}")
    else:
        add("Aucune lacune : le scan a abouti sans erreur.")
    add("")
    add("---")
    add("")
    add(f"*Audit déterministe généré le {scanned_at}. Aucune fenêtre temporelle : "
        "reflète l'état complet de l'arbre de dépendances, pas seulement les avis récents.*")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Audit deterministe d'un depot, sans fenetre temporelle ni IA.")
    parser.add_argument("--repo", type=Path, default=Path("."),
                        help="chemin du depot a auditer (defaut : repertoire courant)")
    parser.add_argument("--name", default=None,
                        help="nom affiche (defaut : nom du dossier)")
    parser.add_argument("--out-md", type=Path, default=None,
                        help="rapport Markdown (defaut : stdout)")
    parser.add_argument("--out-json", type=Path, default=None,
                        help="constats bruts en JSON, pour une reprise par un agent")
    parser.add_argument("--no-dotnet", action="store_true",
                        help="ignore la resolution NuGet, qui exige un restore")
    parser.add_argument("--timeout", type=int, default=600)
    args = parser.parse_args()

    repo = args.repo.expanduser().resolve()
    if not repo.is_dir():
        print(f"ERREUR : {repo} n'est pas un repertoire.", file=sys.stderr)
        return 2

    trivy = which("trivy")
    if not trivy:
        print("ERREUR : trivy introuvable dans le PATH.", file=sys.stderr)
        print("  Windows : winget install AquaSecurity.Trivy", file=sys.stderr)
        print("  Linux   : voir README", file=sys.stderr)
        return 2

    name = args.name or repo.name
    print(f"[*] Trivy : {trivy_version(trivy)}", file=sys.stderr)
    print(f"[*] Audit de {name}", file=sys.stderr)

    ecosystems = detect_ecosystems(repo)
    findings, errors = trivy_scan_repo(trivy, repo, name, True, True, args.timeout)

    if "dotnet" in ecosystems:
        if args.no_dotnet:
            # Skipping on request is still a gap. Left unsaid, the coverage
            # section would announce a complete scan.
            errors.append("resolution NuGet ignoree (--no-dotnet) "
                          "[transitif .NET non couvert, direct scanne par Trivy]")
        else:
            net_findings, net_errors = scan_dotnet(repo, name, args.timeout)
            findings += net_findings
            errors += net_errors

    groups = group_by_package(findings)
    iac = [f for f in findings if f.get("scope") == "iac"]
    context = git_context(repo)
    scanned_at = datetime.now(timezone.utc).replace(microsecond=0).isoformat()

    markdown = render(name, context, groups, iac, errors, scanned_at, ecosystems)

    if args.out_md:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(markdown, encoding="utf-8")
        print(f"[+] Rapport : {args.out_md}", file=sys.stderr)
    else:
        print(markdown)

    if args.out_json:
        payload = {
            "schema": 1,
            "repo": {"name": name, "path": str(repo), **context},
            "scanned_at": scanned_at,
            "trivy": trivy_version(trivy),
            "ecosystems": ecosystems,
            "summary": {
                "packages": len(groups),
                "findings": sum(len(g["findings"]) for g in groups),
                "by_severity": summarize([f for g in groups for f in g["findings"]]),
                "iac": len(iac),
            },
            "packages": [{k: v for k, v in g.items() if k != "rank"} for g in groups],
            "iac": iac,
            "errors": errors,
        }
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(payload, indent=2, ensure_ascii=False),
                                 encoding="utf-8")
        print(f"[+] JSON    : {args.out_json}", file=sys.stderr)

    counts = summarize([f for g in groups for f in g["findings"]])
    print("[*] " + "  ".join(f"{s.lower()}={counts.get(s, 0)}"
                             for s in SEVERITY_ORDER if counts.get(s)), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

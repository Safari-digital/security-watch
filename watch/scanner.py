#!/usr/bin/env python3
"""
security-watch -- the primitives that read a repository's dependency tree.

Everything here answers one question: what is *this repository* exposed to,
according to its manifests and lockfiles. Nothing reads the machine it runs
on -- no installed packages, no local container images, no OS inventory.

Version-to-CVE matching happens in Trivy and in the .NET SDK, never here and
never in a model. This module normalises what they return and is careful about
one thing above all: when a source cannot answer, that is recorded as a gap,
not smoothed over. A partial scan presenting itself as complete is worse than
no scan.

Not a command. `watch/audit.py` is the entry point.

Requires Trivy on PATH, plus the .NET SDK for repositories that carry .NET.
Stdlib only otherwise. Python >= 3.9. Windows and Linux.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from fnmatch import fnmatch
from pathlib import Path

IS_WINDOWS = os.name == "nt"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# bin/ and obj/ are skipped on purpose: they hold potentially stale build-time
# *.deps.json, and .NET coverage comes from `dotnet list package` instead.
SKIP_DIRS = [
    "node_modules", "bin", "obj", "dist", "build", ".next", ".nuxt",
    "vendor", ".venv", "venv", "__pycache__", ".vs", ".idea", "TestResults",
]


# --------------------------------------------------------------------------
# Shell and parsing helpers
# --------------------------------------------------------------------------

def log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg, file=sys.stderr, flush=True)


def run(cmd, cwd=None, timeout=600):
    """Run a command. Returns (code, stdout, stderr). Never raises."""
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout apres {timeout}s"
    except (OSError, ValueError) as exc:
        return 127, "", str(exc)


def which(name: str):
    """shutil.which, tolerating a missing .exe suffix on Windows."""
    found = shutil.which(name)
    if found:
        return found
    if IS_WINDOWS:
        return shutil.which(name + ".exe")
    return None


def load_json(text: str):
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return None


def summarize(findings):
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        severity = finding.get("severity", "UNKNOWN")
        counts[severity] = counts.get(severity, 0) + 1
    return counts


# --------------------------------------------------------------------------
# What the repository is made of
# --------------------------------------------------------------------------

# Deep enough for apps/<service>/<project>/x.csproj in a monorepo, which is
# where a chain of `*/*/pattern` globs used to go blind: the ecosystem went
# undetected, its scan never ran, and the report still announced full coverage.
MANIFEST_DEPTH = 4


def find_manifests(repo: Path, pattern: str, limit: int = 200, depth: int = MANIFEST_DEPTH):
    """Files matching `pattern` under `repo`, pruning what Trivy also skips.

    A plain rglob descends into node_modules and takes minutes on a monorepo;
    pruning keeps it cheap without capping how deep a project may legitimately
    sit.
    """
    hits = []

    def walk(directory: Path, level: int):
        if len(hits) >= limit:
            return
        try:
            with os.scandir(directory) as entries_iter:
                entries = sorted(entries_iter, key=lambda e: e.name)
        except OSError:
            return
        for entry in entries:
            if entry.is_file():
                if fnmatch(entry.name, pattern):
                    hits.append(Path(entry.path))
                    if len(hits) >= limit:
                        return
            elif level < depth and entry.is_dir(follow_symlinks=False):
                if entry.name in SKIP_DIRS or entry.name.startswith("."):
                    continue
                walk(Path(entry.path), level + 1)

    walk(repo, 0)
    return hits


def detect_ecosystems(repo: Path):
    """Ecosystems present, from a pruned manifest search."""
    found = set()
    markers = {
        "npm": ["package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock"],
        # .slnx is the XML solution format shipped with the .NET 9 SDK; a repo
        # that has migrated to it carries no .sln at all.
        "dotnet": ["*.sln", "*.slnx", "*.csproj", "*.fsproj", "packages.lock.json"],
        "container": ["Dockerfile", "Containerfile", "docker-compose.yml",
                      "docker-compose.yaml", "compose.yml", "compose.yaml"],
        "python": ["requirements.txt", "pyproject.toml", "Pipfile.lock"],
        "go": ["go.mod"],
        "rust": ["Cargo.lock"],
        "java": ["pom.xml", "build.gradle"],
    }
    for eco, patterns in markers.items():
        for pattern in patterns:
            if find_manifests(repo, pattern, limit=1):
                found.add(eco)
                break
    return sorted(found)


# --------------------------------------------------------------------------
# Trivy -- lockfiles, manifests, and container/IaC configuration in the tree
# --------------------------------------------------------------------------

def trivy_version(trivy: str):
    code, out, _ = run([trivy, "--version"], timeout=60)
    if code != 0:
        return None
    return out.strip().splitlines()[0] if out.strip() else "unknown"


def parse_trivy_vulns(payload, repo=None):
    """Normalise the Vulnerabilities of a Trivy JSON output.

    `target` keeps the exact path Trivy reported (the manifest it read): it is
    what tells two legitimate occurrences of the same package apart within one
    repository.
    """
    findings = []
    for result in (payload.get("Results") or []):
        for vuln in (result.get("Vulnerabilities") or []):
            scores = []
            for vendor in (vuln.get("CVSS") or {}).values():
                for key in ("V3Score", "V4Score", "V2Score"):
                    if isinstance(vendor, dict) and isinstance(vendor.get(key), (int, float)):
                        scores.append(float(vendor[key]))
            findings.append({
                "scope": "dependency",
                "id": vuln.get("VulnerabilityID"),
                "package": vuln.get("PkgName"),
                "installed": vuln.get("InstalledVersion"),
                "fixed": vuln.get("FixedVersion") or None,
                "severity": (vuln.get("Severity") or "UNKNOWN").upper(),
                "cvss": max(scores) if scores else None,
                "title": vuln.get("Title"),
                "url": vuln.get("PrimaryURL"),
                "ecosystem": result.get("Type"),
                "repo": repo,
                "target": result.get("Target"),
                "detector": "trivy",
            })
    return findings


def parse_trivy_misconfigs(payload, repo=None):
    findings = []
    for result in (payload.get("Results") or []):
        for miscfg in (result.get("Misconfigurations") or []):
            findings.append({
                "scope": "iac",
                "id": miscfg.get("ID"),
                "severity": (miscfg.get("Severity") or "UNKNOWN").upper(),
                "title": miscfg.get("Title"),
                "message": miscfg.get("Message"),
                "resolution": miscfg.get("Resolution"),
                "url": miscfg.get("PrimaryURL"),
                "repo": repo,
                "target": result.get("Target"),
                "detector": "trivy-config",
            })
    return findings


def trivy_skip_args():
    """--skip-dirs is a glob against the path relative to the scan root.

    A bare name therefore only skips the one directory at the top. Nested
    build output stayed in scope: an audit of a monorepo once read 53 stale
    `bin/**/*.deps.json` out of 54 targets and turned 34 advisories into 82
    lines. Both forms are passed, since only the prefixed one is documented to
    match at depth and only the bare one is certain to match at the root.
    """
    args = []
    for name in SKIP_DIRS:
        args += ["--skip-dirs", name, "--skip-dirs", f"**/{name}"]
    return args


def trivy_scan_repo(trivy: str, repo: Path, label: str, do_vuln: bool, do_iac: bool, timeout: int):
    findings, errors = [], []

    if do_vuln:
        cmd = [trivy, "fs", "--scanners", "vuln", "--format", "json", "--quiet"]
        cmd += trivy_skip_args()
        cmd.append(str(repo))
        code, out, err = run(cmd, timeout=timeout)
        payload = load_json(out)
        if payload:
            findings += parse_trivy_vulns(payload, repo=label)
        elif code != 0:
            errors.append(f"trivy fs: {(err or '').strip()[:300]}")

    if do_iac:
        cmd = [trivy, "config", "--format", "json", "--quiet"]
        cmd += trivy_skip_args()
        cmd.append(str(repo))
        code, out, err = run(cmd, timeout=timeout)
        payload = load_json(out)
        if payload:
            findings += parse_trivy_misconfigs(payload, repo=label)
        elif code != 0:
            errors.append(f"trivy config: {(err or '').strip()[:300]}")

    return findings, errors


# --------------------------------------------------------------------------
# .NET -- transitive resolution through the SDK
# --------------------------------------------------------------------------

def dotnet_targets(repo: Path):
    """Solutions first, projects as the fallback tier.

    A solution covers all its projects, so it keeps the number of restores
    down. But `dotnet list` only accepts .slnx on recent SDKs, so the projects
    are kept as a second tier rather than discarded: an SDK too old to read the
    solution should cost extra invocations, not the whole transitive graph.
    """
    solutions = find_manifests(repo, "*.sln") + find_manifests(repo, "*.slnx")
    projects = find_manifests(repo, "*.csproj") + find_manifests(repo, "*.fsproj")
    tiers = []
    if solutions:
        tiers.append(sorted(solutions)[:5])
    if projects:
        tiers.append(sorted(projects)[:20])
    return tiers


def scan_dotnet(repo: Path, label: str, timeout: int):
    """`dotnet list package --vulnerable --include-transitive`.

    Requires a restore, so it fails when a private NuGet feed is unreachable or
    unauthenticated. The failure is recorded, never silently swallowed: a
    partial scan presenting itself as complete is worse than no scan.
    """
    dotnet = which("dotnet")
    if not dotnet:
        return [], ["dotnet introuvable "
                    "[transitif .NET non couvert, direct scanne par Trivy]"]

    tiers = dotnet_targets(repo)
    if not tiers:
        return [], ["dotnet : aucune solution ni projet trouve "
                    "[transitif .NET non couvert, direct scanne par Trivy]"]

    first_failure = []
    for rank, tier in enumerate(tiers):
        findings, errors = [], []
        for target in tier:
            cmd = [dotnet, "list", str(target), "package", "--vulnerable",
                   "--include-transitive", "--format", "json"]
            code, out, err = run(cmd, cwd=repo, timeout=timeout)
            payload = load_json(out)
            if not payload:
                reason = (err or out or "").strip().splitlines()
                detail = reason[-1][:200] if reason else f"code {code}"
                # Be precise about the blast radius: Trivy still read the
                # .csproj, so direct dependencies are covered. Only the
                # transitive graph is missing, and saying "not audited" would
                # overstate the gap.
                errors.append(f"dotnet list ({target.name}): {detail} "
                              "[transitif .NET non couvert, direct scanne par Trivy]")
                if rank and not findings:
                    # The fallback tier exists for a solution the SDK could not
                    # read, not for a feed it cannot reach. One project failing
                    # before any has succeeded means the restore itself is
                    # broken, and the remaining ones would only repeat it
                    # slowly.
                    break
                continue
            findings += parse_dotnet_vulns(payload, target, label)

        if findings or len(errors) < len(tier):
            # Something resolved, so this tier is the answer. Running the next
            # one as well would report the same packages twice.
            return findings, errors
        first_failure = first_failure or errors

    return [], first_failure


def parse_dotnet_vulns(payload, target: Path, label: str):
    findings = []
    for project in (payload.get("projects") or []):
        proj_name = Path(project.get("path") or str(target)).name
        for framework in (project.get("frameworks") or []):
            fw = framework.get("framework")
            for kind in ("topLevelPackages", "transitivePackages"):
                for pkg in (framework.get(kind) or []):
                    for vuln in (pkg.get("vulnerabilities") or []):
                        url = vuln.get("advisoryurl") or vuln.get("advisoryUrl")
                        findings.append({
                            "scope": "dependency",
                            "id": (url or "").rstrip("/").split("/")[-1] or "GHSA-?",
                            "package": pkg.get("id"),
                            "installed": pkg.get("resolvedVersion"),
                            # The SDK names where a vulnerability is, never
                            # which release fixes it. audit.py reads that
                            # silence as unknown, not as "no patch exists".
                            "fixed": None,
                            "severity": (vuln.get("severity") or "UNKNOWN").upper(),
                            "cvss": None,
                            "title": None,
                            "url": url,
                            "ecosystem": "nuget",
                            "repo": label,
                            "target": f"{proj_name} [{fw}]",
                            "transitive": kind == "transitivePackages",
                            "detector": "dotnet-sdk",
                        })
    return findings

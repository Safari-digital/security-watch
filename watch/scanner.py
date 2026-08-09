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
import re
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


def force_utf8_output():
    """Let stdout and stderr carry what the report is made of.

    Reports are French and use `→` between an installed version and its fix.
    A Windows console defaults to cp1252, which has no such character, so
    printing the report died with UnicodeEncodeError instead of producing it --
    and only when no output file was given, which is the quickest way to run
    the tool and the one the usage line shows first.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8")
        except (OSError, ValueError):
            # A stream that refuses is still usable; losing the report to an
            # encoding error would be worse than a mangled accent.
            pass


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


def parse_trivy_vulns(payload, repo=None, scope="dependency", image=None):
    """Normalise the Vulnerabilities of a Trivy JSON output.

    `target` keeps the exact path Trivy reported (the manifest it read): it is
    what tells two legitimate occurrences of the same package apart within one
    repository. `image` is set only for a base image, where the unit of work is
    the image rather than the package.
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
                "scope": scope,
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
                "image": image,
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
# Base images -- what the repository's Dockerfiles build on top of
# --------------------------------------------------------------------------
#
# `trivy fs` reads lockfiles and `trivy config` reads Dockerfile syntax;
# neither ever looks inside the image a Dockerfile starts from. A `FROM
# node:24-alpine` carrying a critical flaw in its OS packages was invisible,
# while the report announced full coverage because nothing had failed.
#
# This resolves the FROM lines and scans those images from the registry. Trivy
# pulls them itself -- no Docker daemon is involved, locally or in CI.

FROM_RE = re.compile(r"^\s*FROM\s+(.+?)\s*$", re.IGNORECASE)
ARG_RE = re.compile(r"^\s*ARG\s+([A-Za-z_]\w*)\s*=\s*(.*?)\s*$", re.IGNORECASE)
VAR_RE = re.compile(
    r"\$\{(?P<braced>[A-Za-z_]\w*)(?::?-(?P<default>[^}]*))?\}"
    r"|\$(?P<bare>[A-Za-z_]\w*)"
)

DOCKERFILE_PATTERNS = ["Dockerfile", "Dockerfile.*", "*.Dockerfile", "Containerfile"]


def find_dockerfiles(repo: Path):
    seen, files = set(), []
    for pattern in DOCKERFILE_PATTERNS:
        for path in find_manifests(repo, pattern):
            if path not in seen:
                seen.add(path)
                files.append(path)
    return sorted(files)


def expand_vars(value: str, args: dict):
    """Substitute ${VAR}, ${VAR:-default} and $VAR from the file's own ARGs.

    Only defaults declared in the Dockerfile are used. A variable supplied at
    build time cannot be known from the source, so it is reported unresolved
    rather than guessed -- an invented tag would be scanned as if it were real.
    """
    missing = []

    def replace(match):
        name = match.group("braced") or match.group("bare")
        if name in args:
            return args[name]
        default = match.group("default")
        if default is not None:
            return default
        missing.append(name)
        return match.group(0)

    return VAR_RE.sub(replace, value), missing


def parse_base_images(dockerfile: Path, repo: Path = None):
    """External images a Dockerfile builds on, plus the refs it could not resolve.

    Skips what is not an image: `scratch`, and any FROM pointing at an earlier
    build stage by name.
    """
    try:
        text = dockerfile.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return [], [f"{dockerfile.name} illisible : {exc}"]

    # A FROM can be split over several lines with a trailing backslash.
    text = re.sub(r"\\\s*\n\s*", " ", text)
    # Forward slashes even on Windows: this path is read in a GitHub issue,
    # next to the paths Trivy reports, which are always POSIX.
    where = dockerfile.relative_to(repo).as_posix() if repo else dockerfile.name

    args, stages, images, unresolved = {}, set(), [], []
    for line in text.splitlines():
        if line.lstrip().startswith("#"):
            continue

        arg = ARG_RE.match(line)
        if arg:
            args[arg.group(1)] = arg.group(2).strip("'\"")
            continue

        from_match = FROM_RE.match(line)
        if not from_match:
            continue

        tokens = from_match.group(1).split()
        index = 0
        while index < len(tokens) and tokens[index].startswith("--"):
            index += 1
        if index >= len(tokens):
            continue
        ref, missing = expand_vars(tokens[index], args)

        alias = None
        if index + 2 < len(tokens) and tokens[index + 1].lower() == "as":
            alias = tokens[index + 2].lower()

        if missing:
            unresolved.append(f"{where} : `{tokens[index]}` non resolu "
                              f"({', '.join('$' + m for m in missing)}) "
                              "[image de base non couverte]")
        # Checked before the alias is registered: a stage cannot refer to itself.
        elif ref.lower() not in stages and ref.lower() != "scratch":
            images.append({"ref": ref, "dockerfile": where, "stage": alias})

        if alias:
            stages.add(alias)

    return images, unresolved


def scan_images(trivy: str, images, timeout: int, limit: int = 10):
    """Scan each distinct base image. Returns (findings, errors, scanned).

    `scanned` carries what the vulnerability list alone does not say: which
    Dockerfile asked for the image, and whether its OS is past end of life --
    on an EOSL base no fix is ever coming, which outranks any single CVE.
    """
    origins = {}
    for entry in images:
        origins.setdefault(entry["ref"], []).append(entry)

    findings, errors, scanned = [], [], []
    refs = sorted(origins)
    if len(refs) > limit:
        # Never truncate in silence: a capped scan that looks complete is the
        # failure this whole module exists to close.
        errors.append(f"images de base : {len(refs)} references trouvees, "
                      f"seules les {limit} premieres ont ete scannees "
                      "[le reste non couvert]")
        refs = refs[:limit]

    for ref in refs:
        code, out, err = run(
            [trivy, "image", "--scanners", "vuln", "--format", "json", "--quiet", ref],
            timeout=timeout)
        payload = load_json(out)
        if not payload:
            reason = (err or out or "").strip().splitlines()
            detail = reason[-1][:200] if reason else f"code {code}"
            errors.append(f"trivy image ({ref}): {detail} [image de base non couverte]")
            continue

        findings += parse_trivy_vulns(payload, scope="image", image=ref)
        os_meta = (payload.get("Metadata") or {}).get("OS") or {}
        scanned.append({
            "ref": ref,
            "os": " ".join(filter(None, [os_meta.get("Family"), os_meta.get("Name")])) or None,
            "eosl": bool(os_meta.get("EOSL")),
            "dockerfiles": sorted({o["dockerfile"] for o in origins[ref]}),
            "stages": sorted({o["stage"] for o in origins[ref] if o["stage"]}),
        })

    return findings, errors, scanned


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

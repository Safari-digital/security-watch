#!/usr/bin/env python3
"""
security-watch -- local exposure scanner.

Writes snapshots/<machine>.json: the vulnerabilities actually present on THIS
machine (dependencies, IaC, transitive .NET, container images, OS packages,
installed software), plus the delta since the previous run.

Version-to-CVE matching happens here, deterministically, via Trivy and the .NET
SDK. No interpretation: writing the report is the watch side's job.

Stdlib only -- nothing to install. Python >= 3.9. Windows and Linux.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

AGENT_DIR = Path(__file__).resolve().parent
ROOT_DIR = AGENT_DIR.parent
SNAPSHOT_DIR = ROOT_DIR / "snapshots"
CONFIG_PATH = AGENT_DIR / "config.json"

SCHEMA_VERSION = 1
IS_WINDOWS = os.name == "nt"

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# bin/ and obj/ are skipped on purpose: they hold potentially stale build-time
# *.deps.json, and transitive .NET coverage comes from `dotnet list package`.
SKIP_DIRS = [
    "node_modules", "bin", "obj", "dist", "build", ".next", ".nuxt",
    "vendor", ".venv", "venv", "__pycache__", ".vs", ".idea", "TestResults",
]

LINUX_OS_SKIP = ["/proc", "/sys", "/dev", "/run", "/tmp", "/mnt", "/media", "/home", "/root"]

# Arch-family distributions. Trivy has no Arch support, so these fall back to a
# pacman inventory and are matched later against security.archlinux.org.
ARCH_LIKE = {"arch", "archarm", "manjaro", "endeavouros", "garuda", "cachyos", "artix"}

DEFAULT_CONFIG = {
    # `label` names the snapshot file, so it must stay stable and be distinct
    # across machines -- a hostname rarely tells you which box it was.
    "machine": {"label": None, "role": None},
    # Declared by hand: no PC-side scan can read a phone's patch level.
    "android": None,
    # Structural gaps you have accepted, so they stop reading as fresh
    # breakage. They stay visible in the report, but under "known limitations"
    # rather than mixed in with today's anomalies.
    # [{"repo": "acme/legacy-api", "scan": "dotnet", "reason": "..."}]
    "known_limitations": [],
    "roots": [],
    "exclude": [],
    "scan": {
        "projects": True,     # npm/pnpm/NuGet lockfiles via Trivy
        "iac": True,          # Dockerfile / compose / k8s via Trivy config
        "dotnet": True,       # transitive .NET dependencies via the SDK
        "containers": True,   # local podman/docker images
        "os": True,           # OS packages (Linux)
        "software": True,     # installed software (Windows) / pacman (Arch)
    },
    "container_engine": "auto",
    "repo_timeout_seconds": 300,
    "dotnet_timeout_seconds": 300,
    "os_timeout_seconds": 900,
    "container_image_limit": 15,
    "max_depth": 4,
}


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


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


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

def default_roots():
    """Likely project roots, per platform."""
    home = Path.home()
    candidates = [home / ".sources", home / "source" / "repos", home / "src",
                  home / "dev", home / "projects", home / "Projects"]
    return [str(p) for p in candidates if p.is_dir()]


def load_config(path: Path) -> dict:
    cfg = json.loads(json.dumps(DEFAULT_CONFIG))  # deep copy
    if path.is_file():
        user = load_json(path.read_text(encoding="utf-8")) or {}
        for key, value in user.items():
            if key == "scan" and isinstance(value, dict):
                cfg["scan"].update(value)
            else:
                cfg[key] = value
    if not cfg["roots"]:
        cfg["roots"] = default_roots()
    return cfg


# --------------------------------------------------------------------------
# Repository discovery
# --------------------------------------------------------------------------

def discover_repos(roots, exclude, max_depth):
    """Git repositories under the given roots. Does not descend into a repo."""
    excluded = [e.lower() for e in exclude]
    repos = []

    def walk(directory: Path, depth: int):
        if depth > max_depth:
            return
        if (directory / ".git").exists():
            repos.append(directory)
            return
        try:
            entries = list(directory.iterdir())
        except (PermissionError, OSError):
            return
        for entry in entries:
            if not entry.is_dir() or entry.is_symlink():
                continue
            if entry.name in SKIP_DIRS:
                continue
            if entry.name.startswith("."):
                # Hidden directories are skipped unless they are themselves a
                # repository (e.g. a repo named `.github`) or a known root.
                if not (entry / ".git").exists() and entry.name != ".sources":
                    continue
            if any(x in str(entry).lower() for x in excluded):
                continue
            walk(entry, depth + 1)

    for root in roots:
        path = Path(root).expanduser()
        if path.is_dir():
            walk(path, 0)
    return sorted(set(repos))


def git_remote(repo: Path):
    code, out, _ = run(["git", "-C", str(repo), "config", "--get", "remote.origin.url"], timeout=20)
    return out.strip() if code == 0 and out.strip() else None


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
# Trivy
# --------------------------------------------------------------------------

def trivy_version(trivy: str):
    code, out, _ = run([trivy, "--version"], timeout=60)
    if code != 0:
        return None
    return out.strip().splitlines()[0] if out.strip() else "unknown"


def parse_trivy_vulns(payload, scope, repo=None, image=None):
    """Normalise the Vulnerabilities of a Trivy JSON output.

    `target` keeps the exact path Trivy reported (the manifest or layer): it is
    what tells two legitimate occurrences of the same package apart within one
    repository. `repo` / `image` carry the attachment.
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
            findings += parse_trivy_vulns(payload, "dependency", repo=label)
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
                            "fixed": None,
                            "severity": (vuln.get("severity") or "UNKNOWN").upper(),
                            "cvss": None,
                            "title": None,
                            "url": url,
                            "ecosystem": "nuget",
                            "repo": label,
                            "image": None,
                            "target": f"{proj_name} [{fw}]",
                            "transitive": kind == "transitivePackages",
                            "detector": "dotnet-sdk",
                        })
    return findings


# --------------------------------------------------------------------------
# Containers -- podman or docker
# --------------------------------------------------------------------------

def detect_container_engine(preference="auto"):
    """(name, path) of the container engine, podman first."""
    order = ["podman", "docker"] if preference == "auto" else [preference]
    for name in order:
        path = which(name)
        if path:
            return name, path
    return None, None


def scan_container_image(trivy: str, engine_name: str, engine_path: str,
                         image: str, timeout: int):
    """Scan one local image.

    Trivy can talk to the Docker daemon directly, but Podman needs its socket,
    which is absent on Windows and on unconfigured rootless setups. So: try
    direct access first, then fall back to `save` into an archive read through
    --input. The fallback works everywhere.
    """
    direct = [trivy, "image", "--scanners", "vuln", "--format", "json", "--quiet", image]
    code, out, err = run(direct, timeout=timeout)
    payload = load_json(out)
    if payload:
        return payload, None

    tmpdir = tempfile.mkdtemp(prefix="security-watch-")
    archive = Path(tmpdir) / "image.tar"
    try:
        scode, _, serr = run([engine_path, "save", "-o", str(archive), image], timeout=timeout)
        if scode != 0 or not archive.is_file():
            return None, f"{engine_name} save {image}: {(serr or err or '').strip()[:200]}"

        cmd = [trivy, "image", "--scanners", "vuln", "--format", "json",
               "--quiet", "--input", str(archive)]
        icode, iout, ierr = run(cmd, timeout=timeout)
        payload = load_json(iout)
        if payload:
            return payload, None
        return None, f"trivy image --input {image}: {(ierr or '').strip()[:200]}"
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def scan_containers(trivy: str, preference: str, limit: int, timeout: int):
    engine_name, engine_path = detect_container_engine(preference)
    if not engine_name:
        return [], [], ["ni podman ni docker dans le PATH -- scan d'images ignore"], None

    code, out, err = run([engine_path, "images", "--format",
                          "{{.Repository}}:{{.Tag}}"], timeout=120)
    if code != 0:
        detail = " ".join((err or "").split())[:200]
        # On Windows and macOS podman runs inside a VM that has to be started.
        if engine_name == "podman" and "connect" in detail.lower():
            detail += "  [indice : `podman machine start`]"
        return [], [], [f"{engine_name} images: {detail}"], engine_name

    images = sorted({line.strip() for line in out.splitlines()
                     if line.strip() and "<none>" not in line})
    scanned, findings, errors = [], [], []

    if len(images) > limit:
        errors.append(f"{len(images)} images locales, seules les {limit} premieres "
                      f"sont scannees (ajuste container_image_limit)")
        images = images[:limit]

    for image in images:
        payload, error = scan_container_image(trivy, engine_name, engine_path, image, timeout)
        if error:
            errors.append(error)
            continue
        image_findings = parse_trivy_vulns(payload, "container", image=image)
        findings += image_findings
        scanned.append({
            "image": image,
            "engine": engine_name,
            "findings": len(image_findings),
            "severity": summarize(image_findings),
        })

    return scanned, findings, errors, engine_name


# --------------------------------------------------------------------------
# Operating system
# --------------------------------------------------------------------------

def linux_distro():
    """(id, pretty name) from /etc/os-release."""
    values = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                values[key.strip()] = value.strip().strip('"')
    except OSError:
        return None, None
    return (values.get("ID") or "").lower() or None, values.get("PRETTY_NAME")


def arch_installed_packages():
    """Installed pacman packages and their versions.

    Trivy does not know Arch, so no finding can be produced here. We collect the
    raw inventory and matching happens on the watch side against
    security.archlinux.org -- the same split as on Windows.
    """
    pacman = which("pacman")
    if not pacman:
        return [], ["pacman introuvable : inventaire des paquets Arch impossible"]

    code, out, err = run([pacman, "-Q"], timeout=180)
    if code != 0:
        return [], [f"pacman -Q: {(err or '').strip()[:200]}"]

    packages = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            packages.append({"name": parts[0], "version": parts[1], "source": "pacman"})
    if not packages:
        return [], ["pacman -Q n'a retourne aucun paquet"]
    return packages, []


def scan_os_linux(trivy: str, timeout: int):
    cmd = [trivy, "rootfs", "--scanners", "vuln", "--format", "json", "--quiet"]
    for skip in LINUX_OS_SKIP:
        cmd += ["--skip-dirs", skip]
    cmd.append("/")
    code, out, err = run(cmd, timeout=timeout)
    payload = load_json(out)
    if payload:
        return parse_trivy_vulns(payload, "os"), []
    return [], [f"trivy rootfs: {(err or '').strip()[:300]}"]


def windows_installed_software():
    """Registry inventory. CVE matching happens on the watch side."""
    try:
        import winreg  # noqa: PLC0415 -- Windows only
    except ImportError:
        return [], ["winreg indisponible"]

    hives = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    software, seen, errors = [], set(), []

    for hive, subkey in hives:
        try:
            base = winreg.OpenKey(hive, subkey)
        except OSError:
            continue
        try:
            count = winreg.QueryInfoKey(base)[0]
            for index in range(count):
                try:
                    name = winreg.EnumKey(base, index)
                    entry = winreg.OpenKey(base, name)
                except OSError:
                    continue
                values = {}
                try:
                    for value_index in range(winreg.QueryInfoKey(entry)[1]):
                        key_name, data, _ = winreg.EnumValue(entry, value_index)
                        values[key_name] = data
                except OSError:
                    pass
                finally:
                    entry.Close()

                display = values.get("DisplayName")
                # Drop cumulative updates and system components.
                if not display or values.get("SystemComponent") == 1:
                    continue
                if display.startswith("Update for") or display.startswith("Security Update"):
                    continue
                key = (str(display).strip(), str(values.get("DisplayVersion") or "").strip())
                if key in seen:
                    continue
                seen.add(key)
                software.append({
                    "name": key[0],
                    "version": key[1] or None,
                    "publisher": (values.get("Publisher") or None),
                    "source": "registry",
                })
        finally:
            base.Close()

    if not software:
        errors.append("aucun logiciel lu depuis la base de registre")
    return sorted(software, key=lambda s: s["name"].lower()), errors


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

def finding_key(finding: dict):
    """Stable identity of a finding, used for the delta.

    Includes `target`: the same vulnerable package in two different manifests is
    two fixes to make, not a duplicate.
    """
    return "|".join(str(finding.get(f) or "") for f in
                    ("scope", "id", "package", "installed", "repo", "image", "target"))


def group_for_display(findings):
    """Collapse identical occurrences of one CVE for console display."""
    grouped = {}
    for finding in findings:
        key = (finding.get("severity"), finding.get("id"), finding.get("package"),
               finding.get("repo") or finding.get("image"))
        if key in grouped:
            grouped[key]["occurrences"] += 1
        else:
            grouped[key] = dict(finding, occurrences=1)
    return list(grouped.values())


def summarize(findings):
    counts = {sev: 0 for sev in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.get("severity", "UNKNOWN")] = counts.get(finding.get("severity", "UNKNOWN"), 0) + 1
    return counts


def build_inventory(cfg, args):
    quiet = args.quiet
    trivy = which("trivy")
    if not trivy:
        print("ERREUR : trivy introuvable dans le PATH.", file=sys.stderr)
        print("  Windows : .\\scan.ps1  (installe Trivy automatiquement)", file=sys.stderr)
        print("  Linux   : ./scan.sh", file=sys.stderr)
        return None

    scan = cfg["scan"]
    started = now_iso()
    errors, projects, all_findings, limitations = [], [], [], []

    trivy_ver = trivy_version(trivy)
    log(f"[*] Trivy : {trivy_ver}", quiet)

    repos = discover_repos(cfg["roots"], cfg.get("exclude", []), cfg.get("max_depth", 4))
    log(f"[*] {len(repos)} depots decouverts sous {', '.join(cfg['roots'])}", quiet)

    for index, repo in enumerate(repos, 1):
        label = repo.name
        try:
            label = str(repo.relative_to(Path.home())).replace("\\", "/")
        except ValueError:
            label = str(repo)

        log(f"[{index}/{len(repos)}] {label}", quiet)
        ecosystems = detect_ecosystems(repo)
        repo_findings, repo_errors = trivy_scan_repo(
            trivy, repo, label,
            do_vuln=scan.get("projects", True),
            do_iac=scan.get("iac", True),
            timeout=cfg.get("repo_timeout_seconds", 300),
        )

        if scan.get("dotnet", True) and "dotnet" in ecosystems:
            declared = known_limitation(cfg, label, "dotnet")
            if declared:
                # Skip the call entirely rather than let it fail: a command we
                # already know will fail produces noise, not information.
                limitations.append({
                    "repo": label,
                    "scan": "dotnet",
                    "reason": declared.get("reason") or "resolution NuGet indisponible",
                    "impact": "dependances .NET transitives non couvertes ; "
                              "les dependances directes restent scannees par Trivy",
                })
            else:
                net_findings, net_errors = scan_dotnet(
                    repo, label, cfg.get("dotnet_timeout_seconds", 300))
                repo_findings += net_findings
                repo_errors += net_errors

        projects.append({
            "path": str(repo),
            "label": label,
            "remote": git_remote(repo),
            "ecosystems": ecosystems,
            "findings": len(repo_findings),
            "severity": summarize(repo_findings),
            "errors": repo_errors,
        })
        all_findings += repo_findings
        errors += [f"{label}: {e}" for e in repo_errors]

    images, engine_used = [], None
    if scan.get("containers", True):
        log("[*] Images de conteneurs", quiet)
        images, container_findings, container_errors, engine_used = scan_containers(
            trivy,
            cfg.get("container_engine", "auto"),
            cfg.get("container_image_limit", 15),
            cfg.get("repo_timeout_seconds", 300),
        )
        all_findings += container_findings
        errors += container_errors

    software, distro_id, distro_name = [], None, None
    if scan.get("os", True) or scan.get("software", True):
        log("[*] Systeme", quiet)
        if IS_WINDOWS:
            if scan.get("software", True):
                software, sw_errors = windows_installed_software()
                errors += sw_errors
        else:
            distro_id, distro_name = linux_distro()
            if distro_id in ARCH_LIKE:
                if scan.get("software", True):
                    log(f"[*] Paquets pacman ({distro_name or distro_id})", quiet)
                    software, sw_errors = arch_installed_packages()
                    errors += sw_errors
            elif scan.get("os", True):
                os_findings, os_errors = scan_os_linux(trivy, cfg.get("os_timeout_seconds", 900))
                all_findings += os_findings
                errors += os_errors

    all_findings.sort(key=lambda f: (SEVERITY_RANK.get(f.get("severity", "UNKNOWN"), 99),
                                     str(f.get("target")), str(f.get("id"))))

    machine = cfg.get("machine") or {}
    return {
        "schema": SCHEMA_VERSION,
        "machine": {
            "label": machine.get("label") or socket.gethostname(),
            "role": machine.get("role"),
            "hostname": socket.gethostname(),
        },
        "android": cfg.get("android"),
        "host": {
            "name": socket.gethostname(),
            "os": platform.system(),
            "distro": distro_id,
            "distro_name": distro_name,
            "release": platform.release(),
            "version": platform.version(),
            "arch": platform.machine(),
            "python": platform.python_version(),
        },
        "scan": {
            "started_at": started,
            "finished_at": now_iso(),
            "roots": cfg["roots"],
            "enabled": scan,
            "trivy": trivy_ver,
            "dotnet": (run([which("dotnet"), "--version"], timeout=30)[1].strip()
                       if which("dotnet") else None),
            "container_engine": engine_used or detect_container_engine(
                cfg.get("container_engine", "auto"))[0],
        },
        "projects": projects,
        "images": images,
        "installed_software": software,
        "limitations": limitations,
        "findings": all_findings,
        "summary": {
            "projects": len(projects),
            "findings_total": len(all_findings),
            "by_severity": summarize(all_findings),
            "software_count": len(software),
        },
        "errors": errors,
    }


def apply_diff(inventory: dict, previous: dict):
    """Add new / resolved findings relative to the previous run."""
    if not previous:
        inventory["delta"] = {"previous_scan": None, "new": [], "resolved": [],
                              "note": "premier passage : pas de comparaison possible"}
        return inventory

    prev_keys = {finding_key(f): f for f in (previous.get("findings") or [])}
    curr_keys = {finding_key(f): f for f in (inventory.get("findings") or [])}

    new = [f for key, f in curr_keys.items() if key not in prev_keys]
    resolved = [f for key, f in prev_keys.items() if key not in curr_keys]

    inventory["delta"] = {
        "previous_scan": (previous.get("scan") or {}).get("finished_at"),
        "new": new,
        "resolved": resolved,
        "new_count": len(new),
        "resolved_count": len(resolved),
    }
    return inventory


def known_limitation(cfg, label: str, step: str):
    """The declared limitation for this repo and scan step, if any."""
    for entry in (cfg.get("known_limitations") or []):
        repo = str(entry.get("repo") or "").lower()
        if repo and repo in label.lower() and entry.get("scan") == step:
            return entry
    return None


def slugify(label: str) -> str:
    """Safe filename: the label comes from user-supplied config."""
    cleaned = "".join(c if (c.isalnum() or c in "-_") else "-" for c in label.strip())
    while "--" in cleaned:
        cleaned = cleaned.replace("--", "-")
    return cleaned.strip("-").lower() or "machine"


def push_snapshot(output: Path, label: str):
    """Commit and push the snapshot file only.

    Deliberately narrow: `git commit -- <path>` commits just that file even when
    other changes sit in the index. A scan has no business shipping work in
    progress.
    """
    repo = ROOT_DIR
    code, _, _ = run(["git", "-C", str(repo), "rev-parse", "--is-inside-work-tree"], timeout=30)
    if code != 0:
        return False, f"{repo} n'est pas un depot git"

    code, _, err = run(["git", "-C", str(repo), "add", "--", str(output)], timeout=60)
    if code != 0:
        return False, f"git add: {err.strip()[:200]}"

    # `diff --cached --quiet` exits 1 when staged changes exist.
    code, _, _ = run(["git", "-C", str(repo), "diff", "--cached", "--quiet",
                      "--", str(output)], timeout=60)
    if code == 0:
        return True, "snapshot inchange, rien a pousser"

    message = f"snapshot({label}): {datetime.now(timezone.utc).date().isoformat()}"
    code, _, err = run(["git", "-C", str(repo), "commit", "-m", message,
                        "--", str(output)], timeout=120)
    if code != 0:
        return False, f"git commit: {err.strip()[:200]}"

    code, _, err = run(["git", "-C", str(repo), "push"], timeout=180)
    if code != 0:
        return False, f"commit local fait, mais push echoue: {err.strip()[:200]}"
    return True, "commite et pousse"


def print_report(inventory: dict):
    summary = inventory["summary"]
    by_sev = summary["by_severity"]
    host = inventory["host"]
    machine = inventory.get("machine", {})
    delta = inventory.get("delta", {})

    identity = machine.get("label") or host["name"]
    if machine.get("role"):
        identity += f" ({machine['role']})"
    system = host.get("distro_name") or f"{host['os']} {host['release']}"

    print()
    print(f"  security-watch -- {identity} — {system}")
    print(f"  {inventory['scan']['finished_at']}")
    print()
    print(f"  Depots scannes      : {summary['projects']}")
    print(f"  Constats            : {summary['findings_total']}")
    print("  Par severite        : " + "  ".join(
        f"{sev.lower()}={by_sev.get(sev, 0)}" for sev in SEVERITY_ORDER if by_sev.get(sev)))
    if summary["software_count"]:
        kind = "Paquets" if host.get("distro") in ARCH_LIKE else "Logiciels"
        print(f"  {kind} inventories : {summary['software_count']}")
    if delta.get("previous_scan"):
        print(f"  Depuis le {delta['previous_scan']} : "
              f"+{delta.get('new_count', 0)} nouveaux / -{delta.get('resolved_count', 0)} corriges")
    print()

    critical = group_for_display(
        [f for f in inventory["findings"] if f.get("severity") in ("CRITICAL", "HIGH")])
    if critical:
        print(f"  Top {min(15, len(critical))} critical/high (sur {len(critical)} distincts) :")
        for finding in critical[:15]:
            fixed = f" -> {finding['fixed']}" if finding.get("fixed") else " (pas de correctif)"
            pkg = finding.get("package") or finding.get("title") or ""
            times = f"  (x{finding['occurrences']})" if finding.get("occurrences", 1) > 1 else ""
            print(f"    [{finding['severity']:<8}] {str(finding.get('id')):<22} "
                  f"{pkg} {finding.get('installed') or ''}{fixed}{times}")
            print(f"{'':<14}  {finding.get('repo') or finding.get('image')}")
        print()

    if inventory.get("errors"):
        print(f"  {len(inventory['errors'])} avertissement(s) -- voir le champ `errors` du JSON :")
        for err in inventory["errors"][:8]:
            print(f"    - {err}")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="security-watch local exposure scanner.")
    parser.add_argument("--config", type=Path, default=CONFIG_PATH,
                        help="chemin du config.json (defaut : agent/config.json)")
    parser.add_argument("--output", type=Path, default=None,
                        help="fichier de sortie (defaut : snapshots/<machine>.json)")
    parser.add_argument("--roots", nargs="*", default=None,
                        help="racines a scanner, remplace la config")
    parser.add_argument("--only", nargs="*", default=None,
                        choices=["projects", "iac", "dotnet", "containers", "os", "software"],
                        help="restreint le scan a ces etapes")
    parser.add_argument("--quiet", action="store_true", help="masque la progression")
    parser.add_argument("--no-report", action="store_true", help="pas de resume console")
    parser.add_argument("--machine", default=None,
                        help="label du poste, remplace la config (ex: laptop, fixe-arch)")
    parser.add_argument("--role", default=None,
                        help="role du poste, remplace la config")
    parser.add_argument("--push", action="store_true",
                        help="commit et pousse le snapshot (ce fichier uniquement)")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.roots:
        cfg["roots"] = args.roots
    if args.machine:
        cfg.setdefault("machine", {})["label"] = args.machine
    if args.role:
        cfg.setdefault("machine", {})["role"] = args.role
    if args.only:
        cfg["scan"] = {key: (key in args.only) for key in DEFAULT_CONFIG["scan"]}

    if not cfg["roots"]:
        print("ERREUR : aucune racine de projets trouvee. Renseigne `roots` dans "
              f"{args.config} ou passe --roots.", file=sys.stderr)
        return 2

    inventory = build_inventory(cfg, args)
    if inventory is None:
        return 2

    label = inventory["machine"]["label"]
    output = args.output or (SNAPSHOT_DIR / f"{slugify(label)}.json")
    output.parent.mkdir(parents=True, exist_ok=True)

    previous = load_json(output.read_text(encoding="utf-8")) if output.is_file() else None
    inventory = apply_diff(inventory, previous)

    output.write_text(json.dumps(inventory, indent=2, ensure_ascii=False), encoding="utf-8")

    if not args.no_report:
        print_report(inventory)
    print(f"  Snapshot ecrit : {output}")

    if args.push:
        ok, detail = push_snapshot(output, slugify(label))
        print(f"  {'Push' if ok else 'ECHEC push'} : {detail}")
        if not ok:
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

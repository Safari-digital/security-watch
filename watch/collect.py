#!/usr/bin/env python3
"""
security-watch -- advisory feed collection.

Fetches what was published worldwide over a sliding window and normalises it
into a single JSON file. No interpretation here: collect, normalise, log the
failures. Ranking and writing come later.

Sources:
  - CISA KEV        actively exploited flaws (highest signal)
  - GitHub Advisory npm + NuGet, the most reactive source for this stack
  - CERT-FR         ANSSI advisories and alerts (French context)
  - Arch Linux      still-open vulnerability groups (a STATE source)
  - Microsoft MSRC  Patch Tuesday, filtered to this fleet's products
  - Containers      runc, containerd, podman, docker, buildah (via OSV)
  - Android         monthly bulletins (via the OSV archive)
  - EPSS            exploitation probability, to rank what is not in KEV

Note on Arch: that source exposes no date. It describes a current state, not a
feed. Its entries carry `dateless: true` and must not be read as "published
today".

Stdlib only. Output: watch/out/feed-<date>.json
"""

from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

WATCH_DIR = Path(__file__).resolve().parent
OUT_DIR = WATCH_DIR / "out"

USER_AGENT = "security-watch/1.0 (+https://github.com/safaridigital/security-watch)"
HTTP_TIMEOUT = 60

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
GHSA_URL = "https://api.github.com/advisories"
EPSS_URL = "https://api.first.org/data/v1/epss"
CERTFR_FEEDS = {
    "certfr_avis": "https://www.cert.ssi.gouv.fr/avis/feed/",
    "certfr_alerte": "https://www.cert.ssi.gouv.fr/alerte/feed/",
}

# Tracked ecosystems. The stack is Node + .NET; others stay reachable via
# --ecosystems.
DEFAULT_ECOSYSTEMS = ["npm", "nuget"]


ARCH_ISSUES_URL = "https://security.archlinux.org/issues/all.json"
MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_ANDROID_ZIP = "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip"

# Tracked container projects, as named in OSV's Go ecosystem.
CONTAINER_PACKAGES = [
    "github.com/opencontainers/runc",
    "github.com/containerd/containerd",
    "github.com/containers/podman/v4",
    "github.com/containers/podman/v5",
    "github.com/docker/docker",
    "github.com/moby/moby",
    "github.com/containers/buildah",
    "github.com/containers/image/v5",
]

# A monthly MSRC document spans the whole Microsoft catalogue (Azure, Office,
# SQL...). Keep only what touches this fleet.
MSRC_PRODUCT_FILTER = re.compile(
    r"windows|\.net|asp\.net|visual studio|iis|microsoft edge|powershell|wsl",
    re.IGNORECASE)

MSRC_SEVERITIES = {"critical", "important", "moderate", "low"}

# The MSRC catalogue mixes the Windows Patch Tuesday with Azure Linux / CBL
# Mariner release notes, which are revised continuously and therefore top any
# date sort. Without this filter you get Mariner kernels and zero Windows CVEs.
MSRC_DOC_KEEP = re.compile(r"security updates", re.IGNORECASE)
MSRC_DOC_DROP = re.compile(r"mariner|azure linux|release notes", re.IGNORECASE)

# MSRC fills ReleaseDate with a sentinel when the date is unset; the real one
# lives in RevisionHistory.
MSRC_DATE_SENTINEL = "0001-01-01"


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime) -> str:
    return dt.replace(microsecond=0).isoformat()


def log(msg: str, quiet: bool = False) -> None:
    if not quiet:
        print(msg, file=sys.stderr, flush=True)


def http_get(url: str, headers=None, timeout=HTTP_TIMEOUT):
    """Plain GET. Returns (bytes, None) or (None, error message)."""
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            if response.headers.get("Content-Encoding") == "gzip":
                raw = gzip.decompress(raw)
            return raw, None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code} sur {url}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, f"{type(exc).__name__} sur {url}: {exc}"


def http_json(url: str, headers=None, timeout=HTTP_TIMEOUT):
    raw, error = http_get(url, headers, timeout=timeout)
    if error:
        return None, error
    try:
        return json.loads(raw.decode("utf-8")), None
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"JSON invalide depuis {url}: {exc}"


def http_json_post(url: str, body: dict, timeout=HTTP_TIMEOUT):
    payload = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8")), None
    except urllib.error.HTTPError as exc:
        return None, f"HTTP {exc.code} sur {url}"
    except (urllib.error.URLError, TimeoutError, OSError,
            json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, f"{type(exc).__name__} sur {url}: {exc}"


LINK_NEXT_RE = re.compile(r'<([^>]+)>;\s*rel="next"')


def http_json_paged(url: str, headers=None, timeout=HTTP_TIMEOUT):
    """GET returning (payload, next_url, error), following the Link header.

    GitHub's advisories endpoint paginates by cursor (`before`/`after`), not by
    `page`. A `page=N` parameter is silently ignored and returns the first page
    again -- which is how a 7-day window once produced every advisory five
    times over.
    """
    request = urllib.request.Request(
        url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            link = response.headers.get("Link") or ""
    except urllib.error.HTTPError as exc:
        return None, None, f"HTTP {exc.code} sur {url}"
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return None, None, f"{type(exc).__name__} sur {url}: {exc}"

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, None, f"JSON invalide depuis {url}: {exc}"

    match = LINK_NEXT_RE.search(link)
    return payload, (match.group(1) if match else None), None


def parse_dt(value):
    """Lenient ISO date (Z suffix, fractions, offsets). None if unreadable."""
    if not value:
        return None
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(str(value)[:19], fmt)
                break
            except ValueError:
                continue
        else:
            return None
    return parsed.replace(tzinfo=timezone.utc) if parsed.tzinfo is None else parsed


# --------------------------------------------------------------------------
# CISA KEV -- exploited in the wild
# --------------------------------------------------------------------------

def collect_kev(since: datetime):
    payload, error = http_json(KEV_URL)
    if error:
        return [], error

    entries = []
    for item in (payload.get("vulnerabilities") or []):
        added = item.get("dateAdded")
        try:
            added_dt = datetime.strptime(added, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except (TypeError, ValueError):
            continue
        if added_dt < since:
            continue
        entries.append({
            "source": "cisa-kev",
            "id": item.get("cveID"),
            "aliases": [item.get("cveID")],
            "vendor": item.get("vendorProject"),
            "product": item.get("product"),
            "title": item.get("vulnerabilityName"),
            "summary": item.get("shortDescription"),
            "action": item.get("requiredAction"),
            "due": item.get("dueDate"),
            "ransomware": item.get("knownRansomwareCampaignUse") == "Known",
            "published": added,
            "url": f"https://nvd.nist.gov/vuln/detail/{item.get('cveID')}",
            "exploited": True,
        })
    return entries, None


# --------------------------------------------------------------------------
# GitHub Advisory Database -- npm and NuGet
# --------------------------------------------------------------------------

def collect_ghsa(ecosystem: str, since: datetime, token=None, max_pages=5):
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    params = urllib.parse.urlencode({
        "ecosystem": ecosystem,
        "published": f">{since.date().isoformat()}",
        "per_page": 100,
        "sort": "published",
        "direction": "desc",
    })
    url = f"{GHSA_URL}?{params}"

    entries, errors, seen, page = [], [], set(), 0
    while url and page < max_pages:
        page += 1
        payload, url, error = http_json_paged(url, headers)
        if error:
            errors.append(error)
            break
        if not payload:
            break

        for item in payload:
            # Belt and braces: a cursor that ever repeats must not double the
            # feed. Duplicates here would be counted twice in every report.
            if item.get("ghsa_id") in seen:
                continue
            seen.add(item.get("ghsa_id"))
            aliases = [item.get("cve_id")] if item.get("cve_id") else []
            packages = []
            for vuln in (item.get("vulnerabilities") or []):
                package = (vuln.get("package") or {})
                packages.append({
                    "ecosystem": package.get("ecosystem"),
                    "name": package.get("name"),
                    "vulnerable_range": vuln.get("vulnerable_version_range"),
                    "first_patched": vuln.get("first_patched_version"),
                })
            cvss = (item.get("cvss") or {})
            epss = (item.get("epss") or {})
            entries.append({
                "source": "ghsa",
                "id": item.get("ghsa_id"),
                "aliases": aliases,
                "ecosystem": ecosystem,
                "packages": packages,
                "severity": (item.get("severity") or "unknown").upper(),
                "cvss": cvss.get("score"),
                "epss": epss.get("percentage"),
                "title": item.get("summary"),
                "summary": (item.get("description") or "")[:600],
                "published": item.get("published_at"),
                "url": item.get("html_url"),
                "exploited": False,
            })

    if url and page >= max_pages:
        errors.append(f"{ecosystem}: pagination arretee a {max_pages} pages, "
                      "des avis plus anciens de la fenetre sont manquants")

    return entries, errors


# --------------------------------------------------------------------------
# CERT-FR (ANSSI) -- RSS feeds
# --------------------------------------------------------------------------

def collect_certfr(name: str, url: str, since: datetime):
    raw, error = http_get(url)
    if error:
        return [], error
    try:
        root = ET.fromstring(raw)
    except ET.ParseError as exc:
        return [], f"RSS invalide ({name}): {exc}"

    entries = []
    for item in root.iterfind(".//item"):
        def text(tag):
            node = item.find(tag)
            return (node.text or "").strip() if node is not None and node.text else None

        published_raw = text("pubDate")
        published_dt = None
        for fmt in ("%a, %d %b %Y %H:%M:%S %z", "%a, %d %b %Y %H:%M:%S %Z"):
            try:
                published_dt = datetime.strptime(published_raw, fmt)
                break
            except (TypeError, ValueError):
                continue
        if published_dt is None:
            continue
        if published_dt.tzinfo is None:
            published_dt = published_dt.replace(tzinfo=timezone.utc)
        if published_dt < since:
            continue

        entries.append({
            "source": name,
            "id": text("link"),
            "aliases": [],
            "title": text("title"),
            "summary": (text("description") or "")[:600],
            "published": iso(published_dt),
            "url": text("link"),
            "exploited": False,
        })
    return entries, None


# --------------------------------------------------------------------------
# Arch Linux -- a STATE source, not a feed
# --------------------------------------------------------------------------

def collect_arch():
    """Still-open Arch vulnerability groups.

    This source exposes no date: it describes a state, not a feed. So only
    entries still marked `Vulnerable` are returned, with their affected and
    fixed versions -- which makes exposure genuinely computable downstream
    rather than merely informative.
    """
    payload, error = http_json(ARCH_ISSUES_URL)
    if error:
        return [], error

    entries = []
    for item in payload or []:
        if str(item.get("status", "")).lower() != "vulnerable":
            continue
        cves = [c for c in (item.get("issues") or []) if c]
        entries.append({
            "source": "arch",
            "id": item.get("name"),
            "aliases": cves,
            "ecosystem": "arch",
            "packages": [{"ecosystem": "arch", "name": name,
                          "vulnerable_range": item.get("affected"),
                          "first_patched": item.get("fixed")}
                         for name in (item.get("packages") or [])],
            "severity": (item.get("severity") or "UNKNOWN").upper(),
            "title": f"{', '.join(item.get('packages') or [])} — {item.get('type') or 'vulnerabilite'}",
            "summary": f"Statut Arch : {item.get('status')}. "
                       f"Affecte {item.get('affected')}, corrige en "
                       f"{item.get('fixed') or 'aucune version publiee'}.",
            "published": None,
            "dateless": True,
            "url": f"https://security.archlinux.org/{item.get('name')}",
            "exploited": False,
        })
    return entries, None


# --------------------------------------------------------------------------
# Microsoft MSRC -- Patch Tuesday
# --------------------------------------------------------------------------

def msrc_product_map(document):
    """ProductID -> readable name, from the CVRF document's product tree."""
    mapping = {}

    def walk(node):
        for product in (node.get("FullProductName") or []):
            if product.get("ProductID"):
                mapping[str(product["ProductID"])] = product.get("Value") or ""
        for branch in (node.get("Branch") or []):
            walk(branch)

    walk(document.get("ProductTree") or {})
    return mapping


def collect_msrc(since: datetime, max_documents=2):
    """Microsoft CVEs published within the window, restricted to this fleet.

    The monthly document weighs several MB and covers the whole Microsoft
    catalogue. Filtering on products matters: otherwise Azure and Office drown
    the handful of Windows CVEs that actually count.
    """
    payload, error = http_json(MSRC_UPDATES_URL)
    if error:
        return [], [error]

    candidates = []
    for update in (payload.get("value") or []):
        title = update.get("DocumentTitle") or ""
        if MSRC_DOC_KEEP.search(title) and not MSRC_DOC_DROP.search(title):
            candidates.append(update)
    # Most recently published first: alphabetical ID order ("2026-Aug" before
    # "2026-Jul") is not chronological.
    candidates.sort(key=lambda u: u.get("InitialReleaseDate") or "", reverse=True)

    if not candidates:
        return [], ["MSRC : aucun document 'Security Updates' dans le catalogue"]

    entries, errors = [], []
    for update in candidates[:max_documents]:
        url = update.get("CvrfUrl")
        if not url:
            continue
        document, doc_error = http_json(url, {"Accept": "application/json"})
        if doc_error:
            errors.append(f"MSRC {update.get('ID')}: {doc_error}")
            continue

        products = msrc_product_map(document)
        for vuln in (document.get("Vulnerability") or []):
            released = None
            if vuln.get("ReleaseDateSpecified") and not str(
                    vuln.get("ReleaseDate") or "").startswith(MSRC_DATE_SENTINEL):
                released = vuln.get("ReleaseDate")
            if not released:
                revisions = [note.get("Date") for note in (vuln.get("RevisionHistory") or [])
                             if note.get("Date")
                             and not str(note["Date"]).startswith(MSRC_DATE_SENTINEL)]
                released = max(revisions) if revisions else None
            released_dt = parse_dt(released)
            if released_dt is None or released_dt < since:
                continue

            # Actually-affected products, resolved through the product tree.
            affected = []
            for status in (vuln.get("ProductStatuses") or []):
                for product_id in (status.get("ProductID") or []):
                    name = products.get(str(product_id))
                    if name:
                        affected.append(name)
            if not any(MSRC_PRODUCT_FILTER.search(name) for name in affected):
                continue

            severity = "UNKNOWN"
            impact = None
            for threat in (vuln.get("Threats") or []):
                value = ((threat.get("Description") or {}).get("Value") or "").strip()
                if value.lower() in MSRC_SEVERITIES:
                    severity = value.upper()
                elif value and impact is None:
                    impact = value

            score = None
            for score_set in (vuln.get("CVSSScoreSets") or []):
                if isinstance(score_set.get("BaseScore"), (int, float)):
                    score = max(score or 0, float(score_set["BaseScore"]))

            cve = vuln.get("CVE")
            entries.append({
                "source": "msrc",
                "id": cve,
                "aliases": [cve] if cve else [],
                "ecosystem": "microsoft",
                "title": (vuln.get("Title") or {}).get("Value") if isinstance(
                    vuln.get("Title"), dict) else vuln.get("Title"),
                "summary": f"{impact or 'Vulnerabilite Microsoft'}. "
                           f"Produits concernes : {', '.join(sorted(set(affected))[:5])}"
                           + (" …" if len(set(affected)) > 5 else ""),
                "severity": severity if severity != "IMPORTANT" else "HIGH",
                "cvss": score,
                "published": released,
                "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
                "exploited": False,
            })

    return entries, errors


# --------------------------------------------------------------------------
# Containers -- runc, containerd, podman, docker, buildah
# --------------------------------------------------------------------------

def collect_containers(since: datetime):
    """OSV advisories for container projects, filtered to the window.

    OSV cannot filter by date, so each project is queried and the results are
    filtered on `published` afterwards.
    """
    entries, errors, seen = [], [], set()

    for package in CONTAINER_PACKAGES:
        payload, error = http_json_post(
            OSV_QUERY_URL, {"package": {"name": package, "ecosystem": "Go"}})
        if error:
            errors.append(f"OSV {package}: {error}")
            continue

        for vuln in (payload.get("vulns") or []):
            identifier = vuln.get("id")
            if not identifier or identifier in seen:
                continue
            published = parse_dt(vuln.get("published"))
            if published is None or published < since:
                continue
            seen.add(identifier)

            severity = ((vuln.get("database_specific") or {}).get("severity")
                        or "UNKNOWN").upper()
            entries.append({
                "source": "containers",
                "id": identifier,
                "aliases": [a for a in (vuln.get("aliases") or []) if a.startswith("CVE-")],
                "ecosystem": "container",
                "packages": [{"ecosystem": "go", "name": package,
                              "vulnerable_range": None, "first_patched": None}],
                "severity": "MEDIUM" if severity == "MODERATE" else severity,
                "title": vuln.get("summary"),
                "summary": (vuln.get("details") or "")[:600],
                "published": vuln.get("published"),
                "url": f"https://osv.dev/vulnerability/{identifier}",
                "exploited": False,
            })

    return entries, errors


# --------------------------------------------------------------------------
# Android -- monthly bulletins, through the OSV archive
# --------------------------------------------------------------------------

def collect_android(since: datetime):
    """Android advisories published within the window.

    source.android.com exposes no RSS feed, so the only programmatic route is
    the OSV Android ecosystem archive (~9 MB), filtered locally on the
    publication date.
    """
    raw, error = http_get(OSV_ANDROID_ZIP, timeout=180)
    if error:
        return [], error

    entries = []
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name in archive.namelist():
                if not name.endswith(".json"):
                    continue
                try:
                    vuln = json.loads(archive.read(name).decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue
                published = parse_dt(vuln.get("published"))
                if published is None or published < since:
                    continue

                severity = ((vuln.get("database_specific") or {}).get("severity")
                            or "UNKNOWN").upper()
                versions = sorted({
                    str(event.get("introduced"))
                    for affected in (vuln.get("affected") or [])
                    for rng in (affected.get("ranges") or [])
                    for event in (rng.get("events") or [])
                    if event.get("introduced") and event.get("introduced") != "0"})

                entries.append({
                    "source": "android",
                    "id": vuln.get("id"),
                    "aliases": [a for a in (vuln.get("aliases") or [])
                                if str(a).startswith("CVE-")],
                    "ecosystem": "android",
                    "severity": "MEDIUM" if severity == "MODERATE" else severity,
                    "title": vuln.get("summary") or vuln.get("id"),
                    "summary": (vuln.get("details") or "")[:600],
                    "android_versions": versions,
                    "published": vuln.get("published"),
                    "url": f"https://osv.dev/vulnerability/{vuln.get('id')}",
                    "exploited": False,
                })
    except zipfile.BadZipFile as exc:
        return [], f"archive Android illisible : {exc}"

    return entries, None


# --------------------------------------------------------------------------
# EPSS -- enrichment
# --------------------------------------------------------------------------

def enrich_epss(cve_ids, chunk_size=100):
    """Fetch EPSS scores. Returns {cve: {"score": ..., "percentile": ...}}."""
    scores, errors = {}, []
    unique = sorted({c for c in cve_ids if c and c.startswith("CVE-")})

    for start in range(0, len(unique), chunk_size):
        chunk = unique[start:start + chunk_size]
        params = urllib.parse.urlencode({"cve": ",".join(chunk)})
        payload, error = http_json(f"{EPSS_URL}?{params}")
        if error:
            errors.append(f"EPSS: {error}")
            continue
        for row in (payload.get("data") or []):
            try:
                scores[row["cve"]] = {
                    "score": float(row.get("epss", 0)),
                    "percentile": float(row.get("percentile", 0)),
                }
            except (TypeError, ValueError, KeyError):
                continue
    return scores, errors


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="security-watch advisory feed collection.")
    parser.add_argument("--days", type=int, default=1,
                        help="fenetre en jours (defaut : 1)")
    parser.add_argument("--ecosystems", nargs="*", default=DEFAULT_ECOSYSTEMS,
                        help=f"ecosystemes GHSA (defaut : {' '.join(DEFAULT_ECOSYSTEMS)})")
    parser.add_argument("--sources", nargs="*", default=None,
                        choices=["kev", "ghsa", "certfr", "arch", "msrc",
                                 "containers", "android"],
                        help="restreint la collecte a ces sources (defaut : toutes)")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    wanted = set(args.sources) if args.sources else {
        "kev", "ghsa", "certfr", "arch", "msrc", "containers", "android"}

    since = now_utc() - timedelta(days=args.days)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    sources, advisories, errors = {}, [], []

    log(f"[*] Fenetre : depuis {iso(since)}", args.quiet)
    if not token:
        log("[!] Pas de GITHUB_TOKEN : quota GitHub limite a 60 req/h", args.quiet)

    if "kev" in wanted:
        log("[*] CISA KEV", args.quiet)
        kev, kev_error = collect_kev(since)
        sources["cisa_kev"] = {"ok": kev_error is None, "count": len(kev)}
        if kev_error:
            errors.append(f"cisa_kev: {kev_error}")
        advisories += kev

    if "ghsa" in wanted:
        for ecosystem in args.ecosystems:
            log(f"[*] GitHub Advisory ({ecosystem})", args.quiet)
            ghsa, ghsa_errors = collect_ghsa(ecosystem, since, token)
            sources[f"ghsa_{ecosystem}"] = {"ok": not ghsa_errors, "count": len(ghsa)}
            errors += [f"ghsa_{ecosystem}: {e}" for e in ghsa_errors]
            advisories += ghsa

    if "certfr" in wanted:
        for name, url in CERTFR_FEEDS.items():
            log(f"[*] {name}", args.quiet)
            certfr, certfr_error = collect_certfr(name, url, since)
            sources[name] = {"ok": certfr_error is None, "count": len(certfr)}
            if certfr_error:
                errors.append(f"{name}: {certfr_error}")
            advisories += certfr

    if "arch" in wanted:
        log("[*] Arch Linux (etat courant)", args.quiet)
        arch, arch_error = collect_arch()
        sources["arch"] = {"ok": arch_error is None, "count": len(arch),
                           "kind": "etat"}
        if arch_error:
            errors.append(f"arch: {arch_error}")
        advisories += arch

    if "msrc" in wanted:
        log("[*] Microsoft MSRC", args.quiet)
        msrc, msrc_errors = collect_msrc(since)
        sources["msrc"] = {"ok": not msrc_errors, "count": len(msrc)}
        errors += msrc_errors
        advisories += msrc

    if "containers" in wanted:
        log("[*] Conteneurs (runc, containerd, podman, docker)", args.quiet)
        containers, container_errors = collect_containers(since)
        sources["containers"] = {"ok": not container_errors, "count": len(containers)}
        errors += container_errors
        advisories += containers

    if "android" in wanted:
        log("[*] Android (archive OSV)", args.quiet)
        android, android_error = collect_android(since)
        sources["android"] = {"ok": android_error is None, "count": len(android)}
        if android_error:
            errors.append(f"android: {android_error}")
        advisories += android

    # EPSS only for the CVEs actually collected: no full-dataset download, just
    # the hundred or so that matter here.
    cve_ids = [alias for entry in advisories for alias in (entry.get("aliases") or [])]
    log(f"[*] EPSS pour {len(set(cve_ids))} CVE", args.quiet)
    epss_scores, epss_errors = enrich_epss(cve_ids)
    errors += epss_errors
    for entry in advisories:
        for alias in (entry.get("aliases") or []):
            if alias in epss_scores:
                entry["epss_score"] = epss_scores[alias]["score"]
                entry["epss_percentile"] = epss_scores[alias]["percentile"]
                break

    feed = {
        "schema": 1,
        "collected_at": iso(now_utc()),
        "window": {"days": args.days, "since": iso(since)},
        "sources": sources,
        "advisories": advisories,
        "summary": {
            "total": len(advisories),
            "exploited": sum(1 for a in advisories if a.get("exploited")),
            "by_source": {name: info["count"] for name, info in sources.items()},
        },
        "errors": errors,
    }

    output = args.output or (OUT_DIR / f"feed-{now_utc().date().isoformat()}.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(feed, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"\n  {len(advisories)} entrees collectees "
          f"({feed['summary']['exploited']} activement exploitees)")
    for name, info in sources.items():
        status = "ok " if info["ok"] else "ECHEC"
        print(f"    [{status}] {name:<16} {info['count']}")
    if errors:
        print(f"\n  {len(errors)} erreur(s) :")
        for err in errors[:5]:
            print(f"    - {err}")
    print(f"\n  Flux ecrit : {output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

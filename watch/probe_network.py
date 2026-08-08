#!/usr/bin/env python3
"""
Egress probe: which hosts can this environment actually reach?

The daily routine runs behind a proxy that returns 403 for most hosts. This
script tests candidate sources and writes the verdict to watch/NETWORK.md so a
working set of feeds can be picked from evidence rather than guesswork.

Run:  python3 watch/probe_network.py
"""

from __future__ import annotations

import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

OUT = Path(__file__).resolve().parent / "NETWORK.md"
TIMEOUT = 25

# (label, url, method). HEAD keeps large archives cheap to test.
TARGETS = [
    ("OSV npm archive", "https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip", "HEAD"),
    ("OSV NuGet archive", "https://osv-vulnerabilities.storage.googleapis.com/NuGet/all.zip", "HEAD"),
    ("OSV Android archive", "https://osv-vulnerabilities.storage.googleapis.com/Android/all.zip", "HEAD"),
    ("OSV Debian archive", "https://osv-vulnerabilities.storage.googleapis.com/Debian/all.zip", "HEAD"),
    ("OSV API", "https://api.osv.dev/v1/vulns/GHSA-jfh8-c2jp-5v3q", "GET"),
    ("GitHub API", "https://api.github.com/advisories?per_page=1", "GET"),
    ("GitHub raw", "https://raw.githubusercontent.com/aquasecurity/trivy/main/README.md", "HEAD"),
    ("GitHub web", "https://github.com", "HEAD"),
    ("GitHub codeload", "https://codeload.github.com/aquasecurity/trivy/tar.gz/refs/tags/v0.73.0", "HEAD"),
    ("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", "HEAD"),
    ("EPSS (FIRST)", "https://api.first.org/data/v1/epss?cve=CVE-2021-44228", "GET"),
    ("EPSS archive", "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz", "HEAD"),
    ("CERT-FR", "https://www.cert.ssi.gouv.fr/avis/feed/", "HEAD"),
    ("Arch security", "https://security.archlinux.org/issues/all.json", "HEAD"),
    ("MSRC", "https://api.msrc.microsoft.com/cvrf/v3.0/updates", "GET"),
    ("NVD API", "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1", "GET"),
    ("npm registry", "https://registry.npmjs.org/lodash", "HEAD"),
    ("NuGet API", "https://api.nuget.org/v3/index.json", "GET"),
    ("PyPI", "https://pypi.org/pypi/requests/json", "HEAD"),
    ("Anthropic API", "https://api.anthropic.com", "HEAD"),
]


class HeadRequest(urllib.request.Request):
    def get_method(self):
        return "HEAD"


def probe(url: str, method: str):
    request_class = HeadRequest if method == "HEAD" else urllib.request.Request
    request = request_class(url, headers={"User-Agent": "security-watch-probe/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
            return f"OK {response.status}", ""
    except urllib.error.HTTPError as exc:
        # An HTTP status means the host was reached; only the request failed.
        return f"HTTP {exc.code}", "hote joignable"
    except urllib.error.URLError as exc:
        return "BLOQUE", str(exc.reason)[:120]
    except (TimeoutError, socket.timeout):
        return "TIMEOUT", f"{TIMEOUT}s"
    except (OSError, ssl.SSLError) as exc:
        return "ERREUR", f"{type(exc).__name__}: {exc}"[:120]


def main():
    lines = [
        "# Egress reachability",
        "",
        f"Probed at {datetime.now(timezone.utc).replace(microsecond=0).isoformat()}",
        "",
        "| Source | Verdict | Detail |",
        "|---|---|---|",
    ]

    reachable, blocked = [], []
    for label, url, method in TARGETS:
        verdict, detail = probe(url, method)
        print(f"{verdict:<10} {label}", file=sys.stderr, flush=True)
        lines.append(f"| {label} | `{verdict}` | {detail} |")
        (reachable if verdict.startswith(("OK", "HTTP")) else blocked).append(label)

    proxy_vars = {k: v for k, v in os.environ.items()
                  if "proxy" in k.lower() or k.lower() in ("no_proxy",)}
    lines += [
        "",
        "## Proxy environment",
        "",
        "```",
        json.dumps(proxy_vars, indent=2) if proxy_vars else "(no proxy variables set)",
        "```",
        "",
        "## Verdict",
        "",
        f"**Reachable ({len(reachable)})**: " + (", ".join(reachable) or "none"),
        "",
        f"**Blocked ({len(blocked)})**: " + (", ".join(blocked) or "none"),
        "",
    ]

    OUT.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nWritten: {OUT}")
    print(f"reachable={len(reachable)} blocked={len(blocked)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

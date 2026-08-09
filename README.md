# security-watch

Per-repository dependency security audit for web stacks — Node/npm and
.NET/NuGet, the base images the Dockerfiles build on, and the infrastructure
files that sit alongside them.

Scans one repository's real dependency tree, produces a report you can read in a
minute, and — in CI — opens a GitHub issue **only when something new turns up**,
never re-raising what you have already seen.

## Two layers, and the first works alone

| Layer                       | What it does                                             | Needs                            |
|-----------------------------|----------------------------------------------------------|----------------------------------|
| **1. Detection**            | Scans, deduplicates against past issues, opens the issue | Nothing locally / GitHub Actions |
| **2. Summary** *(optional)* | Rewrites the report into a brief with priorities         | A Claude subscription            |

Layer 1 is deterministic: version-to-CVE matching is done by Trivy and the .NET
SDK.

Layer 2 sits **on top of an artefact that is already true**. It groups what
shares a fix, says why something matters here, and leads with the
highest-leverage action. It never decides what is or is not a problem.

> A model asked to match versions against advisories will invent version numbers. So it never does that here: it writes prose over data that was computed. Reports are written in French.

## Auditing a repository locally

One command, no configuration, nothing committed anywhere:

```bash
./scan.sh ../some-project
```

Installs Trivy if it is missing, then leaves `out/<repo>-<date>.md` and its
`.findings.json` next to each other. Windows: `.\scan.ps1 ..\some-project`.
Several at once is fine — each gets its own report:

```bash
./scan.sh ../front ../api ../infra
```

Under it is a plain script you can call directly when you want control over the
paths:

```bash
python watch/audit.py --repo ../some-project --out-md report.md --out-json findings.json
```

`--no-dotnet` skips NuGet resolution when the feed is unreachable, `--no-images`
skips pulling the Dockerfiles' base images. Both gaps are stated in the report.

## Auditing a repository on a schedule

Copy [`templates/security-audit.yml`](templates/security-audit.yml) into a
repository at `.github/workflows/security-audit.yml`, allow Actions to write,
and run it once by hand. It runs the same audit, then reports **only what is
new** against the issues it opened before.

Full instructions, including the deduplication and how to change the cadence:
**[docs/setup-target-repo.md](docs/setup-target-repo.md)**.

## Adding the summary

**[docs/claude-routine.md](docs/claude-routine.md)** — how to have an agent turn
a report into a brief, either on a schedule or by hand.
[`watch/SYNTHESIS.md`](watch/SYNTHESIS.md) holds the rules it must follow; point
your agent at that file rather than restating them.

## Requirements

[Trivy](https://github.com/aquasecurity/trivy) on `PATH` — the scan scripts
install it for you. The .NET SDK for repositories that carry .NET, at least as
new as their target framework. Everything else is Python standard library,
3.9 or later.

## Running tests

```bash
python watch/test_detect.py && python watch/test_report.py && python watch/test_images.py
```

No framework, no network.

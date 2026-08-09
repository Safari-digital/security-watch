# security-watch

Per-repository dependency security audit for web stacks — Node/npm and
.NET/NuGet, plus the container and infrastructure files that sit alongside them.

Scans one repository's real dependency tree, produces a report you can read in a
minute, and — in CI — opens a GitHub issue **only when something new turns up**,
never re-raising what you have already seen.

It answers one question: **what is this repository exposed to right now.** Not
what was published this week, and nothing about the machine it runs on.

## Two layers, and the first works alone

| Layer | What it does | Needs |
|---|---|---|
| **1. Detection** | Scans, deduplicates against past issues, opens the issue | Nothing locally / GitHub Actions |
| **2. Summary** *(optional)* | Rewrites the report into a brief with priorities | A Claude subscription |

Layer 1 is deterministic: version-to-CVE matching is done by Trivy and the .NET
SDK, and nothing in the output is invented. It is useful on its own — a bare
list of advisories with fixed versions is already actionable.

Layer 2 sits **on top of an artefact that is already true**. It groups what
shares a fix, says why something matters here, and leads with the
highest-leverage action. It never decides what is or is not a problem.

Set up layer 1 first. Add layer 2 once you have read a few reports and know what
is missing.

## Auditing a repository, locally

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

`--no-dotnet` skips NuGet resolution when the feed is unreachable — the report
says so rather than quietly shrinking.

## Auditing a repository, on a schedule

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
3.9 or later; there is nothing to `pip install`.

## Two things worth knowing before you rely on it

**A schedule beats a push trigger.** Advisories are published against code that
has not changed. A repository with irregular commits would go unwatched for
weeks on push alone; two findings once landed on a repository overnight without
a single commit.

**A window is not an inventory.** "What was published in the last N days" and
"what this repository carries" are different questions. The audit answers the
second, with no window: a scan once credited a repository with 11 findings on a
7-day window where its full tree held 22.

## What it does not do

- **No SAST.** Application code is not analysed — that is CodeQL or SonarQube.
- **No secret scanning.** Trivy can, but it is noisy enough to deserve its own
  pipeline.
- **Nothing about the machine.** Installed packages, local container images and
  OS patch levels are out of scope. The unit is a repository.

## Layout

```
security-watch/
├── watch/
│   ├── scanner.py        Trivy and .NET SDK primitives, no entry point
│   ├── audit.py          scan one repository → Markdown + JSON
│   ├── publish.py        keep only what was never reported, build the issue
│   ├── test_*.py         see Tests below
│   └── SYNTHESIS.md      the rules layer 2 must follow
├── templates/            the workflow to copy into a target repository
├── docs/                 setup guides
└── scan.ps1 / scan.sh    one-command local audit
```

## Tests

```bash
python watch/test_detect.py && python watch/test_report.py
```

No framework, no network, a second to run. They cover the two places where a
mistake looks like a working scan rather than an error:

| File | Guards against |
|---|---|
| `test_detect.py` | An ecosystem that goes undetected, so its scan never runs and no gap is reported |
| `test_report.py` | Counting one advisory once per file it appears in, and writing "no patch published" over a source that never publishes patch versions |

## Design rule

> Deterministic matching, AI only for the summary.

A model asked to match versions against advisories will invent version numbers.
So it never does that here: it writes prose over data that was computed. Two
consequences you will see in the output — coverage gaps are always stated rather
than swallowed, and anything the matcher could not decide is reported as "to
check", never as "not affected".

## Licence

MIT — see [LICENSE](LICENSE).

Reports are written in French. Everything else — code, comments, documentation —
is in English.

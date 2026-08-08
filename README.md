# security-watch

Dependency security watch for web stacks — Node/npm, .NET/NuGet, containers,
and the OS underneath.

Scans a repository's real dependency tree, opens a GitHub issue **only when
something new turns up**, and never re-raises what you have already seen.

## Two layers, and the first works alone

| Layer | What it does | Needs |
|---|---|---|
| **1. Detection** | Scans, deduplicates against past issues, opens the issue | GitHub Actions |
| **2. Summary** *(optional)* | Rewrites the issue into a readable brief with priorities | An AI agent |

Layer 1 is deterministic: version-to-CVE matching is done by Trivy and the .NET
SDK, and nothing in the output is invented. It is useful on its own — a bare
list of advisories with fixed versions is already actionable.

Layer 2 sits **on top of an artefact that is already true**. It groups what
shares a fix, says why something matters here, and leads with the highest-leverage
action. It never decides what is or is not a problem.

Set up layer 1 first. Add layer 2 once you have read a few reports and know what
is missing.

- **[docs/setup-target-repo.md](docs/setup-target-repo.md)** — layer 1, the
  workflow
- **[docs/claude-routine.md](docs/claude-routine.md)** — layer 2, the AI summary

## Quick start

Copy [`templates/security-audit.yml`](templates/security-audit.yml) into a
repository at `.github/workflows/security-audit.yml`, allow Actions to write,
and run it once by hand. Full instructions in the setup guide.

## Auditing a repository locally

For a repository you cannot add a workflow to — a client's Azure DevOps, a
mirror, anything without CI:

```bash
python watch/audit.py --repo ../some-project --out-md report.md --out-json findings.json
```

Same output as CI, no deduplication and no issue. Hand `findings.json` to an
agent afterwards if you want the summary.

Requires [Trivy](https://github.com/aquasecurity/trivy) on `PATH`. Everything
else is Python standard library — nothing to `pip install`.

## Two things worth knowing before you rely on it

**A schedule beats a push trigger.** Advisories are published against code that
has not changed. A repository with irregular commits would go unwatched for
weeks on push alone; two findings once landed on a repository overnight without
a single commit.

**A window is not an inventory.** Reporting "what was published in the last N
days" and "what this repository carries" are different questions. The per-repo
audit answers the second, with no window: a scan once credited a repository with
11 findings on a 7-day window where its full tree held 22.

## What it does not do

- **No SAST.** Application code is not analysed — that is CodeQL or SonarQube.
- **No secret scanning.** Trivy can, but it is noisy enough to deserve its own
  pipeline.
- **No OS or device matching.** For Windows, Arch or Android the watch reports
  what was published; it cannot tell you whether your build is affected.

## Layout

```
security-watch/
├── watch/
│   ├── audit.py          scan one repository, no window, no AI
│   ├── publish.py        keep only what was never reported, build the issue
│   ├── collect.py        advisory feeds (KEV, GHSA, CERT-FR, MSRC, OSV…)
│   ├── correlate.py      cross feeds with an inventory, ranked by certainty
│   ├── report.py         render Markdown and HTML
│   ├── run.py            run the whole chain locally over any window
│   └── SYNTHESIS.md      the rules layer 2 must follow
├── agent/
│   └── agent.py          local scanner: lockfiles, images, OS packages
├── templates/            workflows to copy into target repositories
├── docs/                 setup guides
└── scan.ps1 / scan.sh    one-command local scan
```

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

# Setting up the audit on a repository

The workflow scans a repository's dependency tree every day and opens an issue
**only when something new turns up**. Findings you have already seen never come
back, and it never touches issues you already have — closing, labelling and
`wontfix` are yours to decide.

## Install

**1. Copy the workflow**

Copy `templates/security-audit.yml` from this repository to
`.github/workflows/security-audit.yml` in the target repository.

Nothing else to fetch: `security-watch` is public, so the workflow clones it
with the default `GITHUB_TOKEN`. Were it made private again, `GITHUB_TOKEN`
would no longer reach it and the checkout step would need a `token:` line
pointing at a personal access token with **Contents: read**.

**2. Allow the workflow to write**

Settings → Actions → General → Workflow permissions → **Read and write
permissions**. Without it the workflow cannot open its issue.

**3. Run it once by hand**

Actions → *Security audit* → *Run workflow*. The first run reports everything,
since nothing has been seen yet. Subsequent runs report only what changed.

## Submodules

The checkout is `submodules: recursive`, because a submodule carries its own
dependencies and its own vulnerabilities. Public submodules work as they are,
including those declared with a `git@github.com:` URL — the checkout action
rewrites them to HTTPS. A **private** submodule in another organisation is the
exception: `GITHUB_TOKEN` cannot reach it, and it needs a token of its own.

## Changing the cadence

Edit the `cron` line in the workflow:

| Cadence | cron | Local time |
|---|---|---|
| Daily | `0 6 * * *` | 08:00 in summer, 07:00 in winter |
| Weekly, Monday | `0 6 * * 1` | idem |
| Twice a week | `0 6 * * 1,4` | Monday and Thursday |

Cron is always UTC, so the local time shifts by an hour across DST. GitHub also
delays scheduled runs by 10 to 30 minutes at peak times, which does not matter
here — nothing downstream is waiting on it.

> A repository with irregular commits still needs a schedule, not a push
> trigger. Advisories are published against code that has not changed: two
> findings landed on a repository overnight without a single commit.

## Settings

Both are repository variables — Settings → Secrets and variables → Actions →
**Variables** — so changing them needs no workflow edit.

| Variable | Default | Role |
|---|---|---|
| `SECWATCH_LOOKBACK_DAYS` | `90` | How far back previous issues are read |
| `SECWATCH_MIN_SEVERITY` | `LOW` | Floor: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` |
| `SECWATCH_DOTNET_VERSION` | `10.0.x` | SDK installed when the repo has .NET |

### Why the .NET version matters

Transitive NuGet resolution goes through `dotnet list package --vulnerable`,
which needs a restore, which needs an SDK at least as new as the target
framework. The runner image lags new SDK releases, so the version is pinned
here. Set it to what your projects target; a repository with no .NET at all
never installs anything and can ignore the variable.

Get it wrong and the audit does not lie about it — the restore fails, and the
coverage section says the transitive graph was not covered.

### Why the lookback matters

It decides how long a finding stays quiet. Past the window, an unaddressed
finding resurfaces — deliberately, so that something ignored in March comes back
once rather than never.

- **Shorter (30 days)**: findings resurface often. Useful if you want pressure.
- **Longer (180 days)**: quieter, but something you skipped can stay buried for
  six months.

90 days is a quarter: long enough not to nag, short enough that nothing is lost
for good.

## The label

Every issue is tagged **`Security report`**, created automatically on the first
run if missing, in red (`B60205`).

It is not decoration: deduplication reads past issues *through this label*.
Rename it and every previous issue becomes invisible, so the next run raises
everything again from scratch. Change it in one place only — the
`SECWATCH_LABEL` variable at the top of the workflow — and rename the existing
label in GitHub at the same time.

## How deduplication works

Each issue carries a hidden block listing the findings it raised:

```
<!-- security-watch:findings
["CVE-2026-59873@tar@7.5.16", ...]
-->
```

The next run reads those blocks back from every issue in the window, open **and
closed**. Two consequences:

- **Closing an issue as wontfix keeps its findings quiet.** Your call is
  respected without any extra configuration.
- **Deleting an issue makes its findings new again.** That is the escape hatch
  when you want something re-raised.

A finding is identified by `<advisory>@<package>@<version>`. If a bump lands and
the advisory still applies to the new version, that counts as new and is raised
again — which is what you want, since the fix did not work.

## What the issue contains, and what it leaves out

The issue lists **only new findings**. The complete picture is attached to the
workflow run as an artifact (`security-audit-full`, kept 30 days), because a
delta is the right thing to read daily but the wrong thing when you sit down to
clear a backlog.

## Auditing a repository without CI

For a repository you cannot add a workflow to — a client's Azure DevOps, say —
run the same audit locally and hand the result to an agent afterwards:

```bash
python watch/audit.py --repo ../some-project --out-md report.md --out-json findings.json
```

Same output, no deduplication and no issue. `--no-dotnet` skips NuGet resolution
when the feed is unreachable.

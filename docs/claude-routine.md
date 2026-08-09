# Adding an AI summary on top

Layer 1 produces a report listing findings grouped by package, with fixed
versions — either as a GitHub issue from
[the workflow](setup-target-repo.md), or as a file from `./scan.sh`. Either
way it is already actionable.

This guide adds layer 2: an agent that reads that report and rewrites it as a
brief you can act on in a minute. It is **optional and additive**. If it never
runs, layer 1 stays exactly as useful as it was.

## What the summary is for

A list of twenty advisories does not tell you where to start. The summary does
three things a list cannot:

- **Leads with the highest-leverage action.** Not the highest CVSS — the bump
  that closes the most. One `nuxt` upgrade once closed seven findings at once.
- **Groups what shares a fix.** Six advisories resolved by one version is one
  line, not six.
- **Says why it matters here.** An unauthenticated RCE in a local dev tool and a
  denial of service on a public API do not carry the same urgency.

## The hard rule

The agent writes **on top of an artefact that is already true**. It must never:

- Invent or "correct" an advisory ID, a package name or a version number
- Re-rank findings — severity and fixed versions are computed, not negotiable
- Declare that something is *not* a problem

That last one matters most. When the matcher cannot decide, it says "to check".
An agent that resolves that ambiguity into "not affected" turns an honest
unknown into a false all-clear, which is worse than no report.

[`watch/SYNTHESIS.md`](../watch/SYNTHESIS.md) holds these rules in full. Point
your agent at it rather than restating them.

## Setting it up

Any scheduled agent with repository access works. The shape is the same:

**1. Trigger** — after the workflow has run. Leave a comfortable gap: scheduled
CI can be delayed by 10 to 30 minutes at peak times. Two hours is plenty.

**2. Prompt** — the essentials:

```
Read the newest open issue labelled "Security report" in <repo>.
Read watch/SYNTHESIS.md from Safari-digital/security-watch — those rules are binding.

Write a summary in the language of the report and post it as a comment on that
issue. Two parts, exactly as SYNTHESIS.md specifies: a plain-prose description
of where the exposure sits, then a numbered list of gestures, the one that
closes the most first.

Never invent an identifier, a package name or a version: the issue body is your
only source. Never write that a finding is not a problem. Open on the fix that
closes the most findings, not on the highest score. Group what shares a fix.

If the issue has no findings, say so in one line. No filler.
```

**3. Output** — post it as a **comment**, not by editing the issue body. The
body carries the deduplication block; rewriting it risks corrupting the state
that keeps findings from being re-raised.

## Running it against several repositories

One agent covering several repositories beats one per repository: a single
prompt to keep aligned, and the summaries stay consistent in tone. Give it the
list and let it iterate.

Repositories on different cadences are fine — a weekly repository simply has no
new issue most days, and the agent says so and moves on.

## Doing it by hand instead

No scheduling, no workflow, no GitHub — this works on a repository you only have
a local clone of, a client's Azure DevOps included:

```bash
./scan.sh ../some-project
```

That leaves `out/<repo>-<date>.md` and its `.findings.json`. Open a session
where the repository is visible and ask for the brief:

```
Lis out/<repo>-<date>.findings.json et watch/SYNTHESIS.md.
Applique ces règles et écris la synthèse.
```

Same rules, same result, on demand. The JSON is the better input of the two —
it carries `fix_unknown`, `targets` and `transitive`, which the Markdown only
summarises.

One caution: that file lists a real dependency tree and its unpatched
vulnerabilities. `out/` is gitignored here for that reason. Think before it
leaves your machine, especially for a client repository.

## Judging whether it earns its place

After a week, ask whether you read the summary or skip straight to the list. If
you skip it, the summary is restating the table instead of adding judgement —
tighten the prompt or drop the layer. It is meant to save you a minute, not to
add a paragraph.

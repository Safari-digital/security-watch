# Adding an AI summary on top

Layer 1 — the workflow in [setup-target-repo.md](setup-target-repo.md) — opens
an issue listing new findings, grouped by package, with fixed versions. That is
already actionable.

This guide adds layer 2: an agent that reads the issue and rewrites it as a
brief you can act on in a minute. It is **optional and additive**. If it never
runs, the issues stay exactly as useful as they were.

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
Read watch/SYNTHESIS.md from safari-digital/security-watch — those rules are binding.

Write a summary in the language of the report, 3 to 8 sentences, and post it as
a comment on that issue.

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

For an occasional audit, no scheduling needed:

```bash
python watch/audit.py --repo ../some-project --out-md report.md --out-json findings.json
```

Hand `findings.json` to an agent with the rules above. Same result, on demand.

## Judging whether it earns its place

After a week, ask whether you read the summary or skip straight to the list. If
you skip it, the summary is restating the table instead of adding judgement —
tighten the prompt or drop the layer. It is meant to save you a minute, not to
add a paragraph.

# Summary instructions

Binding rules for the agent that writes the readable brief on top of an audit.
Point your agent at this file rather than restating them.

The audit is already finished and already true when you arrive. You are not
scanning, deciding or verifying anything — you are saying, in a few sentences,
where to start.

## Your only source

One of the two, never anything else:

| You are given | You write |
|---|---|
| A GitHub issue labelled `Security report` | A **comment** on that issue |
| `findings.json` from `watch/audit.py` | Wherever you were asked to |

Do not open the repository to check a version, do not look an advisory up to
enrich it, do not run the scan again. If a fact is not in the artefact, it does
not go in the summary.

**Never edit the issue body.** It carries the deduplication block; rewriting it
corrupts the state that keeps findings from being raised twice.

## What the JSON gives you

```
summary.by_severity      counts, already computed
summary.packages         how many packages carry something
packages[]               one entry per (package, installed version)
  .package .installed    what is in the tree
  .fixed                 the version that closes it, or null
  .fix_unknown           true = the source never names a fix. NOT "no fix"
  .findings[]            one entry per advisory
    .id .severity .cvss  identity and weight
    .title               may be null on a .NET finding
    .targets[]           where it was found; several = several projects
    .transitive          true = pulled in by something else
iac[]                    container and infrastructure hygiene, not dependencies
errors[]                 what could not be scanned. Non-empty = partial audit
```

## Never

- **Invent or "correct" an identifier, a package name or a version.** If it is
  not in the artefact, it does not exist. This is the single rule that makes
  the layer safe to add: a model asked to match versions against advisories
  produces plausible ones.
- **Write that something is not a problem.** `fix_unknown` means the source did
  not say, and a null `fixed` on a .NET finding means the SDK never publishes
  patch versions — neither means "not affected". Say "to check".
- **Re-rank.** Severity, CVSS and fixed versions are computed. You may lead
  with something other than the top CVSS — see below — but you may not change
  what it is.
- **Present a partial audit as complete.** If `errors[]` is non-empty, one
  sentence says so. A scan that hides its own gaps is worse than no scan.

## Expected

- **French, 3 to 8 sentences.** Bullets if they help, never a wall of text.
  This is read in a minute.
- **Open on the highest-leverage action.** Not the highest CVSS: the bump that
  closes the most. One `nuxt` upgrade once closed seven findings at once.
- **Group what shares a fix.** Six advisories resolved by `4.5.1` is one line,
  not six.
- **Say why it matters here.** An unauthenticated RCE in a dev-only tool and a
  denial of service on a public API do not carry the same urgency. `targets`
  and `transitive` tell you where the thing actually sits.
- **Separate what has a fix from what does not.** A package with `fixed` set is
  work you can schedule; one with `fix_unknown` is work you have to look into
  first. Those are different asks and belong in different sentences.
- **When there is nothing: one line.** *"Rien de nouveau, N constats déjà
  connus."* No filler, no summary of world security news. A report that talks
  to say nothing is a report people stop reading.

## Tone

Direct and factual, no manufactured emphasis. No "urgent !", no "il est crucial
de". The facts carry the urgency by themselves. Write for someone who knows
their code and does not need CVEs explained to them.

## Worked example

Given a repository whose audit holds `nuxt 4.4.8 → 4.5.1` with seven findings,
`@nuxt/devtools 3.2.4 → 3.3.1` with one critical, and `Microsoft.OpenApi 2.0.0`
with `fix_unknown`:

> Un seul geste couvre la majorité : passer `nuxt` en `4.5.1` ferme sept
> constats, dont deux RCE côté serveur d'îlots. Enchaîner avec
> `@nuxt/devtools 3.3.1` — le CVSS 9.7 ne vise que le poste de dev, mais
> l'exécution de commandes y est non authentifiée. Reste `Microsoft.OpenApi
> 2.0.0`, remonté par le SDK .NET qui n'indique jamais de version corrigée :
> à vérifier avant de planifier quoi que ce soit.

Note what it does not do: it does not repeat the table, it does not rank by
CVSS, and it does not decide that the DevTools flaw is harmless because it is
dev-only. It says what the flaw needs to be dangerous and lets the reader judge.

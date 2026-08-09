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
images[]                 one entry per base image a Dockerfile builds on
  .ref .os               the image, and the distribution inside it
  .eosl                  true = that distribution is past end of life
  .dockerfiles .stages   who asks for it
  .fixable / .total      how much of it can be acted on at all
  .packages[]            same shape as above, system packages this time
iac[]                    container and infrastructure hygiene, not dependencies
errors[]                 what could not be scanned. Non-empty = partial audit
```

`packages[]` and `images[]` are different kinds of work and must not be mixed
in one sentence. A dependency finding is a version bump in code you control. An
image finding is a base image to repin or replace, and most of its packages
usually have no fix at all — quoting a system package by name is rarely useful,
`fixable / total` and the image name are.

**`eosl` outranks every CVE in that image.** A distribution past end of life
will never receive another fix, so the count matters less than the fact that it
can only grow. Say it in its own sentence.

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

## The shape

French, and always these two headings, in this order, nothing before and
nothing else added:

```markdown
## Ce que dit le rapport

## Recommandations
```

**`Ce que dit le rapport`** — two to four sentences of plain prose. What was
found, at what scale, and where it sits. No identifiers, no version numbers, no
list. Someone who will not act today should still understand their exposure
from these sentences alone.

**`Recommandations`** — a numbered list, one gesture per entry, the one that
closes the most first. One line each, action in bold, backticks around every
package and version:

```markdown
1. **`nuxt` → `4.5.1`** — ferme 7 constats, dont deux RCE côté serveur d'îlots.
```

Never two gestures in one entry: a reader must be able to stop after any line
and have done something whole. Dependencies and base images never share an
entry — an image entry names the image and how much of it is fixable, never its
system packages one by one.

Close with a short paragraph, outside the list, for what cannot be acted on:
`fix_unknown`, findings with no published fix, and any gap the coverage section
reported. Outside the list because it is not work anyone can schedule.

Roughly fifteen lines all told. Past that it stops being read.

## Expected

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
- **When there is nothing: one line, and no headings at all.** *"Rien de
  nouveau, N constats déjà connus."* The two-part shape is for a report that
  has something to say; imposing it on an empty day produces ceremony around a
  void. No filler, no summary of world security news. A report that talks to
  say nothing is a report people stop reading.

## Tone

Direct and factual, no manufactured emphasis. No "urgent !", no "il est crucial
de". The facts carry the urgency by themselves. Write for someone who knows
their code and does not need CVEs explained to them.

## Worked example

Given an audit holding `nuxt 4.4.8 → 4.5.1` with seven findings,
`@nuxt/devtools 3.2.4 → 3.3.1` with one critical, `Microsoft.OpenApi 2.0.0`
with `fix_unknown`, and a `node:24-alpine` carrying eighteen fixable system
findings across two Dockerfiles:

> ## Ce que dit le rapport
>
> L'exposition se joue sur deux fronts sans rapport l'un avec l'autre. Côté
> code, le framework front porte l'essentiel : une poignée de montées de version
> règle la majorité des constats, dont deux exécutions de code à distance côté
> serveur. Côté infrastructure, l'image de base sur laquelle deux des trois
> Dockerfiles s'appuient a pris du retard, et tout ce qu'elle traîne se corrige
> d'un seul repin.
>
> ## Recommandations
>
> 1. **Repin `node:24-alpine`** — ferme les 18 constats système des deux
>    Dockerfiles qui s'en servent, en build comme en runtime.
> 2. **`nuxt` → `4.5.1`** — ferme 7 constats, dont une RCE par injection de
>    template dans les props d'îlot et un contournement des gates d'auth.
> 3. **`@nuxt/devtools` → `3.3.1`** — un CVSS 9.7 à lui seul. Le RPC non
>    authentifié ne vise que le poste de dev, mais il y exécute des commandes
>    arbitraires.
>
> `Microsoft.OpenApi 2.0.0` est remonté par le SDK .NET, qui n'indique jamais de
> version corrigée : à vérifier avant de planifier quoi que ce soit.

Note what it does not do. The description names no CVE and no version — that is
what the list is for. No entry merges two gestures. The finding nobody can act
on sits outside the list rather than being ranked among things you can do. And
it does not decide that the DevTools flaw is harmless because it is dev-only: it
says what the flaw needs in order to be dangerous and lets the reader judge.

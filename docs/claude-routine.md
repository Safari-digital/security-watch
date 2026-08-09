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

**1. Access** — the agent has to reach the audited repository. A public one
needs nothing. A **private** one needs the Claude GitHub App installed on the
organisation and scoped to it; without that, creating the routine fails with
`403 You don't have access to a repository this routine uses`. Worth knowing:
that create call is a free probe. It validates access without running anything,
so you can settle the permission question before spending a session on it.

**2. Trigger** — after the workflow has run. Leave a comfortable gap: scheduled
CI can be delayed by 10 to 30 minutes at peak times. Two hours is plenty.

**3. Prompt** — the one in production, French because the reports are:

```
Lis `watch/SYNTHESIS.md` dans Safari-digital/security-watch. Ces règles sont
contraignantes, y compris la section « The shape » qui impose la forme exacte
du commentaire. Suis son exemple travaillé pour le niveau de détail et la
longueur.

Pour chacun de ces dépôts, dans cet ordre : <quotidien>, <hebdomadaire>

    gh issue list --repo <dépôt> --label "Security report" --state open \
      --limit 1 --json number,title,body,createdAt,comments

Passe au dépôt suivant sans rien poster, en disant laquelle de ces conditions
s'applique : aucune issue avec ce label ; l'issue a plus de 26 heures, elle
appartient à un passage précédent ; l'issue porte déjà un commentaire, elle a
déjà été traitée.

Le corps de l'issue est ta SEULE source. N'ouvre pas le code du dépôt audité
pour vérifier une version, ne consulte aucun avis en ligne, ne relance aucun
scan. N'invente ni identifiant, ni nom de paquet, ni numéro de version. N'écris
jamais qu'un constat n'est pas un problème : quand la source ne tranche pas,
écris « à vérifier ».

Poste la synthèse en COMMENTAIRE, jamais en modifiant le corps de l'issue :

    gh issue comment <numéro> --repo <dépôt> --body-file synthese.md

Si `gh` ne peut pas atteindre un dépôt, arrête-toi pour celui-là et rapporte le
message d'erreur exact. Ne poste rien, n'invente rien.

Termine par deux ou trois lignes : pour chaque dépôt, l'issue commentée et
l'URL du commentaire, ou la raison exacte pour laquelle rien n'a été fait.
```

The three skip conditions are what keeps a daily agent quiet, and each earns
its place. Without the age check it comments on last week's issue every
morning. Without the comment check, a rerun says the same thing twice. Without
the empty case it invents something to say.

**4. Output** — post it as a **comment**, not by editing the issue body. The
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

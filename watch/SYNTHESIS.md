# Daily summary instructions

Followed by the daily routine. It produces `watch/out/synthesis-<date>.md`,
which `report.py --synthesis` prepends to the report.

## Pipeline

Collection is **not** the routine's job: the environment sits behind a proxy
that blocks most advisory hosts, so GitHub Actions collects the feed at
05:30 UTC and commits it to `watch/out/`. Never run `collect.py` here — it
would fail and produce a misleadingly empty report.

```bash
git pull origin master
python watch/correlate.py
# write watch/out/synthesis-<date>.md following the rules below
python watch/report.py
```

`report.py` pairs the correlation with its same-date summary automatically, so
`--synthesis` is not needed. Pushing `reports/<date>.md` triggers the notify
workflow, which opens the GitHub issue — that push is the delivery.

If `correlate.py` fails, do not invent a summary: run `report.py` with no
summary at all. A deterministic report with no commentary beats commentary
with no data.

## File format

The file has an overview, then one optional note per topic:

```markdown
<overview: 3 to 8 sentences>

## sujet:msrc
<what those Windows advisories are about>

## sujet:arch
<what those Arch advisories are about>
```

Valid topic keys, taken from the `topics[].key` field of the correlation:
`cisa-kev`, `ghsa`, `msrc`, `arch`, `containers`, `android`, `certfr_avis`,
`certfr_alerte`. A key that matches no topic is silently dropped, so copy them
exactly.

**Write a note for every topic present in the correlation.** Two or three
sentences each. Without it the reader gets a bare list of CVE links and has to
open each one just to find out whether it is serious — which is exactly the
friction this report exists to remove. Say what the advisories are about, who
they hit, and whether they plausibly touch this fleet.

Good: *"Patch Tuesday d'août : trois failles côté .NET. L'élévation de
privilèges ASP.NET Core est la plus sérieuse si tu héberges des applis
exposées ; le RCE PowerShell suppose l'exécution locale d'un script non fiable."*

Bad: *"Trois avis Microsoft ont été publiés."* — that is already in the table.

## Your only source: `watch/out/correlation-<date>.json`

Write from that file and nothing else.

**Never:**

- Invent or "correct" a CVE/GHSA identifier, a package name, a version number.
  If it is not in the JSON, it does not exist.
- Renegotiate priority. The `priority` field is computed deterministically
  (exploited > certainty level > EPSS > CVSS > severity). Follow that order.
- Write that something is *not* a problem. The `to_review` tier exists because
  the machine could not decide; neither can you. Say "to check", never "not
  affected".
- Requalify a `probable` as `confirmed`, or the reverse.

**Expected:**

- **French, 3 to 8 sentences** for the overview, plus a short note per topic.
  Bullets if they help, never a wall of text. This is read in a minute, before
  coffee.
- **Open on the highest-leverage action.** Not the highest CVSS: the fix that
  resolves the most. If one version bump closes six advisories, that is the
  first sentence.
- **Group what shares a fix.** Six Nuxt advisories closed by `4.5.1` is one
  line, not six.
- **Say why it matters here.** An unauthenticated RCE in a local dev tool and a
  denial of service on a public API do not carry the same urgency. The JSON
  gives you the repository: use it.
- **Flag coverage gaps** in one sentence if `errors` is non-empty. Do not copy
  them out; `report.py` already lists them in detail.
- **When there is nothing: one line.** "Rien à traiter, N avis parcourus." No
  filler, no summary of world security news. A report that talks to say nothing
  is a report people stop reading.

## The `context` block

Actively exploited flaws with **no established link** to the fleet. Mention one
only if a plausible connection exists (an adjacent technology, a vendor in use).
Otherwise ignore them: `report.py` already lists them.

## Tone

Direct and factual, no manufactured emphasis. No "urgent!", no "it is crucial
to". The facts carry the urgency by themselves. Write for someone who knows
their code and does not need CVEs explained to them.

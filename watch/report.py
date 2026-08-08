#!/usr/bin/env python3
"""
security-watch -- report rendering.

Turns a correlation into a readable report: Markdown committed to the repo,
plus an optional HTML rendering for previewing. Deterministic -- this module
invents nothing, it formats. The daily routine then prepends a
natural-language summary, but the report stays usable without it.

Delivery is not this module's job: pushing reports/<date>.md triggers the
notify workflow, which opens the GitHub issue.

Stdlib only. Output: reports/<date>.md
"""

from __future__ import annotations

import argparse
import html
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

WATCH_DIR = Path(__file__).resolve().parent
ROOT_DIR = WATCH_DIR.parent
OUT_DIR = WATCH_DIR / "out"
REPORTS_DIR = ROOT_DIR / "reports"

TIER_LABELS = {
    "confirmed": ("A traiter", "Exposition etablie par le scan local"),
    "probable": ("Probable", "Paquet present, version dans la plage vulnerable"),
    "to_review": ("A verifier", "Correspondance partielle, confirmation manuelle requise"),
    "context": ("Contexte", "Exploite activement, sans lien etabli avec ton parc"),
}


def load_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def targets_of(item):
    """Affected targets, deduplicated and readable."""
    seen = []
    for match in item.get("matches") or []:
        label = match.get("repo") or match.get("image") or match.get("name")
        if label and label not in seen:
            seen.append(label)
    return seen


def fix_hint(item):
    """Known fixed versions.

    An advisory spanning several branches (3.x and 4.x) offers more than one:
    show them all rather than none.
    """
    versions = set()
    for match in item.get("matches") or []:
        raw = match.get("fixed") or match.get("first_patched")
        if not raw:
            continue
        # Advisories sometimes list several branches ("4.3.0, 3.15.0"): split,
        # deduplicate, and sort numerically rather than lexically.
        versions.update(part.strip() for part in str(raw).split(",") if part.strip())

    def sort_key(version):
        return [int(p) if p.isdigit() else 0 for p in version.replace("-", ".").split(".")]

    return ", ".join(sorted(versions, key=sort_key)) if versions else None


def split_synthesis(text):
    """Split the summary into its overview and its per-topic notes.

    The routine writes one file, using a heading to start a topic note:

        <overview>
        ## sujet:msrc
        <what those Windows advisories are about>
        ## sujet:arch
        ...

    Per-topic notes matter more than they look: a bare list of CVE links forces
    the reader to open each one just to learn whether it is serious.
    """
    if not text:
        return None, {}

    parts = re.split(r"(?mi)^##\s*sujet\s*:\s*([\w.-]+)\s*$", text)
    overview = parts[0].strip() or None

    notes = {}
    for index in range(1, len(parts) - 1, 2):
        key = parts[index].strip().lower()
        body = parts[index + 1].strip()
        if body:
            notes[key] = body
    return overview, notes


def badges(advisory):
    marks = []
    if advisory.get("exploited"):
        marks.append("EXPLOITE")
    severity = (advisory.get("severity") or "").upper()
    if severity and severity != "UNKNOWN":
        marks.append(severity)
    epss = advisory.get("epss_score")
    if isinstance(epss, (int, float)) and epss >= 0.01:
        marks.append(f"EPSS {epss:.0%}" if epss >= 0.005 else f"EPSS {epss:.3f}")
    cvss = advisory.get("cvss")
    if isinstance(cvss, (int, float)):
        marks.append(f"CVSS {cvss}")
    return marks


# --------------------------------------------------------------------------
# Markdown
# --------------------------------------------------------------------------

def render_markdown(correlation, date_label, synthesis=None, topic_notes=None):
    stats = correlation.get("stats", {})
    feed = correlation.get("feed", {})
    lines = []

    add = lines.append
    add(f"# Veille securite -- {date_label}")
    add("")
    add(f"*{feed.get('advisories', 0)} avis collectes sur "
        f"{(feed.get('window') or {}).get('days', '?')} jour(s). "
        f"{stats.get('confirmed', 0) + stats.get('probable', 0)} te concernent.*")
    add("")

    topic_notes = topic_notes or {}

    if synthesis:
        add("## Résumé")
        add("")
        add(synthesis.strip())
        add("")

    machines = correlation.get("machines") or []
    stale = [m for m in machines if m.get("stale")]
    if stale:
        add("> **Snapshots périmés** : "
            + ", ".join(f"`{m['label']}` ({m['age_days']:.0f} j)" for m in stale)
            + ". Ce rapport les considère à jour alors qu'ils ne le sont pas —"
            + " relance `scan.ps1` ou `scan.sh` sur ces postes.")
        add("")

    if machines:
        add("| Poste | Système | Dernier scan | Constats |")
        add("|---|---|---|---|")
        for machine in machines:
            age = ("jamais" if machine.get("age_days") is None
                   else "aujourd'hui" if machine["age_days"] < 1
                   else f"il y a {machine['age_days']:.0f} j")
            if machine.get("stale"):
                age += " ⚠️"
            add(f"| `{machine['label']}` | {machine.get('os') or '?'} | {age} "
                f"| {machine.get('findings', 0)} |")
        add("")

        android = [m["android"] for m in machines if m.get("android")]
        if android:
            add("Android déclaré : " + ", ".join(
                f"{a.get('device', '?')} (correctif {a.get('security_patch', '?')})"
                for a in android))
            add("")

    actionable = (correlation.get("confirmed") or []) + (correlation.get("probable") or [])
    if not actionable:
        add("## Rien a traiter aujourd'hui")
        add("")
        add("Aucun avis publie sur la fenetre ne correspond a ton inventaire.")
        add("")
    else:
        add(f"## A traiter ({len(actionable)})")
        add("")
        for item in actionable:
            advisory = item["advisory"]
            marks = " · ".join(badges(advisory))
            title = advisory.get("title") or advisory.get("summary") or "(sans titre)"
            add(f"### {advisory.get('id')} — {title}")
            add("")
            if marks:
                add(f"**{marks}**")
                add("")
            add(f"- **Niveau** : {TIER_LABELS[item['tier']][0]} — {item['why']}")
            add(f"- **Concerne** : {', '.join(f'`{t}`' for t in targets_of(item))}")

            versions = sorted({
                f"{m.get('package')} {m.get('installed')}"
                for m in item.get("matches") or [] if m.get("package")})
            if versions:
                add(f"- **Installe** : {', '.join(f'`{v}`' for v in versions)}")
            fix = fix_hint(item)
            if fix:
                add(f"- **Correctif** : `{fix}`")
            if advisory.get("url"):
                add(f"- **Source** : {advisory['url']}")
            add("")

    for tier in ("to_review", "context"):
        bucket = correlation.get(tier) or []
        if not bucket:
            continue
        label, description = TIER_LABELS[tier]
        add(f"## {label} ({len(bucket)})")
        add("")
        add(f"*{description}.*")
        add("")
        for item in bucket:
            advisory = item["advisory"]
            marks = " · ".join(badges(advisory))
            title = advisory.get("title") or advisory.get("summary") or ""
            suffix = f" — {', '.join(targets_of(item))}" if targets_of(item) else ""
            add(f"- **{advisory.get('id')}** {title[:120]}{suffix}"
                + (f"  \n  {marks}" if marks else ""))
        add("")

    topics = correlation.get("topics") or []
    if topics:
        add("## Veille par sujet")
        add("")
        add("| Sujet | Avis | Te concernant | Critical / High |")
        add("|---|---|---|---|")
        for topic in topics:
            sev = topic.get("by_severity") or {}
            crit_high = sev.get("CRITICAL", 0) + sev.get("HIGH", 0)
            total = f"{topic['total']} *(état)*" if topic.get("dateless") else str(topic["total"])
            matched = f"**{topic['matched']}**" if topic.get("matched") else "—"
            add(f"| {topic['label']} | {total} | {matched} | {crit_high or '—'} |")
        add("")
        add("*« état » : source sans date, qui décrit une situation courante et non "
            "des publications du jour.*")
        add("")

        for topic in topics:
            notable = [item for item in topic.get("top") or []
                       if item.get("severity") in ("CRITICAL", "HIGH") or item.get("exploited")]
            note = topic_notes.get(topic["key"])
            if not notable and not note:
                continue
            add(f"**{topic['label']}**")
            add("")
            if note:
                add(note)
                add("")
            for item in notable[:3]:
                marks = []
                if item.get("exploited"):
                    marks.append("EXPLOITÉ")
                if item.get("matched"):
                    marks.append("te concerne")
                suffix = f" — *{', '.join(marks)}*" if marks else ""
                link = f"[{item['id']}]({item['url']})" if item.get("url") else item.get("id")
                # CISA KEV publishes no severity: showing "UNKNOWN" next to
                # "EXPLOITÉ" confuses more than it informs.
                level = f" · {item['severity']}" if item["severity"] != "UNKNOWN" else ""
                add(f"- {link}{level} — {(item.get('title') or '')[:110]}{suffix}")
            add("")

    android = correlation.get("android")
    if android:
        add("## Android")
        add("")
        if android.get("behind"):
            for late in android["behind"]:
                add(f"- **{late.get('device') or late.get('machine')}** : correctif déclaré au "
                    f"`{late['declared_patch']}`, soit **{late['days_behind']} jours de retard** "
                    f"sur le dernier bulletin ({android['latest_bulletin']}).")
        elif android.get("latest_bulletin"):
            add(f"Correctif déclaré à jour vis-à-vis du dernier bulletin "
                f"({android['latest_bulletin']}).")
        else:
            add("Aucun bulletin Android sur la fenêtre — rien à comparer.")
        add("")
        add("> Le niveau de correctif est **déclaré à la main** dans `agent/config.json`. "
            "Aucun scan depuis un PC ne peut le vérifier : s'il est faux, cette section l'est aussi.")
        add("")

    # Declared limitations are deliberately not rendered: they never change, so
    # printing them daily trains the reader to skip this section -- which is the
    # one section that must stay readable when something actually breaks.
    errors = correlation.get("errors") or []
    add("## Couverture")
    add("")
    if errors:
        add("Ce rapport est **partiel**. Ce qui n'a pas pu être analysé :")
        add("")
        for error in errors:
            add(f"- {error}")
    else:
        add("Aucune lacune signalée : toutes les sources et tous les scans ont abouti.")
    add("")
    add("---")
    add("")
    add(f"*Genere par [security-watch](https://github.com/safaridigital/security-watch) "
        f"le {correlation.get('correlated_at')}.*")

    return "\n".join(lines)


# --------------------------------------------------------------------------
# HTML (email)
# --------------------------------------------------------------------------

def markdown_to_html(text):
    """Minimal conversion: paragraphs, lists, **bold**, `code`.

    Enough for the summary, which is short prose. Not worth pulling in a full
    Markdown engine.
    """
    def inline(fragment):
        fragment = html.escape(fragment)
        fragment = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", fragment)
        fragment = re.sub(
            r"`(.+?)`",
            r'<code style="background:#eee;padding:1px 4px;border-radius:2px">\1</code>',
            fragment)
        return fragment

    blocks, bullets = [], []

    def flush_bullets():
        if bullets:
            items = "".join(f'<li style="margin-bottom:3px">{inline(b)}</li>' for b in bullets)
            blocks.append(f'<ul style="padding-left:20px;margin:0 0 8px">{items}</ul>')
            bullets.clear()

    for line in (text or "").splitlines():
        stripped = line.strip()
        if stripped.startswith(("- ", "* ")):
            bullets.append(stripped[2:])
        elif not stripped:
            flush_bullets()
        else:
            flush_bullets()
            blocks.append(f'<p style="margin:0 0 8px">{inline(stripped)}</p>')
    flush_bullets()
    return "".join(blocks)


def render_html(correlation, date_label, synthesis=None, topic_notes=None):
    def esc(value):
        return html.escape(str(value if value is not None else ""))

    stats = correlation.get("stats", {})
    feed = correlation.get("feed", {})
    actionable = (correlation.get("confirmed") or []) + (correlation.get("probable") or [])

    parts = [
        '<div style="font-family:-apple-system,Segoe UI,Roboto,sans-serif;'
        'max-width:680px;margin:0 auto;color:#1a1a1a;line-height:1.5">',
        f'<h1 style="font-size:20px;margin:0 0 4px">Veille securite — {esc(date_label)}</h1>',
        f'<p style="color:#666;margin:0 0 20px;font-size:14px">'
        f'{feed.get("advisories", 0)} avis collectes · '
        f'<strong>{len(actionable)} te concernent</strong></p>',
    ]

    stale = [m for m in (correlation.get("machines") or []) if m.get("stale")]
    if stale:
        listing = ", ".join(f"{esc(m['label'])} ({m['age_days']:.0f} j)" for m in stale)
        parts.append(
            '<div style="background:#fff6e5;border-left:3px solid #d80;padding:10px 16px;'
            'border-radius:3px;margin:0 0 16px;font-size:14px">'
            f'<strong>Snapshots périmés : {listing}</strong><br>'
            '<span style="color:#666">Ce rapport les traite comme à jour alors qu\'ils '
            'ne le sont pas. Relance le scan sur ces postes.</span></div>')

    if synthesis:
        parts.append(
            '<div style="background:#f7f9fc;border:1px solid #dde5f0;padding:14px 18px;'
            'border-radius:4px;margin:0 0 20px;font-size:14px">'
            '<div style="font-size:11px;color:#5577aa;font-weight:600;letter-spacing:.4px;'
            'margin-bottom:8px">RÉSUMÉ</div>'
            + markdown_to_html(synthesis) + '</div>')

    if not actionable:
        parts.append(
            '<div style="background:#f0f7f0;border-left:3px solid #4a4;padding:12px 16px;'
            'border-radius:3px"><strong>Rien a traiter aujourd\'hui.</strong><br>'
            '<span style="color:#555;font-size:14px">Aucun avis publie ne correspond '
            'a ton inventaire.</span></div>')

    for item in actionable:
        advisory = item["advisory"]
        exploited = advisory.get("exploited")
        accent = "#c33" if exploited else "#d80"
        marks = " · ".join(badges(advisory))
        fix = fix_hint(item)

        parts.append(
            f'<div style="border-left:3px solid {accent};padding:10px 16px;margin:0 0 16px;'
            f'background:#fafafa;border-radius:3px">')
        parts.append(
            f'<div style="font-size:11px;color:{accent};font-weight:600;'
            f'letter-spacing:.4px;margin-bottom:4px">{esc(marks)}</div>')
        parts.append(
            f'<div style="font-weight:600;margin-bottom:6px">{esc(advisory.get("id"))} — '
            f'{esc((advisory.get("title") or "")[:140])}</div>')
        parts.append(
            f'<div style="font-size:14px;color:#444">Concerne : '
            + ", ".join(f'<code style="background:#eee;padding:1px 4px;border-radius:2px">'
                        f'{esc(t)}</code>' for t in targets_of(item))
            + '</div>')
        if fix:
            parts.append(
                f'<div style="font-size:14px;color:#444;margin-top:4px">Correctif : '
                f'<code style="background:#e8f4e8;padding:1px 4px;border-radius:2px">'
                f'{esc(fix)}</code></div>')
        if advisory.get("url"):
            parts.append(
                f'<div style="margin-top:6px"><a href="{esc(advisory["url"])}" '
                f'style="color:#06c;font-size:13px">Voir l\'avis</a></div>')
        parts.append("</div>")

    for tier in ("to_review", "context"):
        bucket = correlation.get(tier) or []
        if not bucket:
            continue
        label, description = TIER_LABELS[tier]
        parts.append(f'<h2 style="font-size:15px;margin:24px 0 8px">{esc(label)} '
                     f'<span style="color:#999;font-weight:400">({len(bucket)})</span></h2>')
        parts.append(f'<p style="color:#777;font-size:13px;margin:0 0 8px">{esc(description)}.</p>')
        parts.append('<ul style="font-size:14px;color:#444;padding-left:20px;margin:0">')
        for item in bucket:
            advisory = item["advisory"]
            targets = targets_of(item)
            suffix = f' — {esc(", ".join(targets))}' if targets else ""
            parts.append(f'<li style="margin-bottom:4px"><strong>{esc(advisory.get("id"))}</strong> '
                         f'{esc((advisory.get("title") or "")[:110])}{suffix}</li>')
        parts.append("</ul>")

    topics = correlation.get("topics") or []
    if topics:
        parts.append('<h2 style="font-size:15px;margin:24px 0 8px">Veille par sujet</h2>')
        parts.append('<table style="width:100%;border-collapse:collapse;font-size:13px">')
        parts.append('<tr style="text-align:left;color:#777">'
                     '<th style="padding:4px 0">Sujet</th><th>Avis</th>'
                     '<th>Te concernant</th><th>Crit/High</th></tr>')
        for topic in topics:
            sev = topic.get("by_severity") or {}
            crit_high = sev.get("CRITICAL", 0) + sev.get("HIGH", 0)
            total = (f"{topic['total']} <span style=\"color:#999\">(état)</span>"
                     if topic.get("dateless") else str(topic["total"]))
            matched = (f'<strong style="color:#c33">{topic["matched"]}</strong>'
                       if topic.get("matched") else '<span style="color:#bbb">—</span>')
            parts.append(
                f'<tr style="border-top:1px solid #eee">'
                f'<td style="padding:5px 0">{esc(topic["label"])}</td>'
                f'<td>{total}</td><td>{matched}</td>'
                f'<td>{crit_high or "—"}</td></tr>')
        parts.append("</table>")
        parts.append('<p style="color:#999;font-size:12px;margin:6px 0 0">'
                     '« état » : source sans date, décrivant une situation courante '
                     'et non des publications du jour.</p>')

        for topic in topics:
            note = (topic_notes or {}).get(topic["key"])
            if not note:
                continue
            parts.append(
                f'<div style="margin:12px 0 0;font-size:14px">'
                f'<strong>{esc(topic["label"])}</strong>'
                + markdown_to_html(note) + '</div>')

    android = correlation.get("android")
    if android and android.get("behind"):
        for late in android["behind"]:
            parts.append(
                '<div style="background:#fff6e5;border-left:3px solid #d80;padding:10px 16px;'
                'border-radius:3px;margin:16px 0;font-size:14px">'
                f'<strong>Android — {esc(late.get("device") or late.get("machine"))}</strong><br>'
                f'Correctif déclaré au {esc(late["declared_patch"])}, soit '
                f'<strong>{late["days_behind"]} jours de retard</strong> sur le bulletin du '
                f'{esc(android["latest_bulletin"])}.<br>'
                '<span style="color:#666;font-size:13px">Niveau déclaré à la main : '
                'aucun scan ne peut le vérifier.</span></div>')

    errors = correlation.get("errors") or []
    parts.append('<h2 style="font-size:15px;margin:24px 0 8px">Couverture</h2>')
    if errors:
        parts.append('<p style="font-size:13px;color:#a60;margin:0 0 6px">'
                     'Ce rapport est <strong>partiel</strong>. Non analyse :</p>')
        parts.append('<ul style="font-size:13px;color:#666;padding-left:20px;margin:0">')
        for error in errors:
            parts.append(f'<li>{esc(error)}</li>')
        parts.append("</ul>")
    else:
        parts.append('<p style="font-size:13px;color:#666;margin:0">'
                     'Toutes les sources et tous les scans ont abouti.</p>')

    parts.append(
        '<p style="color:#999;font-size:12px;margin-top:24px;border-top:1px solid #eee;'
        f'padding-top:12px">security-watch · {esc(correlation.get("correlated_at"))}</p>')
    parts.append("</div>")
    return "".join(parts)


# --------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="security-watch report rendering.")
    parser.add_argument("--correlation", type=Path, default=None,
                        help="fichier de correlation (defaut : le plus recent)")
    parser.add_argument("--synthesis", type=Path, default=None,
                        help="synthese Markdown a injecter en tete. Par defaut, "
                             "watch/out/synthesis-<date>.md a cote de la correlation")
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--html-output", type=Path, default=None,
                        help="ecrit aussi le HTML (utile pour previsualiser)")
    args = parser.parse_args()

    path = args.correlation
    if path is None:
        # By modification time, not name: see the note in correlate.py.
        candidates = sorted(OUT_DIR.glob("correlation-*.json"),
                            key=lambda p: p.stat().st_mtime)
        if not candidates:
            print("ERREUR : aucune correlation. Lance d'abord watch/correlate.py.",
                  file=sys.stderr)
            return 2
        path = candidates[-1]

    correlation = load_json(path)
    if correlation is None:
        print(f"ERREUR : correlation illisible : {path}", file=sys.stderr)
        return 2

    # Without an explicit path, pair the correlation with its summary by date so
    # the notify workflow does not have to reconstruct the filename.
    synthesis_path = args.synthesis
    if synthesis_path is None:
        guess = path.parent / path.name.replace("correlation-", "synthesis-").replace(".json", ".md")
        if guess.is_file():
            synthesis_path = guess

    # The summary is a bonus: its absence must never block delivery.
    synthesis = None
    if synthesis_path:
        try:
            synthesis = synthesis_path.read_text(encoding="utf-8").strip() or None
        except OSError as exc:
            print(f"  [!] Synthese ignoree ({exc}) — le rapport part sans elle.",
                  file=sys.stderr)

    overview, topic_notes = split_synthesis(synthesis)

    date_label = datetime.now(timezone.utc).date().isoformat()
    markdown = render_markdown(correlation, date_label, overview, topic_notes)
    html_body = render_html(correlation, date_label, overview, topic_notes)

    output = args.output or (REPORTS_DIR / f"{date_label}.md")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")
    print(f"  Rapport ecrit : {output}")

    if args.html_output:
        args.html_output.parent.mkdir(parents=True, exist_ok=True)
        args.html_output.write_text(html_body, encoding="utf-8")
        print(f"  HTML ecrit    : {args.html_output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

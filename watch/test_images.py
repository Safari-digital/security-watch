#!/usr/bin/env python3
"""
Base-image tests -- resolving a FROM without guessing.

A mis-parsed FROM fails quietly in one of two directions, and both look like a
working scan: an image that is never scanned though the report claims full
coverage, or a build-stage name scanned as if it were an image. Neither raises.

Run:  python watch/test_images.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from audit import group_images, render  # noqa: E402
from scanner import (  # noqa: E402
    expand_vars,
    find_dockerfiles,
    parse_base_images,
    scan_images,
)


def write(root: Path, name: str, body: str):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path


# (name, Dockerfile body, expected image refs, expected unresolved count)
CASES = [
    (
        "simple",
        "FROM node:24-alpine\nRUN echo hi\n",
        ["node:24-alpine"],
        0,
    ),
    (
        # The trap: the second FROM names a stage, not an image. Scanning it
        # would send a bare word to a registry.
        "stage reference",
        "FROM node:24 AS build\nFROM build\nCMD [\"node\"]\n",
        ["node:24"],
        0,
    ),
    (
        "scratch has no filesystem",
        "FROM golang:1.24 AS build\nFROM scratch\nCOPY --from=build /app /app\n",
        ["golang:1.24"],
        0,
    ),
    (
        "platform flag is not the image",
        "FROM --platform=$BUILDPLATFORM node:24 AS build\n",
        ["node:24"],
        0,
    ),
    (
        "ARG default is substituted",
        "ARG VER=24\nFROM node:${VER}-alpine\n",
        ["node:24-alpine"],
        0,
    ),
    (
        "inline default is substituted",
        "FROM ${BASE:-node:24-alpine}\n",
        ["node:24-alpine"],
        0,
    ),
    (
        # Supplied with --build-arg, unknowable from the source. Reported, not
        # invented: a guessed tag would be scanned as though it were real.
        "unresolved variable is reported",
        "ARG REGISTRY\nFROM ${REGISTRY}/app:1.0\n",
        [],
        1,
    ),
    (
        "line continuation",
        "FROM \\\n    node:24-alpine \\\n    AS build\n",
        ["node:24-alpine"],
        0,
    ),
    (
        "comments and lowercase keyword",
        "# FROM commented:1.0\nfrom node:24-alpine\n",
        ["node:24-alpine"],
        0,
    ),
    (
        "one image per occurrence, both kept",
        "FROM node:24-alpine AS build\nFROM node:24-alpine AS runtime\n",
        ["node:24-alpine", "node:24-alpine"],
        0,
    ),
]


def check_parsing(failures):
    for name, body, expected, expected_unresolved in CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = write(root, "Dockerfile", body)
            images, unresolved = parse_base_images(path, root)
            refs = [i["ref"] for i in images]
            if refs != expected:
                failures.append(f"{name} : {refs}, attendu {expected}")
            if len(unresolved) != expected_unresolved:
                failures.append(
                    f"{name} : {len(unresolved)} non resolu(s), attendu {expected_unresolved}")


def check_stage_capture(failures):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        path = write(root, "apps/api/Dockerfile", "FROM node:24 AS build\nFROM nginx:alpine\n")
        images, _ = parse_base_images(path, root)
        stages = [i["stage"] for i in images]
        if stages != ["build", None]:
            failures.append(f"stages = {stages}, attendu ['build', None]")
        # POSIX on every platform: this path is read in a GitHub issue.
        if images[0]["dockerfile"] != "apps/api/Dockerfile":
            failures.append(f"dockerfile = {images[0]['dockerfile']}, "
                            "attendu apps/api/Dockerfile")


def check_expand(failures):
    value, missing = expand_vars("node:$VER", {"VER": "24"})
    if value != "node:24" or missing:
        failures.append(f"expand_vars bare : {value!r} {missing}")

    value, missing = expand_vars("${A}/${B}", {"A": "reg"})
    if missing != ["B"]:
        failures.append(f"expand_vars manquants : {missing}, attendu ['B']")
    if "${B}" not in value:
        failures.append(f"expand_vars : le texte non resolu doit rester tel quel, {value!r}")


def check_discovery(failures):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in ("Dockerfile", "Dockerfile.prod", "api.Dockerfile",
                     "Containerfile", "apps/web/Dockerfile"):
            write(root, name, "FROM node:24\n")
        write(root, "node_modules/dep/Dockerfile", "FROM evil:1\n")
        found = {p.name for p in find_dockerfiles(root)}
        expected = {"Dockerfile", "Dockerfile.prod", "api.Dockerfile", "Containerfile"}
        if not expected <= found:
            failures.append(f"find_dockerfiles : manque {sorted(expected - found)}")
        if len(find_dockerfiles(root)) != 5:
            failures.append("find_dockerfiles : les Dockerfile vendorises doivent etre ignores")


def check_failures_are_reported(failures):
    """A registry that cannot be reached is a gap, never an empty success."""
    images = [{"ref": f"img{i}:1", "dockerfile": "Dockerfile", "stage": None}
              for i in range(12)]
    found, errors, scanned = scan_images("trivy-qui-nexiste-pas", images, timeout=5, limit=3)
    if found or scanned:
        failures.append("scan_images : rien ne doit remonter quand le scanner est absent")
    if len(errors) != 4:  # one truncation notice + one per attempted ref
        failures.append(f"scan_images : {len(errors)} erreur(s), attendu 4")
    if not any("12 references" in e for e in errors):
        failures.append("scan_images : la troncature doit etre annoncee")


def image_finding(**overrides):
    base = {"scope": "image", "image": "base:1", "id": "CVE-1", "package": "pkg",
            "installed": "1.0", "fixed": None, "severity": "MEDIUM",
            "cvss": None, "title": None, "url": None, "detector": "trivy"}
    base.update(overrides)
    return base


def render_one(findings, **entry):
    section = {"ref": "base:1", "os": "alpine 3.19", "eosl": False,
               "dockerfiles": ["Dockerfile"], "stages": []}
    section.update(entry)
    sections = group_images(findings, [section])
    return render("depot", {}, [], [], [], "2026-08-09T00:00:00+00:00", [], sections)


def check_rendering(failures):
    # End of life outranks any single CVE: nothing here will ever be fixed.
    text = render_one([image_finding()], eosl=True)
    if "Fin de support" not in text:
        failures.append("render : une image en fin de support doit etre signalee")
    if "Fin de support" in render_one([image_finding()]):
        failures.append("render : fin de support signalee a tort")

    # A fixable finding must survive the display cap even when milder than the
    # rest, which is the whole point of putting it first.
    findings = [image_finding(id=f"CVE-N{i}", package=f"nofix{i}", severity="HIGH")
                for i in range(20)]
    findings.append(image_finding(id="CVE-FIX", package="actionable",
                                  severity="LOW", fixed="2.0"))
    text = render_one(findings)
    if "actionable" not in text:
        failures.append("render : le paquet corrigeable est tombe sous la troncature")
    if "autre(s) paquet(s)" not in text:
        failures.append("render : la troncature doit etre annoncee")

    text = render_one([])
    if "Aucun paquet système vulnérable" not in text:
        failures.append("render : une image saine doit le dire")


def main():
    failures = []
    check_parsing(failures)
    check_stage_capture(failures)
    check_expand(failures)
    check_discovery(failures)
    check_failures_are_reported(failures)
    check_rendering(failures)

    total = len(CASES) + 2 + 3 + 2 + 3 + 5
    if failures:
        print(f"ECHEC : {len(failures)} probleme(s) sur {total} cas")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"OK : {total}/{total} cas passent")
    return 0


if __name__ == "__main__":
    sys.exit(main())

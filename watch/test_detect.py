#!/usr/bin/env python3
"""
Manifest-detection tests -- the silent half of the coverage question.

An ecosystem that goes undetected does not fail: its scan is skipped, no error
is recorded, and the report announces full coverage over a hole. That is the
failure mode this file exists to catch, so most of these cases are about
finding a manifest somewhere awkward rather than about parsing one.

Run:  python watch/test_detect.py
"""

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "agent"))

from agent import (  # noqa: E402
    SKIP_DIRS,
    detect_ecosystems,
    dotnet_targets,
    find_manifests,
    trivy_skip_args,
)


def make_tree(root: Path, files):
    for relative in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")


# (name, files laid out, ecosystems that must be found, ecosystems that must not)
ECOSYSTEM_CASES = [
    (
        # The regression: apps/<service>/<project>/x.csproj sits three levels
        # down, which a */*/ glob chain never reached.
        "csproj at depth 3",
        ["apps/api/Service.Api/Service.Api.csproj", "package.json"],
        {"dotnet", "npm"},
        set(),
    ),
    (
        # .slnx is the .NET 9 solution format; a migrated repo has no .sln.
        "slnx alone",
        ["src/Thing.slnx"],
        {"dotnet"},
        set(),
    ),
    (
        "root manifests",
        ["pnpm-lock.yaml", "Dockerfile"],
        {"npm", "container"},
        {"dotnet"},
    ),
    (
        # Vendored trees carry thousands of manifests that belong to nobody.
        # Trivy skips them and so must detection, or every repo looks like a
        # Java repo.
        "vendored manifests are ignored",
        ["node_modules/some-dep/pom.xml", "package.json"],
        {"npm"},
        {"java"},
    ),
    (
        "hidden directories are ignored",
        [".cache/build/go.mod", "package.json"],
        {"npm"},
        {"go"},
    ),
    (
        # The bound is deliberate: past it the walk costs more than it finds.
        "past the depth bound",
        ["a/b/c/d/e/deep.csproj"],
        set(),
        {"dotnet"},
    ),
]


def check_ecosystems(failures):
    for name, files, expected, forbidden in ECOSYSTEM_CASES:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            make_tree(root, files)
            found = set(detect_ecosystems(root))
            missing = expected - found
            wrong = forbidden & found
            if missing:
                failures.append(f"{name} : {sorted(missing)} non detecte(s)")
            if wrong:
                failures.append(f"{name} : {sorted(wrong)} detecte(s) a tort")


def check_targets(failures):
    """Solutions lead, projects stay available as the fallback tier."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        make_tree(root, ["apps/api/Api.slnx", "apps/api/Api/Api.csproj",
                         "libs/Core/Core.csproj"])
        tiers = dotnet_targets(root)
        if len(tiers) != 2:
            failures.append(f"dotnet_targets : {len(tiers)} palier(s), attendu 2")
            return
        if [p.name for p in tiers[0]] != ["Api.slnx"]:
            failures.append(f"dotnet_targets : palier 0 = {[p.name for p in tiers[0]]}")
        if sorted(p.name for p in tiers[1]) != ["Api.csproj", "Core.csproj"]:
            failures.append(f"dotnet_targets : palier 1 = {[p.name for p in tiers[1]]}")

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        make_tree(root, ["libs/Core/Core.csproj"])
        tiers = dotnet_targets(root)
        if len(tiers) != 1:
            failures.append(f"dotnet_targets sans solution : {len(tiers)} palier(s), attendu 1")

    with tempfile.TemporaryDirectory() as tmp:
        if dotnet_targets(Path(tmp)):
            failures.append("dotnet_targets : un depot sans .NET doit rendre une liste vide")


def check_limit(failures):
    """`limit` must cap the result, since detection asks for a single hit."""
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        make_tree(root, [f"p{i}/package.json" for i in range(5)])
        if len(find_manifests(root, "package.json", limit=2)) != 2:
            failures.append("find_manifests : limit non respecte")
        if len(find_manifests(root, "package.json")) != 5:
            failures.append("find_manifests : tous les manifestes ne sont pas rendus")


def check_trivy_skips(failures):
    """Nested build output must be out of scope, not just the top-level copy.

    Trivy reads --skip-dirs as a glob relative to the scan root, so dropping
    the `**/` prefix silently puts every nested bin/ and node_modules/ back in
    scope. That is invisible in the output — it inflates the counts instead of
    failing — so it is worth a guard.
    """
    args = trivy_skip_args()
    for name in SKIP_DIRS:
        if name not in args:
            failures.append(f"trivy_skip_args : {name} absent a la racine")
        if f"**/{name}" not in args:
            failures.append(f"trivy_skip_args : {name} non exclu en profondeur")


def main():
    failures = []
    check_ecosystems(failures)
    check_targets(failures)
    check_limit(failures)
    check_trivy_skips(failures)

    total = len(ECOSYSTEM_CASES) + 4 + 2 + len(SKIP_DIRS)
    if failures:
        print(f"ECHEC : {len(failures)} probleme(s) sur {total} cas")
        for failure in failures:
            print(f"  - {failure}")
        return 1

    print(f"OK : {total}/{total} cas passent")
    return 0


if __name__ == "__main__":
    sys.exit(main())

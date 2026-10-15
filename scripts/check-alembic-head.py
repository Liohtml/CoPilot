#!/usr/bin/env python3
"""Fail when backend/alembic has a head the Rust schema fixture does not.

No dependencies: revisions are read from the migration files' source. Run from
anywhere; CI runs it before the Rust e2e tests (.github/workflows/rust.yml).
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSIONS = ROOT / "backend" / "alembic" / "versions"
FIXTURE = ROOT / "crates" / "copilot" / "tests" / "fixtures" / "schema.sql"
TESTED = ROOT / "crates" / "copilot-db" / "src" / "schema.rs"

REV = re.compile(r"^revision(?::\s*str)?\s*=\s*['\"]([0-9a-zA-Z_]+)['\"]", re.M)
DOWN = re.compile(r"^down_revision(?:[^=]*)=\s*(.+)$", re.M)


def main() -> int:
    revisions, parents = set(), set()
    for path in VERSIONS.glob("*.py"):
        text = path.read_text(encoding="utf-8")
        rev = REV.search(text)
        if not rev:
            continue
        revisions.add(rev.group(1))
        down = DOWN.search(text)
        if down:
            parents.update(re.findall(r"['\"]([0-9a-zA-Z_]+)['\"]", down.group(1)))
    heads = sorted(revisions - parents)
    fixture = re.findall(r"INSERT INTO `alembic_version` VALUES \('([0-9a-zA-Z_]+)'\)", FIXTURE.read_text())
    tested = re.findall(r'TESTED_ALEMBIC_HEAD: &str = "([0-9a-zA-Z_]+)"', TESTED.read_text())
    print(f"alembic heads: {heads}; fixture: {fixture}; TESTED_ALEMBIC_HEAD: {tested}")
    if len(heads) != 1:
        print("expected exactly one Alembic head")
        return 1
    if fixture != heads or tested != heads:
        print(
            "The Rust schema fixture is behind the migrations. Migrate a disposable database to head, "
            "run scripts/dump-schema.sh, update TESTED_ALEMBIC_HEAD in crates/copilot-db/src/schema.rs, "
            "and check the Rust modules against the new columns.",
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

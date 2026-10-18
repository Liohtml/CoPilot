#!/usr/bin/env python3
"""Fail when backend/alembic gains a migration: Alembic is frozen at the Rust baseline's revision.

Since phase 5 the Rust binary owns the schema (crates/copilot-migrate): its baseline is the schema
at the Alembic head d15ab1ed7e1e, and every later change is a Rust migration
(crates/copilot-migrate/migrations/). A new Python migration would never run under the Rust
service, so it is an error this check reports: write it as a Rust migration instead.

No dependencies: revisions are read from the migration files' source. Run from anywhere; CI runs it
before the Rust e2e tests (.github/workflows/rust.yml).
"""
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
VERSIONS = ROOT / "backend" / "alembic" / "versions"
FIXTURE = ROOT / "crates" / "copilot" / "tests" / "fixtures" / "schema.sql"
TESTED = ROOT / "crates" / "copilot-db" / "src" / "schema.rs"
BASELINE = ROOT / "crates" / "copilot-migrate" / "migrations" / "0001_baseline.sql"
MIGRATIONS = ROOT / "crates" / "copilot-migrate" / "src" / "migrations.rs"
FROZEN = ROOT / "crates" / "copilot-migrate" / "src" / "alembic_revisions.json"

REV = re.compile(r"^revision(?::\s*str)?\s*=\s*['\"]([0-9a-zA-Z_]+)['\"]", re.M)
DOWN = re.compile(r"^down_revision(?:[^=]*)=\s*(.+)$", re.M)
INSERT = re.compile(r"INSERT INTO `alembic_version` VALUES \('([0-9a-zA-Z_]+)'\)")


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
    frozen = json.loads(FROZEN.read_text())
    head = re.findall(r'ALEMBIC_HEAD: &str = "([0-9a-zA-Z_]+)"', MIGRATIONS.read_text())
    fixture = INSERT.findall(FIXTURE.read_text())
    baseline = INSERT.findall(BASELINE.read_text())
    tested = re.findall(r'TESTED_ALEMBIC_HEAD: &str = "([0-9a-zA-Z_]+)"', TESTED.read_text())
    print(f"alembic heads: {heads}; frozen at: {head}; baseline: {baseline}; fixture: {fixture}; TESTED_ALEMBIC_HEAD: {tested}")
    failures = []
    new = sorted(revisions - set(frozen["revisions"]))
    if new:
        failures.append(
            f"new Alembic migration(s) {new}: Alembic is frozen at {frozen['head']} since the Rust binary owns the schema. "
            "Write the change as a Rust migration (crates/copilot-migrate/migrations/000N_<what>.sql, then a Migration in "
            "MIGRATIONS) and remove the Python one.",
        )
    gone = sorted(set(frozen["revisions"]) - revisions)
    if gone:
        failures.append(f"Alembic migration(s) {gone} were removed: a Python backend could no longer read databases at those revisions.")
    if heads != [frozen["head"]] or head != heads or baseline != heads or tested != heads:
        failures.append(
            f"the Alembic head, the baseline and TESTED_ALEMBIC_HEAD must all be {frozen['head']} "
            f"(heads {heads}, ALEMBIC_HEAD {head}, baseline {baseline}, TESTED_ALEMBIC_HEAD {tested}).",
        )
    if fixture != [frozen["head"]]:
        failures.append(f"the e2e fixture's alembic_version must be {frozen['head']} (found {fixture}).")
    for f in failures:
        print(f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

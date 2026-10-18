#!/usr/bin/env python3
"""Check the Compose files, `.env.example` and the Rust image against what the Rust backend reads.

Run from anywhere (CI runs it on every change to these files):

    python3 scripts/check-compose.py

It needs Docker Compose v2 (`docker compose config` resolves the files, their interpolation,
`env_file`, profiles and `!reset` without a Docker daemon) and nothing but the standard library.

The variables the binary knows are the table in `crates/copilot-core/src/env_vars.rs` (what
`copilot doctor` lists unknown variables against). The checks:

1. **The sources.** Every environment variable the Rust sources read (outside the tests) is in
   that table, as read, test-only or system.
2. **`.env.example`.** It documents every variable the binary reads (set, or commented out with
   its default) and every connector the startup tasks seed, names only variables the table knows,
   and none of the test-only stand-ins or obsolete names.
3. **The layouts.** The base file (Rust alone), the `legacy` profile, the staged rollout
   (`docker-compose.rust.yml`, with and without `COPILOT_SCHEDULER_OWNER=rust`) and the rollback
   (`docker-compose.legacy.yml`), each resolved with `.env.example` as the `.env`: exactly one
   service answers to `copilot-backend` and publishes port 5000; exactly one scheduler owns the
   schedule (the Rust service under `COPILOT_SCHEDULER_OWNER=rust`, else one APScheduler), and a
   Rust service in the hand-over reaches a Python backend through `COPILOT_LEGACY_URL`; the Rust
   service gets every variable it needs and only variables it reads in its own `environment:`, no
   test-only one anywhere; every volume exists, the data directory and ScoutSuite's reports are
   mounted where the binary looks for them (read-write, the init step handing them to the image's
   uid) and shared with the Python backend; the images are the ones `docker.yml` pushes.
4. **The image.** Every file the release build embeds from outside `crates/` is copied by
   `crates/copilot/Dockerfile` and allowed by its `.dockerignore`, the runtime user's uid is the
   one the init step hands the data to, and the `HEALTHCHECK` probes the route the binary serves.

Then a self-test: each breakage in `SELF_TEST` (the standby running APScheduler, a read-only data
directory, MinIO's objects handed over, a stand-in passed, …) is applied to a copy of the files and
must fail the layout checks, so a check that stopped biting is noticed.

Exits non-zero, naming every failure.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV_VARS_RS = ROOT / "crates" / "copilot-core" / "src" / "env_vars.rs"
ENV_EXAMPLE = ROOT / ".env.example"
DOCKERFILE = ROOT / "crates" / "copilot" / "Dockerfile"
DOCKERIGNORE = ROOT / "crates" / "copilot" / "Dockerfile.dockerignore"
DOCKER_WORKFLOW = ROOT / ".github" / "workflows" / "docker.yml"
APP_RS = ROOT / "crates" / "copilot" / "src" / "app.rs"
COMPOSE_FILES = ("docker-compose.yml", "docker-compose.rust.yml", "docker-compose.legacy.yml")

RUST_IMAGE = "ghcr.io/socfortress/copilot-rs"
PYTHON_IMAGE = "ghcr.io/socfortress/copilot-backend"
RUST_SERVICE = "copilot-backend"
INIT_SERVICE = "copilot-backend-init"
LEGACY_SERVICE = "copilot-backend-legacy"
LEGACY_PROFILE = "legacy"
BACKEND_NAME = "copilot-backend"
BACKEND_PORT = "5000"

# What the Rust service cannot start or work without; each must reach it (from `.env`).
# MYSQL_ROOT_PASSWORD: the startup tasks' PRODUCTION bootstrap (ENVIRONMENT defaults to it).
REQUIRED = (
    "JWT_SECRET",
    "MYSQL_URL",
    "MYSQL_USER",
    "MYSQL_PASSWORD",
    "MYSQL_ROOT_PASSWORD",
    "MINIO_URL",
    "MINIO_ROOT_USER",
    "MINIO_ROOT_PASSWORD",
)
# What the deployment fixes in the Rust service's own `environment:` (the paths are the Python
# backend's, so files, rows and the connector rows' paths stay valid across a rollback).
FIXED = {
    "COPILOT_BACKEND_DATA_DIR": "/opt/copilot/backend/data",
    "COPILOT_SCOUTSUITE_DIR": "/opt/copilot/backend",
    "COPILOT_MIMECAST_DIR": "/opt/copilot/backend/data/mimecast",
    "COPILOT_RUN_MIGRATIONS": "true",
    "COPILOT_STARTUP_TASKS": "true",
}
# Python's `py_scheduler_enabled()`: anything but these runs APScheduler.
PY_SCHEDULER_OFF = ("false", "0", "no", "off")
# String literals the source scan meets in env-reading files that are not variables.
NOT_ENV = {
    "IN_PROGRESS",
    "PENDING_CUSTOMER",
    "FALSE_POSITIVE",
}

failures: list[str] = []


def fail(message: str) -> None:
    failures.append(message)


# --------------------------------------------------------------------------- the table


def load_table() -> tuple[dict[str, str], list[str], list[str], list[str]]:
    """`KNOWN` as {name: kind}, and the connector seed prefixes, suffixes and extras."""
    text = ENV_VARS_RS.read_text()
    known: dict[str, str] = {}
    for name, kind in re.findall(r'^\s*\("([A-Za-z][A-Za-z0-9_]*)",\s*(\w+)\),', text, re.M):
        if name in known:
            fail(f"env_vars.rs: {name} listed twice")
        known[name] = kind

    def strings(const: str) -> list[str]:
        block = re.search(rf"pub const {const}: &\[&str\] = &\[(.*?)\];", text, re.S)
        if block is None:
            fail(f"env_vars.rs: {const} not found")
            return []
        return re.findall(r'"([^"]+)"', block.group(1))

    return known, strings("CONNECTOR_SEED_PREFIXES"), strings("SEED_SUFFIXES"), strings("SEED_EXTRA")


KNOWN, SEED_PREFIXES, SEED_SUFFIXES, SEED_EXTRA = load_table()


def kind(name: str) -> str | None:
    """`copilot_core::env_vars::kind`."""
    if name in KNOWN:
        return KNOWN[name]
    if name in SEED_EXTRA:
        return "Seed"
    for prefix in SEED_PREFIXES:
        if name.startswith(prefix) and name[len(prefix) :] in SEED_SUFFIXES:
            return "Seed"
    return None


# --------------------------------------------------------------------------- 1. the sources

# A variable's name; the looser patterns (loop arrays, helpers' arguments) want an underscore.
NAME = r"[A-Z][A-Z0-9_]*"
ENV_NAME = r"[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+"
READS_ENV = re.compile(r"env::var(?:_os)?\(|EnvFile|\benv\.get")


def without_tests(text: str) -> str:
    """The file up to its first inline `#[cfg(test)]` module (the crates keep tests last)."""
    match = re.search(r"^\s*#\[cfg\(test\)\]\s*\n\s*(?:pub\s+)?mod\s+\w+\s*\{", text, re.M)
    return text[: match.start()] if match else text


def test_only_files() -> set[Path]:
    """The files of out-of-line test modules (`#[cfg(test)] mod name;`): compiled only for the
    tests, like the inline modules `without_tests` cuts off."""
    files: set[Path] = set()
    for path in (ROOT / "crates").glob("*/src/**/*.rs"):
        names = re.findall(r"^\s*#\[cfg\(test\)\]\s*\n\s*(?:pub\s+)?mod\s+(\w+)\s*;", path.read_text(), re.M)
        base = path.parent if path.name in ("lib.rs", "main.rs", "mod.rs") else path.parent / path.stem
        for name in names:
            files.update(f for f in (base / f"{name}.rs", base / name / "mod.rs") if f.exists())
    return files


def rust_sources() -> list[Path]:
    """Every source file of the crates the release build compiles (test-only modules left out)."""
    skip = test_only_files()
    return [p for p in sorted((ROOT / "crates").glob("*/src/**/*.rs")) if p not in skip]


def env_reads(text: str) -> set[str]:
    """Variable names a Rust source reads: literals in a read call's argument (and clap's
    `env = "…"`), `const`s, `const` lists and loop arrays handed to one, and literals handed to
    a local closure or function that reads its parameter."""
    names: set[str] = set()
    calls = r"(?:env::var(?:_os)?|\.get_raw|\.get_or|\.get_bool_or|\.get_bool|\.get_u64|\.get)"
    names.update(re.findall(rf'{calls}\(\s*"({NAME})"', text))
    names.update(re.findall(rf'#\[arg\([^)]*\benv = "({NAME})"', text))
    for const, value in re.findall(rf'const (\w+): &str = "({NAME})";', text):
        if re.search(rf"{calls}\(\s*{const}\s*\)", text):
            names.add(value)
    for const, items in re.findall(r"const (\w+): &\[&str\] = &\[(.*?)\];", text, re.S):
        if re.search(rf"\b{const}\s*\.iter\(\)", text):
            names.update(re.findall(rf'"({ENV_NAME})"', items))
    for var, items in re.findall(r"for (\w+) in \[([^\]]*)\]", text):
        if re.search(rf"{calls}\(\s*{var}\s*\)", text):
            names.update(re.findall(rf'"({ENV_NAME})"', items))
    helpers = set()
    for helper, param in re.findall(r"let (\w+) = \|(\w+): &str[^|]*\|", text):
        if re.search(rf"{calls}\(\s*{param}\s*\)", text):
            helpers.add(helper)
    for helper, param in re.findall(r"fn (\w+)\((?:[^)]*?,\s*)?(\w+): &str", text):
        if re.search(rf"{calls}\(\s*{param}\s*\)", text):
            helpers.add(helper)
    for helper in helpers:
        names.update(re.findall(rf'\b{helper}\(\s*(?:\w+,\s*)?"({ENV_NAME})"', text))
    return names - NOT_ENV


def check_sources() -> None:
    read: dict[str, str] = {}
    for path in rust_sources():
        text = without_tests(path.read_text())
        if not READS_ENV.search(text):
            continue
        for name in env_reads(text):
            read.setdefault(name, str(path.relative_to(ROOT)))
    for name, where in sorted(read.items()):
        k = kind(name)
        if k not in ("Read", "Test", "System"):
            fail(f"{where} reads {name}, which env_vars.rs lists as {k or 'unknown'} (add it as Read, Test or System)")


# --------------------------------------------------------------------------- 2. .env.example


def env_example() -> tuple[set[str], set[str]]:
    """(every name `.env.example` sets or shows commented out, the names it sets)."""
    documented: set[str] = set()
    assigned: set[str] = set()
    for line in ENV_EXAMPLE.read_text().splitlines():
        match = re.match(r"^(#\s*)?([A-Za-z_][A-Za-z0-9_]*)=", line.strip())
        if match:
            documented.add(match.group(2))
            if not match.group(1):
                assigned.add(match.group(2))
    return documented, assigned


def check_env_example() -> None:
    documented, assigned = env_example()
    for name, k in sorted(KNOWN.items()):
        if k == "Read" and name not in documented:
            fail(f".env.example does not document {name}, which the Rust backend reads")
    for prefix in SEED_PREFIXES:
        if not any(prefix + suffix in documented for suffix in SEED_SUFFIXES):
            fail(f".env.example documents none of {prefix}_* (the {prefix} connector's seed)")
    for name in SEED_EXTRA:
        if name not in documented:
            fail(f".env.example does not document {name} (a connector's extra data seed)")
    for name in sorted(documented):
        k = kind(name)
        if k is None:
            fail(f".env.example names {name}, which no CoPilot service reads (add it to env_vars.rs or drop it)")
        elif k == "Test":
            fail(f".env.example names {name}: test harnesses only, never set in production")
        elif k == "Obsolete":
            fail(f".env.example names {name}, which no CoPilot service reads any more")
        elif k == "System":
            fail(f".env.example names {name}, which the system or the image sets")
    for name in REQUIRED:
        if name not in assigned:
            fail(f".env.example does not set {name} (required by the Rust backend)")


# --------------------------------------------------------------------------- 3. the layouts


def compose_config(workdir: Path, files: list[str], profiles: list[str], env: dict[str, str]) -> dict:
    args = ["docker", "compose"]
    for f in files:
        args += ["-f", f]
    for p in profiles:
        args += ["--profile", p]
    args += ["config", "--format", "json"]
    clean = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "DOCKER_CONFIG", "DOCKER_HOST")}
    clean.update(env)
    out = subprocess.run(args, cwd=workdir, env=clean, capture_output=True, text=True)
    if out.returncode != 0:
        fail(f"docker compose {' '.join(args[2:])} failed: {out.stderr.strip()}")
        return {"services": {}, "volumes": {}}
    return json.loads(out.stdout)


def image_of(service: dict) -> str:
    return (service.get("image") or "").rsplit(":", 1)[0]


def names_of(name: str, service: dict) -> set[str]:
    names = {name}
    for net in (service.get("networks") or {}).values():
        names.update((net or {}).get("aliases") or [])
    return names


def mounts(service: dict) -> dict[str, dict]:
    return {v["target"]: v for v in service.get("volumes") or []}


def py_scheduler_on(service: dict) -> bool:
    value = (service.get("environment") or {}).get("COPILOT_PY_SCHEDULER")
    return (value if value is not None else "true").strip().lower() not in PY_SCHEDULER_OFF


def check_layout(label: str, config: dict, explicit: dict, workdir: Path) -> None:
    services = config.get("services", {})
    rust = {n: s for n, s in services.items() if image_of(s) == RUST_IMAGE and n != INIT_SERVICE}
    python = {n: s for n, s in services.items() if image_of(s) == PYTHON_IMAGE}

    answering = [n for n, s in services.items() if BACKEND_NAME in names_of(n, s)]
    if len(answering) != 1:
        fail(f"{label}: {len(answering)} services answer to {BACKEND_NAME} ({answering}), want exactly one")
    publishing = [n for n, s in services.items() if any(str(p.get("published")) == BACKEND_PORT for p in s.get("ports") or [])]
    if len(publishing) != 1 or publishing != answering:
        fail(f"{label}: port {BACKEND_PORT} is published by {publishing}, want the one {BACKEND_NAME} ({answering})")

    owners = [n for n, s in rust.items() if (s.get("environment") or {}).get("COPILOT_SCHEDULER_OWNER", "").strip() == "rust"]
    owners += [n for n, s in python.items() if py_scheduler_on(s)]
    if len(owners) != 1:
        fail(f"{label}: the schedule has {len(owners)} owners ({owners}), want exactly one")
    for name, service in rust.items():
        env = service.get("environment") or {}
        if env.get("COPILOT_SCHEDULER_OWNER", "").strip() != "rust":
            legacy = re.match(r"^https?://([^:/]+):(\d+)/?$", env.get("COPILOT_LEGACY_URL") or "")
            targets = {alias for n, s in python.items() for alias in names_of(n, s)}
            if not legacy or legacy.group(1) not in targets or legacy.group(2) != BACKEND_PORT:
                fail(f"{label}: {name} hands the schedule over but its COPILOT_LEGACY_URL reaches no Python backend")

    for name, service in rust.items():
        env = service.get("environment") or {}
        for var in REQUIRED:
            if not env.get(var):
                fail(f"{label}: {name} does not get {var}")
        for var, value in FIXED.items():
            if env.get(var) != value:
                fail(f"{label}: {name} has {var}={env.get(var)!r}, want {value!r}")
        for var in sorted(env):
            k = kind(var)
            if k is None:
                fail(f"{label}: {name} is passed {var}, which env_vars.rs does not know")
            elif k == "Test":
                fail(f"{label}: {name} is passed {var}, a test harness's stand-in")
        for var in sorted((explicit.get(name) or {}).get("environment") or {}):
            if kind(var) != "Read":
                fail(f"{label}: {name}'s environment sets {var}, which the Rust backend does not read")
        check_mounts(label, name, service, services, workdir)
    for name, service in python.items():
        for var in service.get("environment") or {}:
            if kind(var) == "Test":
                fail(f"{label}: {name} is passed {var}, a test harness's stand-in")

    declared = set(config.get("volumes") or {})
    for name, service in services.items():
        for volume in service.get("volumes") or []:
            if volume.get("type") == "volume" and volume.get("source") not in declared:
                fail(f"{label}: {name} mounts the undeclared volume {volume.get('source')}")


def check_mounts(label: str, name: str, service: dict, services: dict, workdir: Path) -> None:
    env = service.get("environment") or {}
    own = mounts(service)
    data_dir = env.get("COPILOT_BACKEND_DATA_DIR", "")
    reports = env.get("COPILOT_SCOUTSUITE_DIR", "") + "/scoutsuite-report"
    mimecast = env.get("COPILOT_MIMECAST_DIR", "")
    data = own.get(data_dir)
    if data is None or data.get("type") != "bind" or data.get("read_only"):
        fail(f"{label}: {name} does not mount its data directory {data_dir} read-write")
    if reports not in own:
        fail(f"{label}: {name} does not mount ScoutSuite's reports at {reports}")
    if not any(mimecast == t or mimecast.startswith(t.rstrip("/") + "/") for t in own):
        fail(f"{label}: {name}'s COPILOT_MIMECAST_DIR {mimecast} is not on a mounted volume")

    init = services.get(INIT_SERVICE)
    depends = (service.get("depends_on") or {}).get(INIT_SERVICE) or {}
    if init is None or depends.get("condition") != "service_completed_successfully":
        fail(f"{label}: {name} does not wait for {INIT_SERVICE} to complete")
    else:
        init_mounts = mounts(init)
        for target in (data_dir, reports):
            if target not in init_mounts or init_mounts[target].get("source") != own.get(target, {}).get("source"):
                fail(f"{label}: {INIT_SERVICE} does not mount {name}'s {target}")
        if str(init.get("user")) not in ("0", "0:0", "root"):
            fail(f"{label}: {INIT_SERVICE} must run as root to hand the files over")
        script = " ".join(init.get("command") or [])
        uid = runtime_uid()
        for target in (data_dir, reports):
            if target not in script:
                fail(f"{label}: {INIT_SERVICE} does not hand {target} over")
        if f"{uid}:{uid}" not in script:
            fail(f"{label}: {INIT_SERVICE} hands the files to another uid than the image's ({uid})")
        # Another service's data inside the data directory (MinIO's objects) is left alone.
        if data is not None:
            for other, s in services.items():
                for m in s.get("volumes") or []:
                    source = m.get("source", "")
                    if other not in (name, INIT_SERVICE) and image_of(s) not in (RUST_IMAGE, PYTHON_IMAGE) and m.get("type") == "bind":
                        if source.startswith(data["source"].rstrip("/") + "/"):
                            inside = data_dir + source[len(data["source"].rstrip("/")) :]
                            if f"-path {inside} -prune" not in script:
                                fail(f"{label}: {INIT_SERVICE} would take {other}'s {inside} from it")

    for other, s in services.items():
        if image_of(s) != PYTHON_IMAGE:
            continue
        theirs = mounts(s)
        for target in (data_dir, reports):
            if theirs.get(target, {}).get("source") != own.get(target, {}).get("source"):
                fail(f"{label}: {other} and {name} do not share {target}")


def check_layouts(edits: dict[str, tuple[str, str]] | None = None) -> None:
    """Every layout; `edits` ({file: (old, new)}) changes a copy of the files first (the self-test)."""
    if shutil.which("docker") is None:
        fail("docker compose is needed (Docker Compose v2): docker not found")
        return
    with tempfile.TemporaryDirectory(prefix="check-compose-") as tmp:
        work = Path(tmp)
        for f in COMPOSE_FILES:
            text = (ROOT / f).read_text()
            if edits and f in edits:
                old, new = edits[f]
                if old not in text:
                    fail(f"self-test: {f} no longer holds {old!r}")
                text = text.replace(old, new)
            (work / f).write_text(text)
        layouts = [
            ("base", ["docker-compose.yml"], [], {}),
            ("base + legacy profile", ["docker-compose.yml"], [LEGACY_PROFILE], {}),
            ("staged rollout (hand-over)", ["docker-compose.yml", "docker-compose.rust.yml"], [], {}),
            ("staged rollout (Rust owns)", ["docker-compose.yml", "docker-compose.rust.yml"], [], {"COPILOT_SCHEDULER_OWNER": "rust"}),
            ("rollback", ["docker-compose.yml", "docker-compose.legacy.yml"], [], {}),
        ]
        for label, files, profiles, env in layouts:
            # What each service's own `environment:` sets: resolved against an empty .env.
            (work / ".env").write_text("")
            explicit = compose_config(work, files, profiles, env).get("services", {})
            shutil.copy(ENV_EXAMPLE, work / ".env")
            config = compose_config(work, files, profiles, env)
            check_layout(label, config, explicit, work)
            services = config.get("services", {})
            python = [n for n, s in services.items() if image_of(s) == PYTHON_IMAGE]
            if label == "base" and python:
                fail(f"base: {python} start without a profile")
            if label == "base + legacy profile" and python != [LEGACY_SERVICE]:
                fail(f"base + legacy profile: the Python backend is {python}, want {LEGACY_SERVICE}")
            if label == "rollback" and any(image_of(s) == RUST_IMAGE for s in services.values()):
                fail("rollback: a Rust service still starts")


# --------------------------------------------------------------------------- 4. the image


def runtime_uid() -> str:
    match = re.search(r"useradd [^\n]*--uid (\d+)", DOCKERFILE.read_text())
    return match.group(1) if match else "?"


def embedded_paths() -> set[str]:
    """Paths outside `crates/` the release build reads: `include_*!` outside the tests, and the
    directories a `build.rs` reads."""
    paths: set[str] = set()
    for path in rust_sources():
        text = without_tests(path.read_text())
        for rel in re.findall(r'include_(?:str|bytes)!\(\s*"([^"]+)"', text):
            target = (path.parent / rel).resolve()
            if not str(target).startswith(str(ROOT / "crates")):
                paths.add(str(target.relative_to(ROOT)))
    for build in sorted((ROOT / "crates").glob("*/build.rs")):
        for rel in re.findall(r'"((?:\.\./)+[^"]+)"', build.read_text()):
            target = (build.parent / rel).resolve()
            if not str(target).startswith(str(ROOT / "crates")):
                paths.add(str(target.relative_to(ROOT)))
    return paths


def check_image() -> None:
    dockerfile = DOCKERFILE.read_text()
    copied = re.findall(r"^COPY (?!--from)(\S+)", dockerfile, re.M)
    allowed = [line.strip()[1:].rstrip("/") for line in DOCKERIGNORE.read_text().splitlines() if line.strip().startswith("!")]
    for path in sorted(embedded_paths()):
        if not any(path == c.rstrip("/") or path.startswith(c.rstrip("/") + "/") for c in copied):
            fail(f"crates/copilot/Dockerfile does not COPY {path}, which the release build embeds")
        if not any(path == a or path.startswith(a + "/") for a in allowed):
            fail(f"crates/copilot/Dockerfile.dockerignore does not allow {path}")
    health = re.search(r"HEALTHCHECK[^\n]*\\\n\s*CMD [^\n]*(/_copilot/health)", dockerfile)
    if health is None:
        fail("crates/copilot/Dockerfile has no HEALTHCHECK on /_copilot/health")
    elif '"/_copilot/health"' not in APP_RS.read_text():
        fail("the HEALTHCHECK probes /_copilot/health, which app.rs does not route")
    workflow = DOCKER_WORKFLOW.read_text()
    for image in (RUST_IMAGE, PYTHON_IMAGE):
        if image not in workflow:
            fail(f".github/workflows/docker.yml does not push {image}, which the Compose files run")


# Breakages the layout checks must catch: (what, file, old text, new text, a word of the failure).
SELF_TEST = [
    ("the standby runs APScheduler", "docker-compose.yml", "- COPILOT_PY_SCHEDULER=false", "- COPILOT_PY_SCHEDULER=true", "owners"),
    ("nobody owns the schedule", "docker-compose.yml", "- COPILOT_SCHEDULER_OWNER=rust", "- COPILOT_SCHEDULER_OWNER=", "owners"),
    (
        "the data directory read-only",
        "docker-compose.yml",
        "- ./data/data:/opt/copilot/backend/data\n            - scoutsuite",
        "- ./data/data:/opt/copilot/backend/data:ro\n            - scoutsuite",
        "read-write",
    ),
    (
        "the init step not awaited",
        "docker-compose.yml",
        "condition: service_completed_successfully",
        "condition: service_started",
        "wait for",
    ),
    (
        "MinIO's objects handed over",
        "docker-compose.yml",
        "-path /opt/copilot/backend/data/minio-data -prune",
        "-path /nowhere -prune",
        "copilot-minio",
    ),
    (
        "a test stand-in passed",
        "docker-compose.yml",
        "- COPILOT_SCHEDULER_OWNER=rust",
        "- COPILOT_SCHEDULER_OWNER=rust\n            - COPILOT_MINIO_ENDPOINT=x",
        "stand-in",
    ),
    (
        "an unknown variable passed",
        "docker-compose.yml",
        "- COPILOT_SCHEDULER_OWNER=rust",
        "- COPILOT_SCHEDULER_OWNER=rust\n            - COPILOT_SHEDULER=rust",
        "does not know",
    ),
    (
        "the hand-over reaches no Python",
        "docker-compose.rust.yml",
        "- COPILOT_LEGACY_URL=http://copilot-backend-legacy:5000",
        "- COPILOT_LEGACY_URL=",
        "no Python backend",
    ),
    (
        "the rollback answers to no name",
        "docker-compose.legacy.yml",
        "                    - copilot-backend\n",
        "                    - copilot-python\n",
        "answer to",
    ),
]


def self_test() -> None:
    """Each breakage of SELF_TEST must fail the layout checks, naming it."""
    global failures
    kept = failures
    for what, file, old, new, word in SELF_TEST:
        failures = []
        check_layouts({file: (old, new)})
        caught = [m for m in failures if word in m and not m.startswith("self-test")]
        broken = [m for m in failures if m.startswith("self-test")]
        kept += broken
        if not caught and not broken:
            kept.append(f"self-test: {what} ({file}) passed the layout checks")
    failures = kept


def main() -> int:
    check_sources()
    check_env_example()
    check_layouts()
    check_image()
    if not failures:
        self_test()
    if failures:
        for message in failures:
            print(f"FAIL {message}")
        print(f"{len(failures)} check(s) failed")
        return 1
    print(f"ok: the sources, .env.example, the five Compose layouts and the Rust image agree; {len(SELF_TEST)} breakages caught")
    return 0


if __name__ == "__main__":
    sys.exit(main())

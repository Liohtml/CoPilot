"""Generate the startup vectors: what the Python backend's `lifespan` seeds, from its own lists.

    MYSQL_PASSWORD=x MYSQL_ROOT_PASSWORD=x JWT_SECRET=<not the default> \
        backend/.venv/bin/python -I scripts/gen-startup-vectors.py

(run from the repository root; it imports the backend, which connects to nothing here: every
function that would talk to MySQL or MinIO is run on a stand-in session or patched.) It writes two
files:

* `crates/copilot-migrate/src/alembic_revisions.json` — every revision of `backend/alembic/versions/`
  (Alembic's `ScriptDirectory`, newest first) and the head. Alembic is frozen at that head: the Rust
  runner tells a database at an older revision (refused, with what to do) from one at a revision no
  CoPilot release has (refused), and `scripts/check-alembic-head.py` fails on any new revision.
* `crates/copilot-startup/src/startup_vectors.json` — the catalogs `copilot-startup` holds as data,
  each as `db_populate.py` / `db_setup.py` / the scheduler build it:
  - `connectors`: `get_connectors_list()`'s arguments to `load_connector_data`, and the row that
    function builds with no variable set and with `connector_env` set (the prefix rule, the
    `os.getenv` defaults, `bool(os.getenv("…_VERIFIED", False))`: "false" is `True`);
  - `deleted_connectors`, `roles` (`ROLES`);
  - `integrations` / `network_connectors`: name, description and the SHA-256 and length of the
    deployment instructions `load_markdown_for_*` reads (run from `backend/`, as the image does), with
    the file name it opens; their auth keys in `get_available_*_auth_keys_list`'s order; the
    placeholder text;
  - `templates`: `BUILTIN_TEMPLATES`; `portal_defaults`: `CustomerPortalSettings.get_default_values()`;
  - `jobs`: what `initialize_job_metadata` adds on an empty table; `buckets`: `create_buckets()`'s
    names in order; `users`: the admin and scheduler rows `create_*_user` add and the length
    `Password.generate` is asked for; `password_classes`: `Password.generate`'s four alphabets.

Regenerate after a change to any of those lists, to the markdown files, or to an Alembic revision.
"""

import asyncio
import hashlib
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKEND = os.path.join(ROOT, "backend")
sys.path.insert(0, BACKEND)
os.chdir(BACKEND)


def connector_env(args_list):
    """Every variable the connectors read, for the rows built "with the environment set": each prefix
    gets its six variables (and its extra-data key), with values that exercise `load_connector_data`."""
    env = {}
    for i, args in enumerate(args_list):
        name = args[0]
        prefix = name.upper().replace("-", "_").replace(" ", "_")
        env[f"{prefix}_URL"] = f"https://{prefix.lower()}.example:{9000 + i}"
        env[f"{prefix}_USERNAME"] = "" if i % 3 == 0 else f"user-{i}"
        env[f"{prefix}_PASSWORD"] = f"pw-{i}"
        env[f"{prefix}_API_KEY"] = f"key-{i}" if i % 2 else ""
        if i % 4 != 1:
            env[f"{prefix}_SUPPORTS"] = f"supports {i}"
        # bool() of the raw text: every non-empty value is True, "false" included.
        env[f"{prefix}_VERIFIED"] = ["false", "", "1", "no"][i % 4]
        if args[4]:
            env[args[4]] = f"extra {i}"
    return env


class Scalars:
    def __init__(self, value):
        self.value = value

    def first(self):
        return self.value

    def one_or_none(self):
        return self.value

    def all(self):
        return [] if self.value is None else [self.value]


class Result:
    def __init__(self, value):
        self.value = value

    def scalars(self):
        return Scalars(self.value)


class Session:
    """A session that finds nothing (or `found`) and records what is added."""

    def __init__(self, found=None):
        self.found = found
        self.added = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def execute(self, *a, **k):
        return Result(self.found)

    def add(self, obj):
        self.added.append(obj)

    async def commit(self):
        pass

    async def rollback(self):
        pass

    async def close(self):
        pass


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def main():
    os.environ.setdefault("MYSQL_PASSWORD", "unused")
    os.environ.setdefault("MYSQL_ROOT_PASSWORD", "unused")
    os.environ.setdefault("JWT_SECRET", "startup-vectors-not-a-secret")

    from alembic.config import Config
    from alembic.script import ScriptDirectory

    cfg = Config(os.path.join("alembic", "alembic.ini"))
    cfg.set_main_option("script_location", "alembic")
    script = ScriptDirectory.from_config(cfg)
    heads = script.get_heads()
    assert len(heads) == 1, heads
    alembic = {"head": heads[0], "revisions": [r.revision for r in script.walk_revisions()]}

    from app.auth.models import users as users_models
    from app.auth.services import universal as auth_universal
    from app.customer_portal.services.settings import CustomerPortalSettings
    from app.data_store import data_store_setup
    from app.db import db_populate
    from app.notifications.services.template_seeds import BUILTIN_TEMPLATES
    from app.schedulers import scheduler as scheduler_module

    # Connectors: the arguments, then the rows.
    captured = []
    real_load = db_populate.load_connector_data
    db_populate.load_connector_data = lambda *a: captured.append(a) or a
    db_populate.get_connectors_list()
    db_populate.load_connector_data = real_load
    args_list = [list(a) + [None] * (5 - len(a)) for a in captured]
    env = connector_env(args_list)
    for key in env:
        os.environ.pop(key, None)
    rows_unset = [real_load(*a) for a in captured]
    saved = dict(os.environ)
    os.environ.update(env)
    rows_set = [real_load(*a) for a in captured]
    os.environ.clear()
    os.environ.update(saved)
    connectors = [{"args": args, "row_unset": u, "row_set": s} for args, u, s in zip(args_list, rows_unset, rows_set)]

    # Integrations and network connectors.
    placeholder = "No deployment instructions available."

    def catalog(items, name_key, desc_key, details_key, folder):
        out = []
        for item in items:
            name = item[name_key]
            stem = name.replace(" ", "_") if " " in name else name
            details = item[details_key]
            out.append(
                {
                    "name": name,
                    "description": item[desc_key],
                    "file": f"{stem.lower()}.md",
                    "found": details != placeholder,
                    "details_sha256": sha(details),
                    "details_len": len(details),
                },
            )
        return out

    integrations = catalog(
        db_populate.get_available_integrations_list(),
        "integration_name",
        "description",
        "integration_details",
        "integrations",
    )
    network = catalog(
        db_populate.get_available_network_connectors_list(),
        "network_connector_name",
        "description",
        "network_connector_details",
        "network_connectors",
    )

    async def keys():
        a = await db_populate.get_available_integrations_auth_keys_list(Session(found=1))
        b = await db_populate.get_available_network_connectors_auth_keys_list(Session(found=1))
        return [[k["integration_name"], k["auth_key_name"]] for k in a], [[k["network_connector_name"], k["auth_key_name"]] for k in b]

    integration_keys, network_keys = asyncio.run(keys())

    # Scheduler rows on an empty table.
    session = Session()
    scheduler_module.AsyncSession = lambda *a, **k: session
    asyncio.run(scheduler_module.initialize_job_metadata())
    jobs = [
        {
            "job_id": j.job_id,
            "time_interval": j.time_interval,
            "enabled": j.enabled,
            "job_description": j.job_description,
            "last_success": j.last_success,
        }
        for j in session.added
    ]

    # Buckets.
    buckets = []

    async def record_bucket(name):
        buckets.append(name)

    data_store_setup.create_bucket_if_not_exists = record_bucket
    asyncio.run(data_store_setup.create_buckets())

    # Users.
    lengths = []
    real_generate = users_models.Password.generate

    def generate(length=12):
        lengths.append(length)
        return real_generate(length=length)

    users = {}
    for kind, fn in (("admin", auth_universal.create_admin_user), ("scheduler", auth_universal.create_scheduler_user)):
        lengths.clear()
        users_models.Password.generate = staticmethod(generate)
        auth_universal.Password.generate = staticmethod(generate)
        s = Session()
        asyncio.run(fn(s))
        user = s.added[0]
        users[kind] = {"username": user.username, "email": user.email, "role_id": user.role_id, "password_length": lengths[0]}
    users_models.Password.generate = real_generate

    import string

    vectors = {
        "connectors": connectors,
        "connector_env": env,
        "deleted_connectors": db_populate.delete_connectors_list(),
        "roles": [list(r) for r in db_populate.ROLES],
        "integrations": integrations,
        "integration_auth_keys": integration_keys,
        "network_connectors": network,
        "network_connector_auth_keys": network_keys,
        "placeholder": placeholder,
        "templates": BUILTIN_TEMPLATES,
        "portal_defaults": CustomerPortalSettings.get_default_values(),
        "jobs": jobs,
        "buckets": buckets,
        "users": users,
        "password_classes": [string.ascii_lowercase, string.ascii_uppercase, string.digits, "@$!%*?&#"],
    }
    with open(os.path.join(ROOT, "crates/copilot-migrate/src/alembic_revisions.json"), "w") as f:
        json.dump(alembic, f, indent=1, ensure_ascii=False)
        f.write("\n")
    with open(os.path.join(ROOT, "crates/copilot-startup/src/startup_vectors.json"), "w") as f:
        json.dump(vectors, f, indent=1, ensure_ascii=False)
        f.write("\n")
    print(f"{len(alembic['revisions'])} revisions (head {alembic['head']}); {len(connectors)} connectors, {len(jobs)} jobs")


if __name__ == "__main__":
    main()

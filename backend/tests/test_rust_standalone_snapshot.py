"""The Python app the Rust service answers for, as `copilot-standalone` compiles it in.

`crates/copilot-standalone/src/python/app.json` (the routes in Starlette's order, their methods,
the documentation pages) and `openapi.json` (`GET /openapi.json`'s body) are written by
`scripts/gen-standalone-vectors.py`. This test builds both again from the app and fails when a
route, a schema or a FastAPI upgrade changed them: re-run the script then.

The methods of a route are a `set`, iterated in an order that varies between Python processes
for the four documentation routes (`GET`, `HEAD`), so they are compared sorted.
"""

import importlib.util
import json
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = REPO / "scripts" / "gen-standalone-vectors.py"
COMPILED = REPO / "crates" / "copilot-standalone" / "src" / "python"


def _generator():
    spec = importlib.util.spec_from_file_location("gen_standalone_vectors", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sorted_methods(data):
    for route in data["routes"]:
        if route["methods"] is not None:
            route["methods"] = sorted(route["methods"])
    return data


def test_app_json_is_the_apps():
    gen = _generator()
    app = gen.load_app()
    current = _sorted_methods(json.loads(json.dumps(gen.app_json(app))))
    compiled = _sorted_methods(json.loads((COMPILED / "app.json").read_text(encoding="utf-8")))
    assert current == compiled, "re-run scripts/gen-standalone-vectors.py"


def test_openapi_json_is_the_apps():
    gen = _generator()
    app = gen.load_app()
    current = gen.openapi_body(app)
    compiled = (COMPILED / "openapi.json").read_text(encoding="utf-8")
    assert current == compiled, "re-run scripts/gen-standalone-vectors.py"

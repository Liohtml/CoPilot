"""Regenerate the vectors that pin the CoPilot MCP port (`copilot-mcp`) to the Python module it
ports (`app/integrations/copilot_mcp/`).

    cd backend && PYTHONPATH=. MYSQL_URL=x MYSQL_USER=x MYSQL_PASSWORD=x \\
        MYSQL_ROOT_PASSWORD=x JWT_SECRET=x python ../scripts/gen-copilot-mcp-vectors.py

Writes `crates/copilot-mcp/src/mcp_vectors.json`:

* `servers`, `questions`, `categories` — `ExampleQuestionsService`'s tables, as the routes dump
  them;
* `services` — `MCPService`'s routing: each server's deployment (local or cloud), endpoint and
  full URL;
* `requests` — `MCPQueryRequest` on request bodies: the dump, Pydantic's errors (`type`, `loc`,
  `msg`) or the `HTTPException` its validator raises;
* `answers` — `MCPQueryResponse(**answer)` on what a server may answer: the dump or the
  exception (class and `str()`).

Re-run after a change to the module or a Pydantic upgrade.
"""

import json
import pathlib

from fastapi import HTTPException
from pydantic import ValidationError

from app.integrations.copilot_mcp.schema.copilot_mcp import MCPQueryRequest
from app.integrations.copilot_mcp.schema.copilot_mcp import MCPQueryResponse
from app.integrations.copilot_mcp.schema.copilot_mcp import MCPServerType
from app.integrations.copilot_mcp.services.copilot_mcp import MCPService
from app.integrations.copilot_mcp.services.example_questions import (
    ExampleQuestionsService,
)

OUT = pathlib.Path(__file__).resolve().parent.parent / "crates" / "copilot-mcp" / "src" / "mcp_vectors.json"

REQUESTS = [
    {"input": "hello", "mcp_server": "copilot"},
    {"input": "hello", "mcp_server": "cyber-news", "verbose": False},
    {"input": "hello", "mcp_server": "wazuh-indexer", "verbose": None},
    {"input": "hello", "mcp_server": "velociraptor", "verbose": "yes"},
    {"input": "hello", "mcp_server": "knowledgebase", "verbose": 0},
    {"input": "hello", "mcp_server": "attack-surface", "verbose": "maybe"},
    {"input": "hello", "mcp_server": "threat-intel", "verbose": 2},
    {"input": "hello", "mcp_server": "nope"},
    {"input": "hello", "mcp_server": "Copilot"},
    {"input": "hello", "mcp_server": ""},
    {"mcp_server": "nope"},
    {"input": 5, "mcp_server": "nope"},
    {"input": "hello", "mcp_server": 5},
    {"input": "hello", "mcp_server": None},
    {"input": "hello", "mcp_server": ["copilot"]},
    {"input": "hello"},
    {"mcp_server": "copilot"},
    {"input": 5, "mcp_server": "copilot", "verbose": "x"},
    {"input": None, "mcp_server": 7},
    {},
    {"input": "x", "mcp_server": "copilot", "extra": 1},
]

ANSWERS = [
    {"message": "ok", "success": True},
    {
        "message": "ok",
        "success": True,
        "result": {"a": [1, 2.5]},
        "structured_result": {"response": "md", "thinking_process": None},
        "execution_time": 1,
    },
    {"message": "ok", "success": "true", "execution_time": "2.5", "extra": "dropped"},
    {"message": "ok", "success": True, "structured_result": {"thinking_process": "t"}},
    {"message": 5, "success": None},
    {"success": True},
    {"message": "ok", "success": True, "structured_result": "text"},
    {"message": "ok", "success": True, "execution_time": "fast"},
    [1, 2],
    "text",
    None,
    7,
]


def request_outcome(body):
    try:
        return {"ok": MCPQueryRequest.model_validate(body).model_dump(mode="json")}
    except HTTPException as e:
        return {"http": [e.status_code, e.detail]}
    except ValidationError as e:
        return {"errors": [{"type": x["type"], "loc": list(x["loc"]), "msg": x["msg"]} for x in e.errors()]}


def answer_outcome(answer):
    try:
        return {"ok": MCPQueryResponse(**answer).model_dump(mode="json")}
    except Exception as e:  # noqa: BLE001 - the exception is the vector
        return {"error": {"class": type(e).__name__, "text": str(e)}}


def main():
    out = {
        "servers": [s.model_dump() for s in ExampleQuestionsService.get_available_servers()],
        "questions": {s.value: [q.model_dump() for q in ExampleQuestionsService.get_example_questions(s)] for s in MCPServerType},
        "categories": {s.value: ExampleQuestionsService.get_available_categories(s) for s in MCPServerType},
        "services": {
            s.value: {
                "cloud": MCPService.is_cloud_service(s),
                "endpoint": MCPService.get_server_config(s).endpoint,
                "url": MCPService.build_full_url(s),
            }
            for s in MCPServerType
        },
        "requests": [{"body": b, "outcome": request_outcome(b)} for b in REQUESTS],
        "answers": [{"answer": a, "outcome": answer_outcome(a)} for a in ANSWERS],
    }
    OUT.write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()

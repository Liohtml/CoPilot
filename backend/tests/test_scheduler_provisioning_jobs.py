"""The scheduler's `/provisioning_jobs` hook, through which the Rust service registers the jobs of the
integrations' `/provision` routes it answers (no DB, no scheduler)."""

import ast
import asyncio
import pathlib

import pytest
from fastapi import HTTPException

from app.schedulers.models.scheduler import CreateSchedulerRequest
from app.schedulers.routes import scheduler as routes

INTEGRATIONS = pathlib.Path(__file__).resolve().parent.parent / "app" / "integrations"
MODULES = ["huntress", "darktrace", "duo", "cato", "carbonblack", "mimecast", "sap_siem"]


def provision_route_jobs(module):
    tree = ast.parse((INTEGRATIONS / module / "routes" / "provision.py").read_text())
    route = next(
        f
        for f in tree.body
        if isinstance(f, ast.AsyncFunctionDef)
        and any(isinstance(d, ast.Call) and d.args and getattr(d.args[0], "value", None) == "/provision" for d in f.decorator_list)
    )
    return {
        kw.value.value
        for node in ast.walk(route)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) == "CreateSchedulerRequest"
        for kw in node.keywords
        if kw.arg == "job_id"
    }


def test_the_allowlist_is_the_provision_routes_jobs():
    jobs = set().union(*(provision_route_jobs(m) for m in MODULES))
    assert routes.PROVISIONING_JOBS == jobs


def test_jobs_are_added_in_order(monkeypatch):
    added = []

    async def fake_add(request):
        added.append((request.job_id, request.time_interval))

    monkeypatch.setattr(routes, "add_scheduler_jobs", fake_add)
    request = routes.ProvisioningJobsRequest(
        jobs=[
            CreateSchedulerRequest(function_name=j, job_id=j, time_interval=i)
            for j, i in (("invoke_mimecast_integration_ttp", 15), ("invoke_mimecast_integration", 5))
        ],
    )
    answer = asyncio.run(routes.add_provisioning_jobs(request))
    assert answer == {"success": True, "message": "Jobs added successfully"}
    assert added == [("invoke_mimecast_integration_ttp", 15), ("invoke_mimecast_integration", 5)]


@pytest.mark.parametrize(
    "function_name,job_id",
    [("agent_sync", "agent_sync"), ("invoke_duo_integration_collect", "invoke_huntress_integration_collect")],
)
def test_other_jobs_are_refused_before_any_is_added(monkeypatch, function_name, job_id):
    added = []

    async def fake_add(request):
        added.append(request.job_id)

    monkeypatch.setattr(routes, "add_scheduler_jobs", fake_add)
    request = routes.ProvisioningJobsRequest(
        jobs=[
            CreateSchedulerRequest(
                function_name="invoke_duo_integration_collect",
                job_id="invoke_duo_integration_collect",
                time_interval=1,
            ),
            CreateSchedulerRequest(function_name=function_name, job_id=job_id, time_interval=1),
        ],
    )
    with pytest.raises(HTTPException) as e:
        asyncio.run(routes.add_provisioning_jobs(request))
    assert e.value.status_code == 400
    assert added == []

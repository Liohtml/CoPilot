import asyncio
from typing import List
from typing import Literal
from typing import Optional

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Security
from loguru import logger
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from app.auth.utils import AuthHandler
from app.db.db_session import get_db
from app.middleware.search_query import SearchParams
from app.middleware.search_query import filter_and_limit
from app.middleware.search_query import search_query
from app.schedulers.handover import manual_run
from app.schedulers.models.scheduler import CreateSchedulerRequest
from app.schedulers.models.scheduler import JobMetadata
from app.schedulers.scheduler import add_scheduler_jobs
from app.schedulers.scheduler import get_function_by_name
from app.schedulers.scheduler import get_scheduler_instance
from app.schedulers.scheduler import init_scheduler
from app.schedulers.schema.scheduler import JobDetailResponse
from app.schedulers.schema.scheduler import JobsNextRunResponse
from app.schedulers.schema.scheduler import JobsResponse

scheduler_router = APIRouter(
    dependencies=[Security(AuthHandler().require_any_scope("admin", "analyst"))],
)


async def get_scheduler():
    # Singleton pattern or reference to existing instance
    return await init_scheduler()


async def find_job_by_id(scheduler, job_id):
    """
    Find a job in the scheduler by its ID.

    Args:
        scheduler (Scheduler): The scheduler object.
        job_id (str): The ID of the job to find.

    Returns:
        Job: The job object if found, None otherwise.
    """
    for job in scheduler.get_jobs():
        if job.id == job_id:
            return job
    return None


async def manage_job_metadata(session, job_id, action, **kwargs):
    """
    Manage job metadata based on the specified action.

    Args:
        session (Session): The database session.
        job_id (int): The ID of the job.
        action (str): The action to perform on the job metadata. Possible values are "update" and "delete".
        **kwargs: Additional keyword arguments representing the fields to update and their new values.

    Returns:
        JobMetadata: The updated or deleted job metadata.
    """
    if action == "add":
        job_metadata = JobMetadata(
            job_id=job_id,
            last_success=None,
            time_interval=kwargs["time_interval"],
            enabled=True,
            extra_data=kwargs["extra_data"],
        )
        session.add(job_metadata)
        await session.commit()
        return job_metadata

    job_metadata = await session.execute(select(JobMetadata).filter_by(job_id=job_id))
    job_metadata = job_metadata.scalars().first()

    if action == "update":
        for key, value in kwargs.items():
            setattr(job_metadata, key, value)
        await session.commit()
    elif action == "delete":
        await session.delete(job_metadata)
        await session.commit()

    return job_metadata


def build_job_payload(job, job_metadata: JobMetadata | None) -> dict:
    return {
        "id": job.id,
        "name": job.name,
        "time_interval": job_metadata.time_interval if job_metadata else 0,
        "enabled": job_metadata.enabled if job_metadata else job.next_run_time is not None,
        "description": job_metadata.job_description if job_metadata else None,
        "last_success": job_metadata.last_success if job_metadata else None,
    }


async def get_job_payload(job_id: str, session: AsyncSession) -> dict:
    scheduler = await get_scheduler_instance()
    job = await find_job_by_id(scheduler, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    job_metadata = await session.execute(select(JobMetadata).filter_by(job_id=job_id))
    job_metadata = job_metadata.scalars().first()
    return build_job_payload(job, job_metadata)


@scheduler_router.get("", response_model=JobsResponse, description="Get all jobs")
async def get_all_jobs(
    search_params: SearchParams = Depends(search_query),
    session: AsyncSession = Depends(get_db),
) -> JobsResponse:
    """
    Retrieve jobs from the scheduler.

    ``search``/``limit`` (see ``search_query``) narrow the (small, in-memory) job set
    to those whose id or name contains the string and cap the count — used by the
    global search palette so the client never pulls the whole job list to filter it.

    Args:
        session (AsyncSession): The database session.

    Returns:
        JobsResponse: The response containing the list of jobs.

    """
    scheduler = await get_scheduler_instance()
    jobs = filter_and_limit(scheduler.get_jobs(), search_params, key=lambda job: f"{job.id or ''} {job.name or ''}")
    apscheduler_jobs = []
    for job in jobs:
        job_metadata = await session.execute(
            select(JobMetadata).filter_by(job_id=job.id),
        )
        job_metadata = job_metadata.scalars().first()
        logger.info(f"job_metadata: {job_metadata}")
        apscheduler_jobs.append(build_job_payload(job, job_metadata))
    logger.info(f"apscheduler_jobs: {apscheduler_jobs}")
    return JobsResponse(
        jobs=apscheduler_jobs,
        success=True,
        message="Jobs successfully retrieved.",
    )


@scheduler_router.get("/{job_id}", response_model=JobDetailResponse, description="Get a single job by id")
async def get_job(job_id: str, session: AsyncSession = Depends(get_db)) -> JobDetailResponse:
    job = await get_job_payload(job_id, session)
    return JobDetailResponse(
        job=job,
        success=True,
        message="Job successfully retrieved.",
    )


@scheduler_router.get("/next_run/{job_id}", response_model=JobsNextRunResponse, description="Get the next run time of a job")
async def get_next_run(job_id: str) -> JobsNextRunResponse:
    """
    Get the next run time of a job.

    Args:
        job_id (str): The ID of the job.

    Returns:
        dict: A dictionary containing the next run time of the job.
    """
    scheduler = await get_scheduler_instance()
    job = await find_job_by_id(scheduler, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")
    next_run_time = job.next_run_time
    logger.info(f"Next run time for job {job_id}: {next_run_time}")
    return JobsNextRunResponse(
        next_run_time=next_run_time,
        success=True,
        message="Next run time successfully retrieved.",
    )


@scheduler_router.post("/add", description="Add a job")
async def add_job(
    job_id: str,
    function_name: str,
    time_interval: int,
    extra_data: Optional[str] = None,
    session: AsyncSession = Depends(get_db),
):
    """
    Add a job to the scheduler.

    Args:
        job_id (str): The ID of the job.
        function_name (str): The name of the function to be scheduled.
        time_interval (int): The time interval for the job in minutes.
        extra_data (str, optional): Additional data to be stored with the job metadata. Defaults to None.
        session (AsyncSession, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A dictionary containing the success status and a message.
    """
    scheduler = await get_scheduler_instance()
    job_function = get_function_by_name(function_name)
    scheduler.add_job(
        job_function,
        "interval",
        minutes=time_interval,
        id=job_id,
        replace_existing=True,
    )
    await manage_job_metadata(
        session,
        job_id,
        "add",
        time_interval=time_interval,
        extra_data=extra_data,
    )
    if not scheduler.running:
        scheduler.start()
    logger.info(f"Job {job_id} added successfully")
    return {"success": True, "message": "Job added successfully"}


# The jobs the integrations' `/provision` routes register. Those routes are answered by the Rust
# service (copilot-integration-provisioning), which cannot reach APScheduler: it hands this one step
# back here, after its provisioning, with the caller's token.
PROVISIONING_JOBS = frozenset(
    {
        "invoke_huntress_integration_collect",
        "invoke_darktrace_integration_collect",
        "invoke_duo_integration_collect",
        "invoke_cato_integration_collect",
        "invoke_carbonblack_integration_collection",
        "invoke_mimecast_integration_ttp",
        "invoke_mimecast_integration",
        "invoke_sap_siem_integration_collection",
        "invoke_sap_siem_integration_suspicious_logins_analysis",
        "invoke_sap_siem_integration_multiple_logins_same_ip_analysis",
    },
)


class ProvisioningJobsRequest(BaseModel):
    jobs: List[CreateSchedulerRequest]


@scheduler_router.post("/provisioning_jobs", include_in_schema=False, description="Register an integration's jobs")
async def add_provisioning_jobs(request: ProvisioningJobsRequest):
    """
    `add_scheduler_jobs` for each job, in order, as the integrations' `/provision` routes call it.
    Only those routes' jobs, each under its own function name.
    """
    for job in request.jobs:
        if job.job_id not in PROVISIONING_JOBS or job.function_name != job.job_id:
            raise HTTPException(status_code=400, detail=f"Job {job.job_id} is not an integration provisioning job")
    for job in request.jobs:
        await add_scheduler_jobs(job)
    return {"success": True, "message": "Jobs added successfully"}


class ApschedulerOp(BaseModel):
    op: Literal["add", "reschedule", "remove", "pause", "resume"]
    job_id: str
    function_name: Optional[str] = None
    time_interval: Optional[int] = None
    # `add` as POST /add calls it (APScheduler's job defaults) rather than as `add_scheduler_jobs`.
    defaults: bool = False


class ApschedulerOpsRequest(BaseModel):
    ops: List[ApschedulerOp]


@scheduler_router.post("/apscheduler_ops", include_in_schema=False, description="APScheduler's part of a Scheduler write")
async def apscheduler_ops(request: ApschedulerOpsRequest):
    """
    The APScheduler operations of the Scheduler's write routes, each exactly as the route calls it.

    The Rust service answers those routes (and the integrations' provisioning) and does their
    `scheduled_job_metadata` work itself; while APScheduler owns the schedule it hands this part
    here, in the route's order, with the caller's token. `found` is `find_job_by_id`'s answer for
    every operation but `add` (always true).
    """
    scheduler = await get_scheduler_instance()
    found = []
    for op in request.ops:
        if op.op == "add":
            job_function = get_function_by_name(op.function_name)
            options = {} if op.defaults else {"coalesce": True, "max_instances": 1}
            scheduler.add_job(job_function, "interval", minutes=op.time_interval, id=op.job_id, replace_existing=True, **options)
            if not scheduler.running:
                scheduler.start()
            found.append(True)
            continue
        job = await find_job_by_id(scheduler, op.job_id)
        if job is None:
            found.append(False)
            continue
        if op.op == "reschedule":
            job.reschedule(trigger="interval", minutes=op.time_interval)
        elif op.op == "remove":
            scheduler.remove_job(op.job_id)
        elif op.op == "pause":
            job.pause()
        else:
            job.resume()
        found.append(True)
    return {"success": True, "found": found}


@scheduler_router.post("/jobs/run/{job_id}", description="Run a job")
async def run_job_manually(job_id: str, session: AsyncSession = Depends(get_db)):
    """
    Manually triggers a scheduled job for immediate execution.

    Args:
        job_id (str): The identifier of the job to run.
        session (AsyncSession): The database session dependency.

    Returns:
        A JSON response with the result of the operation.
    """
    scheduler = await get_scheduler_instance()  # Make sure your scheduler is properly initialized
    job = scheduler.get_job(job_id)

    if job is None:
        raise HTTPException(status_code=404, detail="Job not found")

    try:
        # Retrieve the function associated with the job and run it
        job_function = get_function_by_name(job.name)  # Ensure this function maps job names to function objects
        logger.info(f"Running job {job_id} manually")
        # A manual run: a job guarded for the hand-over to the Rust service waits for a run in
        # progress instead of skipping (handover.py).
        with manual_run():
            if asyncio.iscoroutinefunction(job_function):
                logger.info(f"Running async job {job_id}")
                result = await job_function()  # Execute the function if it's async
            else:
                logger.info(f"Running sync job {job_id}")
                result = job_function()  # Execute synchronously if not an async function

        return {"success": True, "message": "Job executed successfully", "result": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@scheduler_router.post("/start/{job_id}", description="Start a job")
async def start_job(job_id: str):
    """
    Start a job by resuming its execution.

    Args:
        job_id (str): The ID of the job to start.

    Returns:
        dict: A dictionary containing the success status and a message.
            - If the job is found and successfully started, the success status is True and the message is "Job started successfully".
            - If the job is not found, the success status is False and the message is "Job not found".
    """
    scheduler = await get_scheduler_instance()
    job = await find_job_by_id(scheduler, job_id)
    if job:
        job.resume()
        logger.info(f"Job {job_id} started successfully")
        return {"success": True, "message": "Job started successfully"}
    logger.error(f"Job {job_id} not found for starting")
    return {"success": False, "message": "Job not found"}


@scheduler_router.post("/pause/{job_id}", description="Pause a job")
async def pause_job(job_id: str):
    """
    Pause a job.

    Args:
        job_id (str): The ID of the job to be paused.

    Returns:
        dict: A dictionary containing the success status and a message.
            - If the job is paused successfully, the success status is True and the message is "Job paused successfully".
            - If the job is not found, the success status is False and the message is "Job not found".
    """
    scheduler = await get_scheduler_instance()
    job = await find_job_by_id(scheduler, job_id)
    if job:
        job.pause()
        logger.info(f"Job {job_id} paused successfully")
        return {"success": True, "message": "Job paused successfully"}
    logger.error(f"Job {job_id} not found for pausing")
    return {"success": False, "message": "Job not found"}


@scheduler_router.put("/update/{job_id}", description="Update a job")
async def update_job(
    job_id: str,
    time_interval: int,
    extra_data: Optional[str] = None,
    session: AsyncSession = Depends(get_db),
):
    """
    Update a job with the specified job_id and time_interval.

    Parameters:
    - job_id (str): The ID of the job to be updated.
    - time_interval (int): The new time interval for the job in minutes.
    - session (AsyncSession, optional): The database session. Defaults to Depends(get_db).

    Returns:
    - dict: A dictionary containing the success status and a message.

    Example:
    {
        "success": True,
        "message": "Job updated successfully"
    }
    """
    scheduler = await get_scheduler_instance()
    job = await find_job_by_id(scheduler, job_id)
    if job:
        job.reschedule(trigger="interval", minutes=time_interval)
        await manage_job_metadata(
            session,
            job_id,
            "update",
            time_interval=time_interval,
            extra_data=extra_data,
        )
        logger.info(f"Job {job_id} updated successfully")
        # Update the job metadata
        await manage_job_metadata(
            session,
            job_id,
            "update",
            time_interval=time_interval,
            extra_data=extra_data,
        )

        return {"success": True, "message": "Job updated successfully"}
    logger.error(f"Job {job_id} not found for updating")
    return {"success": False, "message": "Job not found"}


@scheduler_router.delete("/{job_id}", description="Delete a job")
async def delete_job(job_id: str, session: AsyncSession = Depends(get_db)):
    """
    Delete a job.

    Args:
        job_id (str): The ID of the job to be deleted.
        session (AsyncSession, optional): The database session. Defaults to Depends(get_db).

    Returns:
        dict: A dictionary containing the success status and a message.
    """
    scheduler = await get_scheduler_instance()
    job = await find_job_by_id(scheduler, job_id)
    if job:
        scheduler.remove_job(job_id)
        await manage_job_metadata(session, job_id, "delete")
        logger.info(f"Job {job_id} deleted successfully")
        return {"success": True, "message": "Job deleted successfully"}
    logger.error(f"Job {job_id} not found for deletion")
    return {"success": False, "message": "Job not found"}

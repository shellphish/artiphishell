from uuid import UUID

from fastapi import APIRouter, Depends
from structlog.stdlib import get_logger

from competition_api.db import db_session
from competition_api.endpoints.lib.auth import get_token_id
from competition_api.models import GPResponse, GPStatusResponse, GPSubmission
from competition_api.models.types import UUIDPathParameter

from .gp import get_gp_status, process_gp_upload

router = APIRouter()

LOGGER = get_logger(__name__)


@router.post("/submission/gp/", tags=["submission"])
async def upload_gp(
    gp: GPSubmission,
    team_id: UUID = Depends(get_token_id),
) -> GPResponse:
    async with db_session() as db:
        return await process_gp_upload(gp, db, team_id)


@router.get("/submission/gp/{gp_uuid}", tags=["submission"])
async def check_gp(
    gp_uuid: UUIDPathParameter,
    team_id: UUID = Depends(get_token_id),
) -> GPStatusResponse:
    async with db_session() as db:
        return await get_gp_status(gp_uuid, db, team_id)

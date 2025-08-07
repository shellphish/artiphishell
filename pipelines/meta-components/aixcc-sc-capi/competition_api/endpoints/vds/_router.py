from uuid import UUID

from fastapi import APIRouter, Depends
from structlog.stdlib import get_logger

from competition_api.db import db_session
from competition_api.endpoints.lib.auth import get_token_id
from competition_api.models.types import UUIDPathParameter
from competition_api.models.vds import VDSResponse, VDSStatusResponse, VDSubmission

from .vds import get_vd_status, process_vd_upload

router = APIRouter()

LOGGER = get_logger(__name__)


@router.post("/submission/vds/", tags=["submission"])
async def upload_vd(
    vds: VDSubmission,
    team_id: UUID = Depends(get_token_id),
) -> VDSResponse:
    async with db_session() as db:
        return await process_vd_upload(vds, db, team_id)


@router.get("/submission/vds/{vd_uuid}", tags=["submission"])
async def check_vd(
    vd_uuid: UUIDPathParameter,
    team_id: UUID = Depends(get_token_id),
) -> VDSStatusResponse:
    async with db_session() as db:
        return await get_vd_status(vd_uuid, db, team_id)

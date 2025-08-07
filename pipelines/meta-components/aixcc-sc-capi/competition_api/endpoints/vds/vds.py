import asyncio
import uuid

from fastapi import HTTPException, status
from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncConnection
from structlog.contextvars import bind_contextvars, clear_contextvars
from structlog.stdlib import get_logger
from vyper import v

from competition_api.audit import get_auditor
from competition_api.audit.types import EventType, VDSubmissionInvalidReason
from competition_api.cp_registry import CPRegistry
from competition_api.db import VulnerabilityDiscovery
from competition_api.flatfile import Flatfile
from competition_api.models.types import FeedbackStatus, UUIDPathParameter
from competition_api.models.vds import VDSResponse, VDSStatusResponse, VDSubmission
from competition_api.tasks import TaskRunner

LOGGER = get_logger(__name__)


async def process_vd_upload(
    vds: VDSubmission,
    db: AsyncConnection,
    team_id: uuid.UUID,
) -> VDSResponse:
    clear_contextvars()
    auditor = get_auditor(team_id)

    bind_contextvars(team_id=str(team_id), cp_name=vds.cp_name, endpoint="VDS upload")
    auditor.push_context(cp_name=vds.cp_name)

    if v.get_bool("mock_mode"):
        await auditor.emit(EventType.MOCK_RESPONSE)
        return VDSResponse(
            status=FeedbackStatus.ACCEPTED,
            cp_name=f"{vds.cp_name}",
            vd_uuid=uuid.uuid4(),
        )

    blob = Flatfile(contents=vds.pov.data)
    await blob.write()
    bind_contextvars(vds_blob_size=len(vds.pov.data), vds_blob_sha256=blob.sha256)

    row = {
        "team_id": team_id,
        "cp_name": vds.cp_name,
        "pou_commit_sha1": vds.pou.commit_sha1,
        "pou_sanitizer": vds.pou.sanitizer,
        "pov_harness": vds.pov.harness,
        "pov_data_sha256": blob.sha256,
    }

    db_row = (
        await db.execute(
            insert(VulnerabilityDiscovery)
            .values(**row)
            .returning(VulnerabilityDiscovery)
        )
    ).fetchone()
    await db.commit()

    if db_row is None:
        raise RuntimeError(
            "No value returned on VulnerabilityDiscovery database insert"
        )
    db_row = db_row[0]

    for update_context in [bind_contextvars, auditor.push_context]:
        update_context(vd_uuid=str(db_row.id))

    if not CPRegistry.instance().has(vds.cp_name):
        await auditor.emit(
            EventType.VD_SUBMISSION_INVALID,
            reason=VDSubmissionInvalidReason.CP_NOT_IN_CP_ROOT_FOLDER,
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="CP not found",
            headers={"WWW-Authenticate": "Basic"},
        )

    await auditor.emit(
        EventType.VD_SUBMISSION,
        harness=db_row.pov_harness,
        pov_blob_sha256=blob.sha256,
        pou_commit=db_row.pou_commit_sha1.lower(),
        sanitizer=db_row.pou_sanitizer,
    )

    asyncio.create_task(TaskRunner(vds.cp_name, auditor).test_vds(db_row))

    return VDSResponse(
        status=db_row.status,
        cp_name=db_row.cp_name,
        vd_uuid=db_row.id,
    )


async def get_vd_status(
    vd_uuid: UUIDPathParameter,
    db: AsyncConnection,
    team_id: uuid.UUID,
) -> VDSStatusResponse:
    if v.get_bool("mock_mode"):
        return VDSStatusResponse(
            status=FeedbackStatus.ACCEPTED,
            vd_uuid=vd_uuid,
            cpv_uuid=uuid.uuid4(),
        )

    result = (
        await db.execute(
            select(
                VulnerabilityDiscovery.status,
                VulnerabilityDiscovery.cpv_uuid,
                VulnerabilityDiscovery.team_id,
            ).where(VulnerabilityDiscovery.id == vd_uuid)
        )
    ).fetchone()

    if result is None or result.team_id != team_id:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="vd_uuid not found",
            headers={"WWW-Authenticate": "Basic"},
        )

    return VDSStatusResponse(
        status=result.status, vd_uuid=vd_uuid, cpv_uuid=result.cpv_uuid
    )

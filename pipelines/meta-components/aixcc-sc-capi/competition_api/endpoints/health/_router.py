from fastapi import APIRouter

from competition_api.models import HealthResponse

router = APIRouter()


@router.get("/health/", tags=["health"])
@router.get("/", tags=["health"])
async def default_healthcheck() -> HealthResponse:
    return HealthResponse(status="ok")

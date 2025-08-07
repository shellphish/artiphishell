from pydantic import BaseModel


class HealthResponse(BaseModel):
    status: str

    model_config = {"json_schema_extra": {"examples": [{"status": "ok"}]}}

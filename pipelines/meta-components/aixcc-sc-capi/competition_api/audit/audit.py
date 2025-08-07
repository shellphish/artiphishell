from typing import Any
from uuid import UUID

from aiofile import async_open
from structlog.stdlib import get_logger
from vyper import v

from .models import (
    EventWrapper,
    GPFunctionalTestsPass,
    GPPatchBuiltEvent,
    GPSanitizerDidNotFire,
    GPSubmissionDuplicateCPVEvent,
    GPSubmissionEvent,
    GPSubmissionFailEvent,
    GPSubmissionInvalidEvent,
    GPSubmissionSuccessEvent,
    MockResponseEvent,
    VDSanitizerResultEvent,
    VDSubmissionEvent,
    VDSubmissionFailEvent,
    VDSubmissionInvalidEvent,
    VDSubmissionSuccessEvent,
)
from .types import EventType

LOGGER = get_logger(__name__)

v.set_default("audit.file", "/var/log/capi/audit.log")


EVENTS = {
    EventType.DUPLICATE_GP_SUBMISSION_FOR_CPV_UUID: GPSubmissionDuplicateCPVEvent,
    EventType.GP_FUNCTIONAL_TESTS_PASS: GPFunctionalTestsPass,
    EventType.GP_PATCH_BUILT: GPPatchBuiltEvent,
    EventType.GP_SANITIZER_DID_NOT_FIRE: GPSanitizerDidNotFire,
    EventType.GP_SUBMISSION: GPSubmissionEvent,
    EventType.GP_SUBMISSION_FAIL: GPSubmissionFailEvent,
    EventType.GP_SUBMISSION_INVALID: GPSubmissionInvalidEvent,
    EventType.GP_SUBMISSION_SUCCESS: GPSubmissionSuccessEvent,
    EventType.MOCK_RESPONSE: MockResponseEvent,
    EventType.VD_SANITIZER_RESULT: VDSanitizerResultEvent,
    EventType.VD_SUBMISSION: VDSubmissionEvent,
    EventType.VD_SUBMISSION_FAIL: VDSubmissionFailEvent,
    EventType.VD_SUBMISSION_INVALID: VDSubmissionInvalidEvent,
    EventType.VD_SUBMISSION_SUCCESS: VDSubmissionSuccessEvent,
}


class Auditor:
    def __init__(self, team_id: UUID):
        self._context: dict[str, Any] = {}
        self._team_id = team_id
        self._outfile = v.get("audit.file")

    async def _emit_event(self, event: Any):
        async with async_open(self._outfile, "a", encoding="utf8") as auditfile:
            event_str = event.model_dump_json()
            await LOGGER.adebug("Audit event: %s", event_str)
            await auditfile.write(f"{event_str}\n")

    def push_context(self, **kwargs):
        self._context = self._context | kwargs

    def pop_context(self, key: str):
        self._context.pop(key)

    async def emit(self, event_type: EventType, **kwargs):
        wrapped = EventWrapper(
            team_id=self._team_id,
            event_type=event_type,
            event=EVENTS[event_type](**self._context, **kwargs),
        )
        await self._emit_event(wrapped)


def get_auditor(*args, **kwargs):
    return Auditor(*args, **kwargs)

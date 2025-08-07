from typing import Any

from competition_api.audit import Auditor
from competition_api.audit.models import EventWrapper
from competition_api.audit.types import EventType


class RecordingAuditor(Auditor):
    def __init__(self, *args, **kwargs):
        self.events: list[EventWrapper] = []
        super().__init__(*args, **kwargs)

    async def _emit_event(self, event: EventWrapper):
        self.events.append(event)

    def get_events(self, event_type: EventType) -> list[Any]:
        return [event.event for event in self.events if event.event_type == event_type]

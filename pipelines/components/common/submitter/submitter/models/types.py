from enum import Enum, unique
from typing import Annotated

from fastapi import Path
from pydantic import UUID4

UUIDPathParameter = Annotated[
    UUID4, Path(description="Example: 744a8ead-9ebc-40cd-9f96-8edf187868fa")
]


@unique
class FeedbackStatus(Enum):
    ACCEPTED = "accepted"
    NOT_ACCEPTED = "rejected"
    PENDING = "pending"

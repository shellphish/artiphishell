import secrets
from typing import Any
from uuid import UUID, uuid4

import argon2
from sqlalchemy import String, Uuid, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncConnection
from sqlalchemy.orm import Mapped, mapped_column
from structlog.stdlib import get_logger

from competition_api.db.common import Base

GENERATED_TOKEN_LEN = 32
HASHER = argon2.PasswordHasher()
LOGGER = get_logger(__name__)


class Token(Base):
    __tablename__ = "token"

    id: Mapped[UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid4
    )  # pylint: disable=redefined-builtin
    token: Mapped[str] = mapped_column("token", String, nullable=True)

    @classmethod
    async def upsert(
        cls, db: AsyncConnection, token_id: UUID | None = None, token: str | None = None
    ) -> tuple[UUID, str]:
        token = (
            token if token is not None else secrets.token_urlsafe(GENERATED_TOKEN_LEN)
        )
        values: dict[str, Any] = {"token": HASHER.hash(token)}

        if token_id:
            values["id"] = token_id

        db_token_id = (
            await db.execute(
                insert(cls)  # type: ignore
                .values(**values)
                .returning(cls.id)
                .on_conflict_do_update(index_elements=[cls.id], set_=values)
            )
        ).fetchone()

        if db_token_id is None:
            raise RuntimeError("No value returned on Token database insert")

        return db_token_id.id, token

    @classmethod
    async def verify(cls, db: AsyncConnection, token_id: UUID, token: str) -> bool:
        await LOGGER.adebug("Verifying token for %s", token_id)

        result = (
            await db.execute(select(cls.token).where(cls.id == token_id))
        ).fetchall()

        if len(result) == 0:
            await LOGGER.adebug("No such id: %s", token_id)
            return False

        try:
            HASHER.verify(result[0].token, token)
            await LOGGER.adebug("Successful auth for %s", token_id)
            return True
        except argon2.exceptions.VerifyMismatchError:
            await LOGGER.adebug("Invalid token for id %s", token_id)
            return False

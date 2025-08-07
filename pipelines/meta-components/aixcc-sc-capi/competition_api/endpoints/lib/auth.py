from typing import Annotated
from uuid import UUID

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from structlog.stdlib import get_logger

from competition_api.db import Token, db_session

auth = HTTPBasic()

LOGGER = get_logger(__name__)


async def get_token_id(
    credentials: Annotated[HTTPBasicCredentials, Depends(auth)],
) -> UUID:
    async with db_session() as db:
        try:
            token_id = UUID(credentials.username)
            token = credentials.password
            authenticated = await Token.verify(db, token_id, token)
        except ValueError:
            authenticated = False

        if not authenticated:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Bad credentials",
                headers={"WWW-Authenticate": "Basic"},
            )

        return token_id

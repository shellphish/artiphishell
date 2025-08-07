import pytest
from sqlalchemy import select

from competition_api.db import Token
from competition_api.db.session import db_session


class TestToken:
    @staticmethod
    @pytest.mark.parametrize("input_token", [None, "sometoken"])
    async def test_set_token(input_token):
        async with db_session() as db:
            token_id, output_token = await Token.upsert(db, token=input_token)

            db_token = (
                await db.execute(select(Token).where(Token.id == token_id))
            ).fetchone()[0]

            assert db_token.token, "Token was null"
            assert db_token.token != input_token, "Token was stored plaintext"
            assert db_token.token != output_token, "Token was stored plaintext"

    @staticmethod
    async def test_verify():
        async with db_session() as db:
            token_id, token = await Token.upsert(db)

            assert await Token.verify(
                db, token_id, token
            ), "Inserted token did not verify correctly"

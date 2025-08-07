import os
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from vyper import v

v.set_default("database.pool.size", 100)

# Uvicorn defines this env var's name
WEB_CONCURRENCY = int(os.environ.get("WEB_CONCURRENCY", 1))


class ConnectionHolder:
    def __init__(self):
        self.engine: AsyncEngine | None = None
        self.session_class: async_sessionmaker | None = None

    def get_engine(self) -> AsyncEngine:
        if not self.engine:
            self.engine = create_async_engine(
                url=v.get("database.url"),
                pool_size=v.get_int("database.pool.size") // WEB_CONCURRENCY,
                max_overflow=0,
            )
        return self.engine

    def get_session_class(self) -> async_sessionmaker:
        if not self.session_class:
            self.session_class = async_sessionmaker(
                self.get_engine(), expire_on_commit=False, class_=AsyncSession
            )
        return self.session_class


CONNECTION_HOLDER = ConnectionHolder()


@asynccontextmanager
async def db_session():
    session = CONNECTION_HOLDER.get_session_class()()
    try:
        session.begin_nested()  # this automatically rolls back on exception
        yield session
        await session.commit()
    finally:
        await session.close()


async def fastapi_get_db():
    async with db_session() as db:
        yield db

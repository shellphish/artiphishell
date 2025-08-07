from sqlalchemy import insert
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    @classmethod
    def insert_returning(cls, returning=None, **row):
        # pylint: disable=no-member
        returning = returning or [
            cls.id,  # type: ignore
            cls.status,  # type: ignore
        ]
        return insert(cls).values(**row).returning(*returning)

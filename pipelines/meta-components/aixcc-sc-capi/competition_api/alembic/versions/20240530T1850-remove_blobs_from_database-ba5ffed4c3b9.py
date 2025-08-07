"""remove blobs from database

Revision ID: ba5ffed4c3b9
Revises: 31f3f6123788
Create Date: 2024-05-30 18:50:14.328031

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "ba5ffed4c3b9"
down_revision: Union[str, None] = "31f3f6123788"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        "generated_patch", sa.Column("data_sha256", sa.String(), nullable=False)
    )
    op.drop_column("generated_patch", "data")
    op.add_column(
        "vulnerability_discovery",
        sa.Column("pov_data_sha256", sa.String(), nullable=False),
    )
    op.drop_column("vulnerability_discovery", "pov_data")


def downgrade() -> None:
    op.add_column(
        "vulnerability_discovery",
        sa.Column("pov_data", postgresql.BYTEA(), autoincrement=False, nullable=False),
    )
    op.drop_column("vulnerability_discovery", "pov_data_sha256")
    op.add_column(
        "generated_patch",
        sa.Column("data", postgresql.BYTEA(), autoincrement=False, nullable=False),
    )
    op.drop_column("generated_patch", "data_sha256")

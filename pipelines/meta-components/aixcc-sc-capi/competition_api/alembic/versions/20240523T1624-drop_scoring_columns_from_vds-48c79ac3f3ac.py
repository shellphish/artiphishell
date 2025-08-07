"""Drop scoring columns from vds

Revision ID: 48c79ac3f3ac
Revises: 2a64367abcdb
Create Date: 2024-05-23 16:24:52.617559

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "48c79ac3f3ac"
down_revision: Union[str, None] = "2a64367abcdb"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.drop_column("vulnerability_discovery", "commit_sha_checked_out")
    op.drop_column("vulnerability_discovery", "sanitizer_fired")
    op.alter_column(
        "vulnerability_discovery",
        "team_id",
        existing_type=sa.VARCHAR(),
        type_=sa.Uuid(),
        existing_nullable=False,
        postgresql_using="team_id::UUID",
    )


def downgrade() -> None:
    op.alter_column(
        "vulnerability_discovery",
        "team_id",
        existing_type=sa.Uuid(),
        type_=sa.VARCHAR(),
        existing_nullable=False,
    )
    op.add_column(
        "vulnerability_discovery",
        sa.Column("sanitizer_fired", sa.BOOLEAN(), autoincrement=False, nullable=True),
    )
    op.add_column(
        "vulnerability_discovery",
        sa.Column(
            "commit_sha_checked_out", sa.BOOLEAN(), autoincrement=False, nullable=True
        ),
    )

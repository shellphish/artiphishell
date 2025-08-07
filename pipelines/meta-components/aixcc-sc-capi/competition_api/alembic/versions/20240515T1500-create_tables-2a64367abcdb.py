"""Create tables

Revision ID: 2a64367abcdb
Revises:
Create Date: 2024-05-15 15:00:42.628795

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2a64367abcdb"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "token",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("token", sa.String(), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "vulnerability_discovery",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cpv_uuid", sa.Uuid(), nullable=True),
        sa.Column("team_id", sa.String(), nullable=False),
        sa.Column("cp_name", sa.String(), nullable=False),
        sa.Column("pou_commit_sha1", sa.String(), nullable=False),
        sa.Column("pou_sanitizer", sa.String(), nullable=False),
        sa.Column("pov_harness", sa.String(), nullable=False),
        sa.Column("pov_data", sa.LargeBinary(), nullable=False),
        sa.Column("commit_sha_checked_out", sa.Boolean(), nullable=True),
        sa.Column("sanitizer_fired", sa.Boolean(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "ACCEPTED",
                "NOT_ACCEPTED",
                "PENDING",
                name="feedbackstatus",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        op.f("ix_vulnerability_discovery_cpv_uuid"),
        "vulnerability_discovery",
        ["cpv_uuid"],
        unique=True,
    )
    op.create_table(
        "generated_patch",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cpv_uuid", sa.Uuid(), nullable=False),
        sa.Column("data", sa.LargeBinary(), nullable=False),
        sa.Column("patch_applied", sa.Boolean(), nullable=True),
        sa.Column("sanitizer_did_not_fire", sa.Boolean(), nullable=True),
        sa.Column("functional_tests_passed", sa.Boolean(), nullable=True),
        sa.Column(
            "status",
            sa.Enum(
                "ACCEPTED",
                "NOT_ACCEPTED",
                "PENDING",
                name="feedbackstatus",
                native_enum=False,
            ),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["cpv_uuid"],
            ["vulnerability_discovery.cpv_uuid"],
        ),
        sa.PrimaryKeyConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("generated_patch")
    op.drop_index(
        op.f("ix_vulnerability_discovery_cpv_uuid"),
        table_name="vulnerability_discovery",
    )
    op.drop_table("vulnerability_discovery")
    op.drop_table("token")

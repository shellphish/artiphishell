"""make cpv uuid optional for workflow

Revision ID: 31f3f6123788
Revises: 48c79ac3f3ac
Create Date: 2024-05-28 12:11:32.960428

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "31f3f6123788"
down_revision: Union[str, None] = "48c79ac3f3ac"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.alter_column(
        "generated_patch", "cpv_uuid", existing_type=sa.UUID(), nullable=True
    )
    op.drop_column("generated_patch", "functional_tests_passed")
    op.drop_column("generated_patch", "sanitizer_did_not_fire")
    op.drop_column("generated_patch", "patch_applied")


def downgrade() -> None:
    op.add_column(
        "generated_patch",
        sa.Column("patch_applied", sa.BOOLEAN(), autoincrement=False, nullable=True),
    )
    op.add_column(
        "generated_patch",
        sa.Column(
            "sanitizer_did_not_fire", sa.BOOLEAN(), autoincrement=False, nullable=True
        ),
    )
    op.add_column(
        "generated_patch",
        sa.Column(
            "functional_tests_passed", sa.BOOLEAN(), autoincrement=False, nullable=True
        ),
    )
    op.alter_column(
        "generated_patch", "cpv_uuid", existing_type=sa.UUID(), nullable=False
    )

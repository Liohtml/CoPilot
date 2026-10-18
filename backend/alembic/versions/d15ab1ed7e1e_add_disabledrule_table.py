"""add the disabledrule table

Revision ID: d15ab1ed7e1e
Revises: d6c01a2b3c4d
Create Date: 2026-10-17 16:30:00.000000

The Wazuh manager's rule disable/enable routes (`/api/wazuh_manager/rule/disabled`,
`/rule/disable`, `/rule/enable`) keep each disabled rule's previous level in
`disabledrule` (`app/connectors/wazuh_manager/models/rules.py:DisabledRule`), but the
model was never imported by `env.py`, so no migration created the table and every one of
those routes failed on its first statement. This creates exactly the table the model
declares; `rule_id` gets the length MySQL needs for a `VARCHAR` (the model's `str` had
none, which `CREATE TABLE` refuses on MySQL).

New table only: nothing is backfilled and no existing table is touched. The downgrade
drops it (losing the record of which rules are disabled and their previous levels).
"""
from typing import Sequence
from typing import Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d15ab1ed7e1e"
down_revision: Union[str, None] = "d6c01a2b3c4d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "disabledrule",
        sa.Column("id", sa.Integer(), nullable=False, autoincrement=True),
        sa.Column("rule_id", sa.String(length=255), nullable=False),
        sa.Column("previous_level", sa.String(length=256), nullable=False),
        sa.Column("new_level", sa.String(length=256), nullable=False),
        sa.Column("reason_for_disabling", sa.String(length=256), nullable=False),
        sa.Column("length_of_time", sa.String(length=256), nullable=False),
        sa.Column("date_disabled", sa.DateTime(), nullable=False),
        sa.Column("disabled_by", sa.String(length=256), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_disabledrule_rule_id", "disabledrule", ["rule_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_disabledrule_rule_id", table_name="disabledrule")
    op.drop_table("disabledrule")

"""add the Sublime alert tables

Revision ID: d6c01a2b3c4d
Revises: c1241a1b2c3d
Create Date: 2026-10-17 16:47:58.650103

The Sublime connector's model (`app/connectors/sublime/models/alerts.py`) was never
imported by `env.py`, so no migration ever created its tables and both
`/api/sublime` routes answered a 500 on every deployment. This creates exactly the
six tables the model declares, as autogenerate renders them against the model:

- `sublimealerts`: one row per alert the Sublime webhook posts
  (`POST /api/sublime/alert`);
- `flaggedrule`, `mailbox`, `triggeredaction`, `sender`, `recipient`: its child
  rows, each with a plain FK `sublime_alert_id` to `sublimealerts.id` (no cascade:
  the module never deletes an alert).

New tables only: no existing table is touched. The downgrade drops the six tables
(losing the stored alerts).
"""
from typing import Sequence
from typing import Union

import sqlalchemy as sa
import sqlmodel

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d6c01a2b3c4d"
down_revision: Union[str, None] = "c1241a1b2c3d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

CHILDREN = ("flaggedrule", "mailbox", "recipient", "sender", "triggeredaction")


def _text(name: str, nullable: bool = False) -> sa.Column:
    return sa.Column(name, sqlmodel.sql.sqltypes.AutoString(), nullable=nullable)


def _child(name: str, *columns: sa.Column) -> None:
    op.create_table(
        name,
        sa.Column("id", sa.Integer(), nullable=False),
        *columns,
        sa.Column("sublime_alert_id", sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(["sublime_alert_id"], ["sublimealerts.id"]),
        sa.PrimaryKeyConstraint("id"),
    )


def upgrade() -> None:
    op.create_table(
        "sublimealerts",
        sa.Column("id", sa.Integer(), nullable=False),
        _text("api_version"),
        _text("created_at"),
        _text("event_id"),
        _text("type"),
        _text("message_id"),
        _text("canonical_id"),
        _text("external_id"),
        _text("message_source_id"),
        sa.Column("timestamp", sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    _child("flaggedrule", _text("rule_id"), _text("name"), _text("severity", nullable=True), _text("tags"))
    _child("mailbox", _text("external_id", nullable=True), _text("mailbox_id"))
    _child("recipient", _text("email"), _text("name", nullable=True))
    _child("sender", _text("email"), _text("name", nullable=True))
    _child("triggeredaction", _text("action_id"), _text("name"), _text("type"))


def downgrade() -> None:
    for name in CHILDREN:
        op.drop_table(name)
    op.drop_table("sublimealerts")

"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}

# revision identifiers, used by Alembic.
revision: str = ${repr(up_revision)}
down_revision: str | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    """Apply the change.

    ${upgrades if upgrades else "No operations in this revision."}
    """
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    """Revert the change.

    Written out in full even when it is lossy, and the loss is called out in a
    comment. A downgrade that quietly drops data is a decision; a downgrade that
    is `pass` and silently leaves the schema ahead of the code is a bug.
    """
    ${downgrades if downgrades else "pass"}

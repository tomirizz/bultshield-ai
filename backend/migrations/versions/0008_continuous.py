"""Opt-in continuous scanning of a registered public branch."""
import sqlalchemy as sa
from alembic import op

revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('repositories', sa.Column('continuous_enabled', sa.Boolean, nullable=False, server_default=sa.false()))
    op.add_column('repositories', sa.Column('observed_sha', sa.String(40)))
    op.add_column('repositories', sa.Column('last_checked_at', sa.DateTime(timezone=True)))


def downgrade():
    for name in ('last_checked_at', 'observed_sha', 'continuous_enabled'):
        op.drop_column('repositories', name)

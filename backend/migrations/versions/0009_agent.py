"""Bounded AI tool sessions."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('agent_runs',
        sa.Column('id', UUID, primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('project_id', UUID, sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('user_id', UUID, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('question', sa.String(1000), nullable=False),
        sa.Column('allow_actions', sa.Boolean, nullable=False), sa.Column('status', sa.String(16), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True)), sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('result', JSONB), sa.Column('error_message', sa.String(300)))
    op.create_index('ix_agent_runs_project_id', 'agent_runs', ['project_id'])


def downgrade():
    op.drop_table('agent_runs')

"""Project-scoped correlation snapshots and security issue groups."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('correlation_runs',
        sa.Column('id', UUID, primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('project_id', UUID, sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('snapshot_key', sa.String(64), nullable=False),
        sa.Column('finding_ids', JSONB, nullable=False),
        sa.Column('total_findings', sa.Integer, nullable=False),
        sa.Column('model', sa.String(200), nullable=False),
        sa.Column('status', sa.String(16), nullable=False),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('error_message', sa.Text))
    op.create_index('ix_correlation_runs_project_id', 'correlation_runs', ['project_id'])
    op.create_index('ix_correlation_active_project', 'correlation_runs', ['project_id'], unique=True,
                    postgresql_where=sa.text("status IN ('PENDING','RUNNING')"))
    op.create_table('security_issue_groups',
        sa.Column('id', UUID, primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column('run_id', UUID, sa.ForeignKey('correlation_runs.id', ondelete='CASCADE'), nullable=False),
        sa.Column('title', sa.String(200), nullable=False),
        sa.Column('interpretation', sa.Text, nullable=False),
        sa.Column('verification', sa.Text, nullable=False),
        sa.Column('finding_ids', JSONB, nullable=False))
    op.create_index('ix_security_issue_groups_run_id', 'security_issue_groups', ['run_id'])


def downgrade():
    op.drop_table('security_issue_groups')
    op.drop_table('correlation_runs')

"""Результаты агента исправлений зависимостей, привязанные к проверке образа."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('dependency_fix_runs',
        sa.Column('id', UUID, primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('project_id', UUID, nullable=False),
        sa.Column('scan_id', UUID, nullable=False),
        sa.Column('image_digest', sa.String(128)),
        sa.Column('commit_sha', sa.String(64)),
        sa.Column('status', sa.String(16), nullable=False, server_default='RUNNING'),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('summary', JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column('items', JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('other', JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('combined', JSONB),
        sa.Column('pull_request', JSONB),
        sa.Column('error_message', sa.Text),
        sa.ForeignKeyConstraint(['project_id', 'scan_id'], ['scans.project_id', 'scans.id'],
                                name=op.f('fk_dependency_fix_runs_project_id_scan_id_scans'), ondelete='CASCADE'),
        sa.CheckConstraint("status IN ('RUNNING','COMPLETED','FAILED')", name=op.f('ck_dependency_fix_runs_status_values')))
    op.create_index('ix_dependency_fix_runs_project_id', 'dependency_fix_runs', ['project_id'])
    op.create_index('ix_dependency_fix_runs_scan_id', 'dependency_fix_runs', ['scan_id'])


def downgrade():
    op.drop_table('dependency_fix_runs')

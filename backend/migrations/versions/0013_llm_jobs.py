"""Фоновые задания на пояснения языковой модели."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('llm_jobs',
        sa.Column('id', UUID, primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('project_id', UUID, nullable=False),
        sa.Column('scan_id', UUID, nullable=False),
        sa.Column('status', sa.String(16), nullable=False, server_default='QUEUED'),
        sa.Column('started_at', sa.DateTime(timezone=True)),
        sa.Column('completed_at', sa.DateTime(timezone=True)),
        sa.Column('summary', JSONB),
        sa.Column('error_message', sa.String(300)),
        sa.ForeignKeyConstraint(['project_id', 'scan_id'], ['scans.project_id', 'scans.id'],
                                name=op.f('fk_llm_jobs_project_id_scan_id_scans'), ondelete='CASCADE'),
        sa.CheckConstraint("status IN ('QUEUED','RUNNING','COMPLETED','FAILED')", name=op.f('ck_llm_jobs_status_values')))
    op.create_index('ix_llm_jobs_project_id', 'llm_jobs', ['project_id'])
    op.create_index('ix_llm_jobs_scan_id', 'llm_jobs', ['scan_id'])
    # На одну проверку не больше одного активного задания: повторный запрос не создаёт дубликат.
    op.create_index('uq_llm_jobs_active', 'llm_jobs', ['scan_id'], unique=True,
                    postgresql_where=sa.text("status IN ('QUEUED','RUNNING')"))


def downgrade():
    op.drop_table('llm_jobs')

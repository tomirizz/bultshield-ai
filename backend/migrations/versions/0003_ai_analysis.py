"""Durable AI analysis state and validated structured response."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = '0003'
down_revision = '0002'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('ai_analyses', sa.Column('started_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('ai_analyses', sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('ai_analyses', sa.Column('result', JSONB, nullable=True))
    op.drop_constraint(op.f('ck_ai_analyses_analysis_status'), 'ai_analyses', type_='check')
    op.create_check_constraint(op.f('ck_ai_analyses_analysis_status'), 'ai_analyses', "status IN ('PENDING','RUNNING','COMPLETED','FAILED')")
    op.create_index('ix_ai_analyses_active_finding', 'ai_analyses', ['finding_id'], unique=True,
                    postgresql_where=sa.text("status IN ('PENDING','RUNNING')"))


def downgrade():
    op.execute("UPDATE ai_analyses SET status='FAILED' WHERE status='RUNNING'")
    op.drop_index('ix_ai_analyses_active_finding', table_name='ai_analyses')
    op.drop_constraint(op.f('ck_ai_analyses_analysis_status'), 'ai_analyses', type_='check')
    op.create_check_constraint(op.f('ck_ai_analyses_analysis_status'), 'ai_analyses', "status IN ('PENDING','COMPLETED','FAILED')")
    for name in ('result', 'completed_at', 'started_at'):
        op.drop_column('ai_analyses', name)

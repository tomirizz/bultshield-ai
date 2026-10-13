"""Запросы к языковой модели: что отправлено, что получено, сколько стоило и почему не удалось."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('llm_calls',
        sa.Column('id', UUID, primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('project_id', UUID, nullable=False),
        sa.Column('scan_id', UUID, nullable=False),
        sa.Column('subject_key', sa.String(300), nullable=False),
        sa.Column('finding_ids', JSONB, nullable=False, server_default=sa.text("'[]'::jsonb")),
        sa.Column('provider', sa.String(32), nullable=False),
        sa.Column('model', sa.String(200)),
        sa.Column('prompt_version', sa.String(32), nullable=False),
        sa.Column('input_hash', sa.String(64), nullable=False),
        sa.Column('status', sa.String(20), nullable=False),
        sa.Column('error_code', sa.String(40)),
        sa.Column('error_message', sa.Text),
        sa.Column('input_tokens', sa.Integer, nullable=False, server_default='0'),
        sa.Column('output_tokens', sa.Integer, nullable=False, server_default='0'),
        sa.Column('cost_usd', sa.Numeric(12, 6), nullable=False, server_default='0'),
        sa.Column('duration_ms', sa.Integer, nullable=False, server_default='0'),
        sa.Column('request', JSONB),
        sa.Column('result', JSONB),
        sa.ForeignKeyConstraint(['project_id', 'scan_id'], ['scans.project_id', 'scans.id'],
                                name=op.f('fk_llm_calls_project_id_scan_id_scans'), ondelete='CASCADE'),
        sa.CheckConstraint("status IN ('COMPLETED','UNAVAILABLE','INVALID_RESPONSE','ERROR','LIMIT_EXCEEDED')",
                           name=op.f('ck_llm_calls_status_values')))
    op.create_index('ix_llm_calls_project_id', 'llm_calls', ['project_id'])
    op.create_index('ix_llm_calls_scan_id', 'llm_calls', ['scan_id'])
    # Одно и то же пояснение для одной проверки сохраняется один раз, даже если два запуска пошли одновременно.
    op.create_index('uq_llm_calls_completed', 'llm_calls', ['scan_id', 'input_hash'], unique=True,
                    postgresql_where=sa.text("status = 'COMPLETED'"))


def downgrade():
    op.drop_table('llm_calls')

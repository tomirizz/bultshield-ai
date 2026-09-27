"""Reviewed fixes, isolated verification and allowlisted web targets."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('scans', sa.Column('kind', sa.String(24), nullable=False, server_default='static'))
    op.create_index('ix_scans_kind', 'scans', ['kind'])
    op.drop_constraint(op.f('ck_fixes_fix_status'), 'fixes', type_='check')
    op.alter_column('fixes', 'status', type_=sa.String(32), existing_type=sa.String(8))
    op.create_check_constraint(op.f('ck_fixes_fix_status'), 'fixes', "status IN ('QUEUED','GENERATING','PROPOSED','APPROVED','APPLIED','RECHECKING','VERIFIED_FIXED','STILL_DETECTED','FAILED')")
    for name, typ in [('base_sha', sa.String(64)), ('file', sa.String(2048)), ('original_hash', sa.String(64)),
                      ('original', sa.Text), ('proposed', sa.Text), ('model', sa.String(200)),
                      ('error_message', sa.Text), ('worker_id', sa.String(64)),
                      ('heartbeat_at', sa.DateTime(timezone=True)), ('approved_at', sa.DateTime(timezone=True))]:
        op.add_column('fixes', sa.Column(name, typ))
    op.add_column('fixes', sa.Column('verification_scan_id', UUID, sa.ForeignKey('scans.id')))
    op.add_column('fixes', sa.Column('verification', JSONB, nullable=False, server_default='{}'))
    op.add_column('fixes', sa.Column('timeline', JSONB, nullable=False, server_default='[]'))
    op.create_index('ix_fixes_active_finding', 'fixes', ['finding_id'], unique=True,
                    postgresql_where=sa.text("status IN ('QUEUED','GENERATING','PROPOSED','APPROVED','APPLIED','RECHECKING')"))
    op.create_table('web_targets',
        sa.Column('id', UUID, primary_key=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column('project_id', UUID, sa.ForeignKey('projects.id', ondelete='CASCADE'), nullable=False),
        sa.Column('url', sa.String(2048), nullable=False),
        sa.Column('confirmed_control', sa.Boolean, nullable=False),
        sa.UniqueConstraint('project_id', 'url'))
    op.create_index('ix_web_targets_project_id', 'web_targets', ['project_id'])


def downgrade():
    # Avoid silently discarding approvals or claiming old lifecycle compatibility.
    raise RuntimeError('Restore a pre-migration backup to downgrade Stage 10–12 data.')

"""Unified scan engine progress and worker ownership."""
import sqlalchemy as sa
from alembic import op

revision = '0002'
down_revision = '0001'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('scans', sa.Column('current_step', sa.String(32), nullable=True))
    op.add_column('scans', sa.Column('error_code', sa.String(64), nullable=True))
    op.add_column('scan_jobs', sa.Column('worker_id', sa.String(64), nullable=True))
    op.drop_constraint(op.f('ck_scans_scan_status'), 'scans', type_='check')
    op.create_check_constraint(op.f('ck_scans_scan_status'), 'scans',
                               "status IN ('QUEUED','CLONING','SCANNING','ANALYSING','NORMALIZING','AI_ANALYSIS','COMPLETED','FAILED')")


def downgrade():
    op.execute("UPDATE scans SET status = 'NORMALIZING' WHERE status = 'ANALYSING'")
    op.drop_constraint(op.f('ck_scans_scan_status'), 'scans', type_='check')
    op.create_check_constraint(op.f('ck_scans_scan_status'), 'scans',
                               "status IN ('QUEUED','CLONING','SCANNING','NORMALIZING','AI_ANALYSIS','COMPLETED','FAILED')")
    op.drop_column('scan_jobs', 'worker_id')
    op.drop_column('scans', 'error_code')
    op.drop_column('scans', 'current_step')

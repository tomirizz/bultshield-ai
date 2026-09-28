"""Separate scanner severity from versioned product priority."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('findings', sa.Column('risk_score', sa.Integer, nullable=True))
    op.add_column('findings', sa.Column('priority', sa.String(2), nullable=True))
    op.add_column('findings', sa.Column('risk_details', JSONB, nullable=True))
    op.create_check_constraint('risk_score_range', 'findings', 'risk_score BETWEEN 0 AND 100')
    op.create_check_constraint('risk_priority', 'findings', "priority IN ('P0','P1','P2','P3','P4')")


def downgrade():
    op.drop_constraint('risk_priority', 'findings', type_='check')
    op.drop_constraint('risk_score_range', 'findings', type_='check')
    for name in ('risk_details', 'priority', 'risk_score'):
        op.drop_column('findings', name)

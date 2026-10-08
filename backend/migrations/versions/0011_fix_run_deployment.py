"""Доказательства применения исправления: результат повторной проверки образа после слияния PR."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB

revision = '0011'
down_revision = '0010'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('dependency_fix_runs', sa.Column('deployment', JSONB))


def downgrade():
    op.drop_column('dependency_fix_runs', 'deployment')

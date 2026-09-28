"""GitHub identities, expiring sessions and credential-free audit trail."""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def common():
    return [sa.Column('id', UUID, primary_key=True),
            sa.Column('created_at', sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now())]


def upgrade():
    op.create_table('github_identities', *common(),
        sa.Column('user_id', UUID, sa.ForeignKey('users.id'), nullable=False, unique=True),
        sa.Column('github_id', sa.String(32), nullable=False, unique=True),
        sa.Column('login', sa.String(100), nullable=False), sa.Column('encrypted_token', sa.Text, nullable=False))
    op.create_table('login_sessions', *common(),
        sa.Column('user_id', UUID, sa.ForeignKey('users.id'), nullable=False),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False))
    op.create_index('ix_login_sessions_user_id', 'login_sessions', ['user_id'])
    op.create_table('oauth_states', *common(),
        sa.Column('token_hash', sa.String(64), nullable=False, unique=True),
        sa.Column('verifier', sa.String(128), nullable=False),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False))
    op.create_table('audit_events', *common(),
        sa.Column('user_id', UUID, sa.ForeignKey('users.id')),
        sa.Column('action', sa.String(100), nullable=False), sa.Column('object_id', sa.String(64)),
        sa.Column('outcome', sa.String(32), nullable=False))
    op.create_index('ix_audit_events_user_id', 'audit_events', ['user_id'])


def downgrade():
    for name in ('audit_events', 'oauth_states', 'login_sessions', 'github_identities'):
        op.drop_table(name)

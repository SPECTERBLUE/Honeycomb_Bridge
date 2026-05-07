"""add mfa_secret to users

Revision ID: 9f26218ff9c7
Revises: 
Create Date: 2025-11-03 16:17:13.571154

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9f26218ff9c7'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('mfa_secret', sa.String(length=64), nullable=True))

def downgrade():
    op.drop_column('users', 'mfa_secret')
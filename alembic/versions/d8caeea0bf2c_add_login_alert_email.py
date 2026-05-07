"""add login_alert_email

Revision ID: d8caeea0bf2c
Revises: 9f26218ff9c7
Create Date: 2025-11-10 15:02:29.647041

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'd8caeea0bf2c'
down_revision = '9f26218ff9c7'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('users', sa.Column('login_alert_email', sa.String(length=100), nullable=True))
    pass


def downgrade():
    op.drop_column('users', 'login_alert_email')
    pass

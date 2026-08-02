"""Script à lancer une fois pour créer le compte admin initial."""
import os
import sys
from app import create_app
from app.extensions import db
from app.models import AdminUser

app = create_app()

with app.app_context():
    db.create_all()
    username = os.environ.get("INIT_ADMIN_USER", "admin")
    password = os.environ.get("INIT_ADMIN_PASS")
    if not password:
        print("Set INIT_ADMIN_PASS env var")
        sys.exit(1)
    if AdminUser.query.filter_by(username=username).first():
        print(f"Admin '{username}' exists already.")
        sys.exit(0)
    admin = AdminUser(username=username)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    print(f"OK Admin '{username}' created.")

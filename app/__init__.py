from flask import Flask, jsonify
from .config import Config
from .extensions import db, login_manager, csrf, limiter

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    csrf.init_app(app)
    limiter.init_app(app)

    from .blueprints.auth import bp as auth_bp
    from .blueprints.admin import bp as admin_bp
    from .blueprints.api_v1 import bp as api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(api_bp)
    csrf.exempt(api_bp)

    from .models import AdminUser
    @login_manager.user_loader
    def load_user(uid):
        return AdminUser.query.get(int(uid))

    with app.app_context():
        db.create_all()
        _run_migrations(app)
        _bootstrap_from_env(app)

    @app.route("/healthz")
    def health():
        return jsonify(status="ok"), 200

    @app.route("/")
    def root():
        from flask import redirect, url_for
        return redirect(url_for("admin.dashboard"))

    return app


def _run_migrations(app):
    """Idempotent auto-migrations. Adds columns added after first prod deploy."""
    try:
        from sqlalchemy import inspect, text
        insp = inspect(db.engine)
        existing = {c["name"] for c in insp.get_columns("licenses")}
        with db.engine.begin() as conn:
            if "usage_count" not in existing:
                conn.execute(text("ALTER TABLE licenses ADD COLUMN usage_count INTEGER DEFAULT 0"))
                conn.execute(text("UPDATE licenses SET usage_count = 0 WHERE usage_count IS NULL"))
                app.logger.warning("[migration] added licenses.usage_count")
    except Exception as e:
        app.logger.error(f"[migration] failed: {e}")


def _bootstrap_from_env(app):
    """
    First-boot bootstrap driven by Fly Secrets (or any env vars).
    Reads:
      INIT_ADMIN_USER   -> username for admin (default "admin")
      INIT_ADMIN_PASS   -> password for admin  (REQUIRED to auto-create admin)
      INIT_APP_NAME     -> Application row name (default "vanguard")
      INIT_APP_SECRET   -> API secret (HMAC key) — must MATCH the client's config
    Idempotent: skips if entries already exist.
    """
    import os
    from .models import AdminUser, Application

    try:
        admin_user = os.environ.get("INIT_ADMIN_USER", "admin").strip()
        admin_pass = os.environ.get("INIT_ADMIN_PASS", "").strip()
        if admin_pass and not AdminUser.query.filter_by(username=admin_user).first():
            u = AdminUser(username=admin_user)
            u.set_password(admin_pass)
            db.session.add(u)
            db.session.commit()
            app.logger.warning(f"[bootstrap] admin '{admin_user}' created from env")
    except Exception as e:
        app.logger.error(f"[bootstrap] admin creation failed: {e}")

    try:
        app_name = os.environ.get("INIT_APP_NAME", "vanguard").strip()
        app_secret = os.environ.get("INIT_APP_SECRET", "").strip()
        if app_name and app_secret and not Application.query.filter_by(name=app_name).first():
            owner = AdminUser.query.order_by(AdminUser.id).first()
            row = Application(
                name=app_name,
                version=os.environ.get("INIT_APP_VERSION", "1.0.0"),
                api_secret=app_secret,
                hwid_lock=True,
                integrity_check=True,
                owner_id=owner.id if owner else None,
            )
            db.session.add(row)
            db.session.commit()
            app.logger.warning(f"[bootstrap] application '{app_name}' created from env")
    except Exception as e:
        app.logger.error(f"[bootstrap] app creation failed: {e}")

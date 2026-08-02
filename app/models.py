import secrets
import time
import bcrypt
from flask_login import UserMixin
from .extensions import db

def now_ts():
    return int(time.time())

def gen_secret(n=32):
    return secrets.token_urlsafe(n)

def gen_license_key():
    parts = [secrets.token_hex(2).upper() for _ in range(5)]
    return "-".join(parts)

class AdminUser(UserMixin, db.Model):
    __tablename__ = "admin_users"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    twofa_secret = db.Column(db.String(64))
    created_at = db.Column(db.Integer, default=now_ts)

    def set_password(self, pw):
        self.password_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

    def check_password(self, pw):
        return bcrypt.checkpw(pw.encode(), self.password_hash.encode())


class Application(db.Model):
    __tablename__ = "applications"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    version = db.Column(db.String(16), default="1.0.0")
    owner_id = db.Column(db.Integer, db.ForeignKey("admin_users.id"))
    api_secret = db.Column(db.String(96), default=gen_secret, nullable=False)
    hwid_lock = db.Column(db.Boolean, default=True)
    integrity_check = db.Column(db.Boolean, default=True)
    disabled = db.Column(db.Boolean, default=False)
    disabled_message = db.Column(db.String(256), default="Application disabled")
    update_message = db.Column(db.String(256), default="")
    download_url = db.Column(db.String(512), default="")
    created_at = db.Column(db.Integer, default=now_ts)

    licenses = db.relationship("License", backref="application", cascade="all, delete-orphan")
    users = db.relationship("EndUser", backref="application", cascade="all, delete-orphan")
    subs = db.relationship("Subscription", backref="application", cascade="all, delete-orphan")


class Subscription(db.Model):
    __tablename__ = "subscriptions"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    level = db.Column(db.Integer, default=1)
    created_at = db.Column(db.Integer, default=now_ts)


class License(db.Model):
    __tablename__ = "licenses"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    sub_id = db.Column(db.Integer, db.ForeignKey("subscriptions.id"))
    key = db.Column(db.String(64), unique=True, default=gen_license_key, nullable=False)
    duration_days = db.Column(db.Integer, default=30)
    max_hwids = db.Column(db.Integer, default=1)
    max_uses = db.Column(db.Integer, default=1)
    used = db.Column(db.Integer, default=0)
    usage_count = db.Column(db.Integer, default=0)  # +1 par sync HWID (spoof)
    note = db.Column(db.String(256))
    banned = db.Column(db.Boolean, default=False)
    activated_at = db.Column(db.Integer)
    expires_at = db.Column(db.Integer)
    created_at = db.Column(db.Integer, default=now_ts)


class EndUser(db.Model):
    __tablename__ = "end_users"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    username = db.Column(db.String(64), nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(128))
    sub_id = db.Column(db.Integer, db.ForeignKey("subscriptions.id"))
    banned = db.Column(db.Boolean, default=False)
    hwid = db.Column(db.String(128))
    ip = db.Column(db.String(64))
    expires_at = db.Column(db.Integer)
    last_login = db.Column(db.Integer)
    created_at = db.Column(db.Integer, default=now_ts)

    __table_args__ = (db.UniqueConstraint("app_id", "username", name="uq_app_user"),)

    def set_password(self, pw):
        self.password_hash = bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()

    def check_password(self, pw):
        return bcrypt.checkpw(pw.encode(), self.password_hash.encode())


class HwidBinding(db.Model):
    __tablename__ = "hwid_bindings"
    id = db.Column(db.Integer, primary_key=True)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id", ondelete="CASCADE"), nullable=False)
    hwid = db.Column(db.String(128), nullable=False)
    ip = db.Column(db.String(64))
    first_seen = db.Column(db.Integer, default=now_ts)
    last_seen = db.Column(db.Integer, default=now_ts)
    __table_args__ = (db.UniqueConstraint("license_id", "hwid", name="uq_lic_hwid"),)


class ClientSession(db.Model):
    __tablename__ = "client_sessions"
    token = db.Column(db.String(64), primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    license_id = db.Column(db.Integer, db.ForeignKey("licenses.id"))
    end_user_id = db.Column(db.Integer, db.ForeignKey("end_users.id"))
    hwid = db.Column(db.String(128))
    ip = db.Column(db.String(64))
    created_at = db.Column(db.Integer, default=now_ts)
    expires_at = db.Column(db.Integer, nullable=False)


class BlacklistEntry(db.Model):
    __tablename__ = "blacklist"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    kind = db.Column(db.String(16), nullable=False)
    value = db.Column(db.String(256), nullable=False)
    reason = db.Column(db.String(256))
    created_at = db.Column(db.Integer, default=now_ts)


class Variable(db.Model):
    __tablename__ = "variables"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    name = db.Column(db.String(64), nullable=False)
    value = db.Column(db.Text, nullable=False)
    secret = db.Column(db.Boolean, default=False)
    min_sub_level = db.Column(db.Integer, default=0)
    created_at = db.Column(db.Integer, default=now_ts)


class StoredFile(db.Model):
    __tablename__ = "files"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    name = db.Column(db.String(128), nullable=False)
    path = db.Column(db.String(512), nullable=False)
    size = db.Column(db.Integer, default=0)
    min_sub_level = db.Column(db.Integer, default=0)
    created_at = db.Column(db.Integer, default=now_ts)


class Webhook(db.Model):
    __tablename__ = "webhooks"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey("applications.id"), nullable=False)
    url = db.Column(db.String(512), nullable=False)
    secret = db.Column(db.String(64), default=gen_secret)
    events = db.Column(db.String(256), default="login,fail,ban")
    active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.Integer, default=now_ts)


class Nonce(db.Model):
    __tablename__ = "nonces"
    nonce = db.Column(db.String(64), primary_key=True)
    app_id = db.Column(db.Integer, nullable=False)
    expires_at = db.Column(db.Integer, nullable=False)


class LogEntry(db.Model):
    __tablename__ = "logs"
    id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer)
    action = db.Column(db.String(64), nullable=False)
    ip = db.Column(db.String(64))
    hwid = db.Column(db.String(128))
    identifier = db.Column(db.String(128))
    details = db.Column(db.Text)
    ts = db.Column(db.Integer, default=now_ts)

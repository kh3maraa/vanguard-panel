import os
import secrets


def _load_or_create_secret():
    """
    Fournit une SECRET_KEY stable :
    1. Utilise la variable d'env SECRET_KEY si présente
    2. Sinon lit/crée un fichier .secret_key à côté de la DB (volume persistant)
    Garantit que tous les workers gunicorn partagent la même clé.
    """
    env = os.environ.get("SECRET_KEY")
    if env:
        return env
    db_path = os.environ.get("DB_PATH", "vanguard.db")
    key_path = os.path.join(os.path.dirname(db_path) or ".", ".vanguard_secret")
    if os.path.exists(key_path):
        try:
            with open(key_path) as f:
                v = f.read().strip()
            if v:
                return v
        except OSError:
            pass
    val = secrets.token_hex(32)
    try:
        d = os.path.dirname(key_path)
        if d:
            os.makedirs(d, exist_ok=True)
        with open(key_path, "w") as f:
            f.write(val)
    except OSError:
        pass
    return val


class Config:
    SECRET_KEY = _load_or_create_secret()
    DB_PATH = os.environ.get("DB_PATH", "vanguard.db")
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{DB_PATH}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    WTF_CSRF_TIME_LIMIT = 3600
    FILES_DIR = os.environ.get("FILES_DIR", "./files")
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024
    RATELIMIT_STORAGE_URI = "memory://"
    RATELIMIT_DEFAULT = "300 per hour"

    HMAC_TIMESTAMP_WINDOW = 30
    SESSION_TTL = 3600 * 6
    NONCE_TTL = 60

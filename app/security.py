"""Vanguard core: HMAC signing, anti-replay, blacklist checks, webhook delivery."""
import hmac
import hashlib
import json
import threading
import requests
from flask import request
from .extensions import db
from .models import Application, Nonce, BlacklistEntry, Webhook, LogEntry, now_ts


def hmac_sign(secret: str, payload: str, ts: str, nonce: str) -> str:
    msg = f"{ts}.{nonce}.{payload}".encode()
    return hmac.new(secret.encode(), msg, hashlib.sha256).hexdigest()


def verify_signature(app: Application, payload_str: str, ts: str, nonce: str, sig: str, window: int):
    if not ts or not nonce or not sig:
        return False, "missing signature fields"
    try:
        ts_i = int(ts)
    except ValueError:
        return False, "bad timestamp"
    if abs(now_ts() - ts_i) > window:
        return False, "timestamp out of window"
    expected = hmac_sign(app.api_secret, payload_str, ts, nonce)
    if not hmac.compare_digest(expected, sig):
        return False, "bad signature"
    if Nonce.query.get(nonce):
        return False, "nonce replayed"
    db.session.add(Nonce(nonce=nonce, app_id=app.id, expires_at=now_ts() + 120))
    db.session.commit()
    return True, "ok"


def prune_nonces():
    Nonce.query.filter(Nonce.expires_at < now_ts()).delete()
    db.session.commit()


def is_blacklisted(app_id: int, kind: str, value: str) -> bool:
    if not value:
        return False
    return db.session.query(BlacklistEntry.id).filter_by(app_id=app_id, kind=kind, value=value).first() is not None


def client_ip():
    fwd = request.headers.get("X-Forwarded-For", "")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.remote_addr or ""


def add_log(app_id, action, ip="", hwid="", identifier="", details=""):
    db.session.add(LogEntry(
        app_id=app_id, action=action, ip=ip, hwid=hwid,
        identifier=identifier, details=details
    ))
    db.session.commit()


def _post_webhook(url, secret, body):
    try:
        raw = json.dumps(body, separators=(",", ":"))
        sig = hmac.new(secret.encode(), raw.encode(), hashlib.sha256).hexdigest()
        requests.post(url, data=raw, headers={
            "Content-Type": "application/json",
            "X-Vanguard-Signature": sig
        }, timeout=5)
    except Exception:
        pass


def fire_webhook(app_id: int, event: str, payload: dict):
    hooks = Webhook.query.filter_by(app_id=app_id, active=True).all()
    for h in hooks:
        if event not in (h.events or "").split(","):
            continue
        body = {"event": event, "app_id": app_id, "ts": now_ts(), "data": payload}
        threading.Thread(target=_post_webhook, args=(h.url, h.secret, body), daemon=True).start()

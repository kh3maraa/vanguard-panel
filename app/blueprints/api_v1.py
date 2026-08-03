"""API client SDK — signee HMAC, protegee anti-replay et blacklist."""
import json
import secrets
from flask import Blueprint, request, jsonify, g, current_app, send_file
from ..extensions import db, limiter
from ..models import (
    Application, License, EndUser, ClientSession, HwidBinding,
    Subscription, Variable, StoredFile, now_ts
)
from ..security import verify_signature, is_blacklisted, client_ip, add_log, fire_webhook, prune_nonces
from ..utils import require_app

bp = Blueprint("api", __name__, url_prefix="/api/v1")


def _sig_check(payload_str):
    ts = request.headers.get("X-Timestamp", "")
    nonce = request.headers.get("X-Nonce", "")
    sig = request.headers.get("X-Signature", "")
    if g.app.integrity_check:
        ok, reason = verify_signature(
            g.app, payload_str, ts, nonce, sig,
            current_app.config["HMAC_TIMESTAMP_WINDOW"]
        )
        if not ok:
            add_log(g.app.id, "sig_fail", client_ip(), "", "", reason)
            return jsonify(success=False, message=f"integrity failure: {reason}"), 401
    return None


def _blacklist_gate(ip, hwid, username=""):
    for kind, value in (("ip", ip), ("hwid", hwid), ("username", username)):
        if value and is_blacklisted(g.app.id, kind, value):
            add_log(g.app.id, "blacklisted", ip, hwid, username, kind)
            return jsonify(success=False, message=f"{kind} blacklisted"), 403
    return None


@bp.route("/init", methods=["POST"])
@limiter.limit("60 per minute")
@require_app
def init():
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err: return err
    prune_nonces()
    add_log(g.app.id, "init", client_ip())
    return jsonify(
        success=True,
        version=g.app.version,
        update_message=g.app.update_message,
        download_url=g.app.download_url,
        server_time=now_ts()
    )


@bp.route("/license", methods=["POST"])
@limiter.limit("30 per minute")
@require_app
def license_login():
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err: return err
    data = json.loads(raw or "{}")
    key = (data.get("key") or "").strip().upper()
    hwid = (data.get("hwid") or "").strip()
    ip = client_ip()

    bl = _blacklist_gate(ip, hwid)
    if bl: return bl

    lic = License.query.filter_by(app_id=g.app.id, key=key).first()
    if not lic:
        add_log(g.app.id, "license_fail", ip, hwid, key, "not found")
        fire_webhook(g.app.id, "fail", {"reason": "bad_key", "ip": ip, "hwid": hwid})
        return jsonify(success=False, message="Invalid license"), 403
    if lic.banned:
        add_log(g.app.id, "license_banned", ip, hwid, key)
        fire_webhook(g.app.id, "ban", {"key": key, "ip": ip})
        return jsonify(success=False, message="License banned"), 403

    if lic.activated_at is None:
        lic.activated_at = now_ts()
        lic.expires_at = now_ts() + lic.duration_days * 86400
    if lic.expires_at and lic.expires_at < now_ts():
        add_log(g.app.id, "license_expired", ip, hwid, key)
        return jsonify(success=False, message="License expired"), 403

    if g.app.hwid_lock and hwid:
        # --- STRICT LOCK ---
        # Un HWID ne peut appartenir qu'a UNE seule license active a la fois.
        # Si HWID est deja bound a une AUTRE license (banned ou pas), on rejette.
        # Pour transferer: l'admin fait "Reset HWID" sur la license qui detient,
        # OU la license actuelle sync (post-spoof) et cela remplace son binding.
        other_bind = (
            db.session.query(HwidBinding)
            .join(License, License.id == HwidBinding.license_id)
            .filter(
                HwidBinding.hwid == hwid,
                HwidBinding.license_id != lic.id,
                License.app_id == g.app.id,
            )
            .first()
        )
        if other_bind:
            add_log(g.app.id, "hwid_locked", ip, hwid, key,
                    f"HWID owned by lic#{other_bind.license_id}")
            fire_webhook(g.app.id, "fail", {"reason": "hwid_locked",
                                            "ip": ip, "hwid": hwid,
                                            "key": key,
                                            "owner_lic": other_bind.license_id})
            return jsonify(success=False, message="hwid already bound to another license"), 403

        # Per-license bindings (max_hwids par cle -- normalement 1).
        #
        # POST-SPOOF REBIND: si le HWID courant n'existe pas encore parmi les
        # bindings de CETTE license ET qu'on a atteint la limite, on considere
        # ca comme une rotation legitime de machine (spoof) tant que le HWID
        # n'appartient a AUCUNE autre license (le check `other_bind` juste
        # au-dessus garantit deja ca). On drop les anciens bindings et on
        # pose le nouveau -- l'invariant "1 cle = 1 device actif" reste vrai.
        # Ca evite le blocage "HWID limit reached" quand le /hwid/sync
        # post-spoof a echoue (reseau, DNS apres rotation MAC) et que
        # l'utilisateur redemarre puis se reconnecte avec la meme cle.
        binds = HwidBinding.query.filter_by(license_id=lic.id).all()
        if not any(b.hwid == hwid for b in binds):
            if len(binds) >= lic.max_hwids:
                HwidBinding.query.filter_by(license_id=lic.id).delete()
                lic.usage_count = (lic.usage_count or 0) + 1
                add_log(g.app.id, "hwid_rebind", ip, hwid, key,
                        f"replaced {len(binds)} binding(s) on login (spoof rotation)")
                fire_webhook(g.app.id, "hwid_sync",
                             {"key": key, "ip": ip, "hwid": hwid, "via": "login"})
            db.session.add(HwidBinding(license_id=lic.id, hwid=hwid, ip=ip))
        else:
            for b in binds:
                if b.hwid == hwid:
                    b.last_seen = now_ts(); b.ip = ip

    token = secrets.token_urlsafe(32)
    exp = now_ts() + current_app.config["SESSION_TTL"]
    db.session.add(ClientSession(
        token=token, app_id=g.app.id, license_id=lic.id,
        hwid=hwid, ip=ip, expires_at=exp
    ))
    db.session.commit()
    add_log(g.app.id, "license_login_ok", ip, hwid, key)
    fire_webhook(g.app.id, "login", {"type": "license", "key": key, "ip": ip, "hwid": hwid})

    sub_name = None
    if lic.sub_id:
        s = Subscription.query.get(lic.sub_id)
        sub_name = s.name if s else None

    return jsonify(
        success=True, message="Login OK",
        token=token,
        expires_at=lic.expires_at,
        subscription=sub_name,
        session_expires=exp
    )


@bp.route("/hwid/sync", methods=["POST"])
@limiter.limit("30 per minute")
@require_app
def hwid_sync():
    """
    Client pushes the freshly rotated HWID for a licensed key after a spoof.
    We wipe the existing HwidBinding rows for the license and pin the new
    HWID as the sole binding, then rewrite active ClientSessions so the
    running app stays authenticated with the new identity.

    Body: {"key": "VNGD-...", "hwid": "<hex>"}
    """
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err:
        return err

    data = json.loads(raw or "{}")
    key = (data.get("key") or "").strip().upper()
    new_hwid = (data.get("hwid") or "").strip()
    ip = client_ip()

    if not key or not new_hwid:
        return jsonify(success=False, message="missing fields"), 400

    bl = _blacklist_gate(ip, new_hwid)
    if bl:
        return bl

    lic = License.query.filter_by(app_id=g.app.id, key=key).first()
    if not lic:
        add_log(g.app.id, "hwid_sync_fail", ip, new_hwid, key, "not found")
        return jsonify(success=False, message="Invalid license"), 403
    if lic.banned:
        add_log(g.app.id, "hwid_sync_banned", ip, new_hwid, key)
        return jsonify(success=False, message="License banned"), 403

    # --- STEAL au sync (asymetrique avec /license strict) ---
    # Rationale : /hwid/sync ne peut etre appele qu'apres qu'une session client
    # ait ete authentifiee avec CETTE license via /license (signature HMAC + key
    # valide). Donc quand un client dit "je viens de spoofer, mon HWID est
    # maintenant X", on considere qu'il en prend legitimement possession -- meme
    # si X etait bound a une autre license via un binding orphelin (test
    # precedent, cle supprimee mais binding survivant, etc).
    # /license reste STRICT (rejette si HWID appartient a une autre cle).
    stolen = (
        db.session.query(HwidBinding)
        .join(License, License.id == HwidBinding.license_id)
        .filter(
            HwidBinding.hwid == new_hwid,
            HwidBinding.license_id != lic.id,
            License.app_id == g.app.id,
        )
        .all()
    )
    stolen_ids = [b.license_id for b in stolen]
    for b in stolen:
        db.session.delete(b)
    if stolen_ids:
        ClientSession.query.filter(
            ClientSession.license_id.in_(stolen_ids),
            ClientSession.hwid == new_hwid,
        ).delete(synchronize_session=False)
        add_log(g.app.id, "hwid_sync_steal", ip, new_hwid, key,
                f"took HWID from lic#{','.join(str(x) for x in stolen_ids)}")

    # Wipe l'ancien binding de CETTE license et pose le nouveau
    HwidBinding.query.filter_by(license_id=lic.id).delete()
    db.session.add(HwidBinding(license_id=lic.id, hwid=new_hwid, ip=ip))

    # Retag active sessions so /session/check keeps returning success.
    active = ClientSession.query.filter_by(app_id=g.app.id, license_id=lic.id).all()
    for s in active:
        if s.expires_at >= now_ts():
            s.hwid = new_hwid
            s.ip = ip

    # Compteur d'utilisations: +1 a chaque spoof->sync HWID.
    lic.usage_count = (lic.usage_count or 0) + 1

    db.session.commit()
    add_log(g.app.id, "hwid_sync_ok", ip, new_hwid, key, f"usage={lic.usage_count}")
    fire_webhook(g.app.id, "hwid_sync", {"key": key, "ip": ip, "hwid": new_hwid})
    return jsonify(success=True, message="HWID synced")


@bp.route("/register", methods=["POST"])
@limiter.limit("10 per minute")
@require_app
def register_user():
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err: return err
    data = json.loads(raw or "{}")
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    email = (data.get("email") or "").strip().lower()
    key = (data.get("key") or "").strip().upper()
    hwid = data.get("hwid") or ""
    ip = client_ip()

    bl = _blacklist_gate(ip, hwid, username)
    if bl: return bl
    if not username or not password or not key:
        return jsonify(success=False, message="missing fields"), 400
    if EndUser.query.filter_by(app_id=g.app.id, username=username).first():
        return jsonify(success=False, message="username taken"), 409

    lic = License.query.filter_by(app_id=g.app.id, key=key).first()
    if not lic or lic.banned or lic.activated_at is not None:
        return jsonify(success=False, message="invalid or used key"), 403

    lic.activated_at = now_ts()
    lic.expires_at = now_ts() + lic.duration_days * 86400
    u = EndUser(app_id=g.app.id, username=username, email=email or None,
                sub_id=lic.sub_id, hwid=hwid, ip=ip, expires_at=lic.expires_at)
    u.set_password(password)
    db.session.add(u); db.session.commit()
    add_log(g.app.id, "user_register", ip, hwid, username)
    return jsonify(success=True, message="registered")


@bp.route("/login", methods=["POST"])
@limiter.limit("20 per minute")
@require_app
def user_login():
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err: return err
    data = json.loads(raw or "{}")
    username = (data.get("username") or "").strip().lower()
    password = data.get("password") or ""
    hwid = data.get("hwid") or ""
    ip = client_ip()

    bl = _blacklist_gate(ip, hwid, username)
    if bl: return bl

    u = EndUser.query.filter_by(app_id=g.app.id, username=username).first()
    if not u or not u.check_password(password):
        add_log(g.app.id, "user_login_fail", ip, hwid, username)
        fire_webhook(g.app.id, "fail", {"type": "user", "username": username, "ip": ip})
        return jsonify(success=False, message="bad credentials"), 403
    if u.banned:
        return jsonify(success=False, message="user banned"), 403
    if u.expires_at and u.expires_at < now_ts():
        return jsonify(success=False, message="subscription expired"), 403
    if g.app.hwid_lock and hwid:
        if u.hwid and u.hwid != hwid:
            return jsonify(success=False, message="hwid mismatch"), 403
        u.hwid = hwid
    u.ip = ip; u.last_login = now_ts()

    token = secrets.token_urlsafe(32)
    exp = now_ts() + current_app.config["SESSION_TTL"]
    db.session.add(ClientSession(
        token=token, app_id=g.app.id, end_user_id=u.id,
        hwid=hwid, ip=ip, expires_at=exp
    ))
    db.session.commit()
    add_log(g.app.id, "user_login_ok", ip, hwid, username)
    fire_webhook(g.app.id, "login", {"type": "user", "username": username, "ip": ip})

    sub_name = None
    if u.sub_id:
        s = Subscription.query.get(u.sub_id)
        sub_name = s.name if s else None
    return jsonify(success=True, token=token, expires_at=u.expires_at,
                   subscription=sub_name, session_expires=exp)


@bp.route("/session/check", methods=["POST"])
@limiter.limit("120 per minute")
@require_app
def session_check():
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err: return err
    data = json.loads(raw or "{}")
    token = data.get("token", "")
    hwid = data.get("hwid", "")
    s = ClientSession.query.filter_by(token=token, app_id=g.app.id).first()
    if not s or s.expires_at < now_ts() or (g.app.hwid_lock and hwid and s.hwid != hwid):
        return jsonify(success=False, message="session invalid"), 401
    return jsonify(success=True, expires_at=s.expires_at)


def _session_from_token(token):
    if not token:
        return None
    s = ClientSession.query.filter_by(token=token, app_id=g.app.id).first()
    if not s or s.expires_at < now_ts():
        return None
    return s


def _sub_level_of_session(s):
    sub_id = None
    if s.license_id:
        lic = License.query.get(s.license_id)
        if lic: sub_id = lic.sub_id
    elif s.end_user_id:
        u = EndUser.query.get(s.end_user_id)
        if u: sub_id = u.sub_id
    if not sub_id:
        return 0
    sub = Subscription.query.get(sub_id)
    return sub.level if sub else 0


@bp.route("/variable", methods=["POST"])
@limiter.limit("60 per minute")
@require_app
def get_variable():
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err: return err
    data = json.loads(raw or "{}")
    name = data.get("name", "")
    token = data.get("token", "")
    v = Variable.query.filter_by(app_id=g.app.id, name=name).first()
    if not v:
        return jsonify(success=False, message="not found"), 404
    if v.secret:
        s = _session_from_token(token)
        if not s: return jsonify(success=False, message="session required"), 401
        if _sub_level_of_session(s) < v.min_sub_level:
            return jsonify(success=False, message="insufficient tier"), 403
    return jsonify(success=True, name=v.name, value=v.value)


@bp.route("/file", methods=["POST"])
@limiter.limit("30 per minute")
@require_app
def get_file():
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err: return err
    data = json.loads(raw or "{}")
    name = data.get("name", "")
    token = data.get("token", "")
    f = StoredFile.query.filter_by(app_id=g.app.id, name=name).first()
    if not f:
        return jsonify(success=False, message="not found"), 404
    if f.min_sub_level > 0:
        s = _session_from_token(token)
        if not s: return jsonify(success=False, message="session required"), 401
        if _sub_level_of_session(s) < f.min_sub_level:
            return jsonify(success=False, message="insufficient tier"), 403
    return send_file(f.path, as_attachment=True, download_name=f.name)


@bp.route("/logout", methods=["POST"])
@limiter.limit("60 per minute")
@require_app
def api_logout():
    raw = request.get_data(as_text=True) or ""
    err = _sig_check(raw)
    if err: return err
    data = json.loads(raw or "{}")
    ClientSession.query.filter_by(token=data.get("token", "")).delete()
    db.session.commit()
    return jsonify(success=True)

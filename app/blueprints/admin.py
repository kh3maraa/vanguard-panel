import os
import time
from datetime import datetime, timezone
from flask import Blueprint, render_template, request, redirect, url_for, flash, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import func
from ..extensions import db
from ..models import (
    AdminUser, Application, License, EndUser, Subscription, HwidBinding,
    ClientSession, BlacklistEntry, Variable, StoredFile, Webhook, LogEntry,
    gen_secret, now_ts
)

bp = Blueprint("admin", __name__, url_prefix="/admin")


@bp.before_request
@login_required
def _guard():
    pass


def _rel_time(ts):
    if not ts:
        return "—"
    diff = now_ts() - ts
    if diff < 60: return "à l'instant"
    if diff < 3600: return f"il y a {diff // 60} min"
    if diff < 86400: return f"il y a {diff // 3600}h"
    return f"il y a {diff // 86400}j"


# ==================== DASHBOARD ====================
@bp.route("/")
def dashboard():
    ts = now_ts()

    apps = Application.query.order_by(Application.id.desc()).all()

    raw_recent = LogEntry.query.order_by(LogEntry.id.desc()).limit(10).all()
    recent = []
    for l in raw_recent:
        recent.append({
            "action": l.action,
            "identifier": l.identifier or "",
            "rel_time": _rel_time(l.ts),
        })

    raw_keys = (
        db.session.query(License, Application.name)
        .outerjoin(Application, Application.id == License.app_id)
        .order_by(License.id.desc()).limit(6).all()
    )
    latest_keys = []
    for lic, app_name in raw_keys:
        latest_keys.append({
            "id": lic.id,
            "key": lic.key,
            "app_name": app_name,
            "duration_days": lic.duration_days,
            "usage_count": lic.usage_count or 0,
            "banned": lic.banned,
            "activated_at": lic.activated_at,
            "expires_at": lic.expires_at,
        })

    return render_template(
        "dashboard.html",
        apps=apps,
        recent=recent,
        latest_keys=latest_keys,
        now_ts=ts,
        active="admin.dashboard",
    )


@bp.route("/apps")
def apps():
    all_apps = Application.query.order_by(Application.id.desc()).all()
    return render_template("apps.html", apps=all_apps)


@bp.route("/apps/new", methods=["POST"])
def app_new():
    name = request.form.get("name", "").strip()
    if not name:
        flash("Nom requis", "error"); return redirect(url_for("admin.apps"))
    if Application.query.filter_by(name=name).first():
        flash("Nom déjà pris", "error"); return redirect(url_for("admin.apps"))
    a = Application(name=name, owner_id=current_user.id)
    db.session.add(a); db.session.commit()
    flash(f"Application « {name} » créée", "success")
    return redirect(url_for("admin.app_detail", aid=a.id))


@bp.route("/apps/<int:aid>")
def app_detail(aid):
    a = Application.query.get_or_404(aid)
    return render_template("app_detail.html", app=a)


@bp.route("/apps/<int:aid>/update", methods=["POST"])
def app_update(aid):
    a = Application.query.get_or_404(aid)
    a.version = request.form.get("version", a.version)
    a.hwid_lock = "hwid_lock" in request.form
    a.integrity_check = "integrity_check" in request.form
    a.disabled = "disabled" in request.form
    a.disabled_message = request.form.get("disabled_message", a.disabled_message)
    a.update_message = request.form.get("update_message", "")
    a.download_url = request.form.get("download_url", "")
    db.session.commit()
    flash("Paramètres mis à jour", "success")
    return redirect(url_for("admin.app_detail", aid=aid))


@bp.route("/apps/<int:aid>/rotate", methods=["POST"])
def app_rotate(aid):
    a = Application.query.get_or_404(aid)
    a.api_secret = gen_secret()
    db.session.commit()
    flash("Secret régénéré", "success")
    return redirect(url_for("admin.app_detail", aid=aid))


@bp.route("/apps/<int:aid>/delete", methods=["POST"])
def app_delete(aid):
    a = Application.query.get_or_404(aid)
    db.session.delete(a); db.session.commit()
    return redirect(url_for("admin.apps"))


# ==================== LICENSES ====================
@bp.route("/licenses")
def licenses():
    aid = request.args.get("app", type=int)
    q = License.query
    if aid: q = q.filter_by(app_id=aid)
    all_lic = q.order_by(License.id.desc()).limit(500).all()
    apps = Application.query.all()
    return render_template("licenses.html", licenses=all_lic, apps=apps, filter_app=aid, now_ts=now_ts())


@bp.route("/licenses/generate", methods=["POST"])
def licenses_generate():
    if not request.form.get("app_id"):
        flash("Sélectionnez une application", "error")
        return redirect(url_for("admin.dashboard"))
    aid = int(request.form["app_id"])
    count = min(int(request.form.get("count", 1) or 1), 500)
    days = int(request.form.get("days", 30) or 30)
    max_hwids = int(request.form.get("max_hwids", 1) or 1)
    sub_id = request.form.get("sub_id", type=int)
    note = request.form.get("note", "")
    generated = []
    for _ in range(count):
        l = License(app_id=aid, sub_id=sub_id or None, duration_days=days,
                    max_hwids=max_hwids, note=note)
        db.session.add(l); generated.append(l)
    db.session.commit()
    return render_template(
        "licenses.html",
        licenses=License.query.filter_by(app_id=aid).order_by(License.id.desc()).limit(500).all(),
        apps=Application.query.all(), filter_app=aid,
        newly_generated=[l.key for l in generated], now_ts=now_ts()
    )


@bp.route("/licenses/<int:lid>/ban", methods=["POST"])
def license_ban(lid):
    l = License.query.get_or_404(lid)
    l.banned = not l.banned
    db.session.commit()
    return redirect(request.referrer or url_for("admin.licenses"))


@bp.route("/licenses/<int:lid>/reset_hwid", methods=["POST"])
def license_reset_hwid(lid):
    # Wipe HWID bindings AND active client sessions so le prochain /license
    # partira sur une base propre (sinon /session/check garde l'ancien HWID
    # en cache et le bouton n'a aucun effet visible cote client).
    HwidBinding.query.filter_by(license_id=lid).delete()
    ClientSession.query.filter_by(license_id=lid).delete()
    db.session.commit()
    add_log_id = lid
    try:
        add_log_app_id = License.query.get(lid).app_id if License.query.get(lid) else 0
    except Exception:
        add_log_app_id = 0
    try:
        from ..security import add_log, client_ip
        add_log(add_log_app_id, "hwid_reset_admin", client_ip(), "", str(lid))
    except Exception:
        pass
    flash("HWID + sessions reset.", "ok")
    return redirect(request.referrer or url_for("admin.licenses"))


@bp.route("/licenses/<int:lid>/delete", methods=["POST"])
def license_delete(lid):
    # Nettoyage explicite: bindings + sessions AVANT la license elle-meme.
    # Comme ca meme si le PRAGMA FK n'est pas actif, le HWID est libere.
    HwidBinding.query.filter_by(license_id=lid).delete()
    ClientSession.query.filter_by(license_id=lid).delete()
    License.query.filter_by(id=lid).delete()
    db.session.commit()
    flash("Cle supprimee. Son HWID est desormais libre.", "ok")
    return redirect(request.referrer or url_for("admin.licenses"))


# ==================== LIAISONS HWID ====================
@bp.route("/api-docs")
def api_docs():
    return render_template("api_docs.html")


# ==================== SETTINGS ====================
@bp.route("/settings")
def settings():
    admins = AdminUser.query.order_by(AdminUser.id).all()
    for a in admins:
        a.created_at = datetime.fromtimestamp(a.created_at, tz=timezone.utc).strftime("%d/%m/%Y")
    return render_template("settings.html", admins=admins)


@bp.route("/settings/password", methods=["POST"])
def settings_password():
    curr = request.form.get("current", "")
    new = request.form.get("new", "")
    new2 = request.form.get("new2", "")
    if not current_user.check_password(curr):
        flash("Mot de passe actuel incorrect", "error"); return redirect(url_for("admin.settings"))
    if len(new) < 8:
        flash("Nouveau mot de passe trop court (min 8)", "error"); return redirect(url_for("admin.settings"))
    if new != new2:
        flash("Les mots de passe ne correspondent pas", "error"); return redirect(url_for("admin.settings"))
    current_user.set_password(new)
    db.session.commit()
    flash("Mot de passe mis à jour", "success")
    return redirect(url_for("admin.settings"))


@bp.route("/settings/new-admin", methods=["POST"])
def settings_new_admin():
    u = request.form.get("username", "").strip()
    p = request.form.get("password", "")
    if len(u) < 3 or len(p) < 8:
        flash("Champs invalides", "error"); return redirect(url_for("admin.settings"))
    if AdminUser.query.filter_by(username=u).first():
        flash("Nom déjà pris", "error"); return redirect(url_for("admin.settings"))
    a = AdminUser(username=u); a.set_password(p)
    db.session.add(a); db.session.commit()
    flash(f"Admin « {u} » créé", "success")
    return redirect(url_for("admin.settings"))


@bp.route("/settings/admins/<int:aid>/delete", methods=["POST"])
def settings_delete_admin(aid):
    if aid == current_user.id:
        flash("Vous ne pouvez pas supprimer votre propre compte", "error")
        return redirect(url_for("admin.settings"))
    if AdminUser.query.count() <= 1:
        flash("Impossible de supprimer le dernier admin", "error")
        return redirect(url_for("admin.settings"))
    AdminUser.query.filter_by(id=aid).delete()
    db.session.commit()
    flash("Admin supprimé", "success")
    return redirect(url_for("admin.settings"))


# ==================== SUBSCRIPTIONS ====================
@bp.route("/subscriptions")
def subscriptions():
    subs = Subscription.query.order_by(Subscription.id.desc()).all()
    apps = Application.query.all()
    return render_template("subscriptions.html", subs=subs, apps=apps)


@bp.route("/subscriptions/new", methods=["POST"])
def sub_new():
    s = Subscription(
        app_id=int(request.form["app_id"]),
        name=request.form["name"],
        level=int(request.form.get("level", 1) or 1)
    )
    db.session.add(s); db.session.commit()
    return redirect(url_for("admin.subscriptions"))


@bp.route("/subscriptions/<int:sid>/delete", methods=["POST"])
def sub_delete(sid):
    Subscription.query.filter_by(id=sid).delete()
    db.session.commit()
    return redirect(url_for("admin.subscriptions"))


# ==================== END USERS ====================
@bp.route("/variables")
def variables():
    vs = Variable.query.order_by(Variable.id.desc()).all()
    apps = Application.query.all()
    return render_template("variables.html", vars=vs, apps=apps)


@bp.route("/variables/new", methods=["POST"])
def var_new():
    v = Variable(
        app_id=int(request.form["app_id"]),
        name=request.form["name"],
        value=request.form["value"],
        secret="secret" in request.form,
        min_sub_level=int(request.form.get("min_sub_level", 0) or 0)
    )
    db.session.add(v); db.session.commit()
    return redirect(url_for("admin.variables"))


@bp.route("/variables/<int:vid>/delete", methods=["POST"])
def var_delete(vid):
    Variable.query.filter_by(id=vid).delete()
    db.session.commit(); return redirect(url_for("admin.variables"))


# ==================== FILES ====================
@bp.route("/files")
def files():
    fs = StoredFile.query.order_by(StoredFile.id.desc()).all()
    apps = Application.query.all()
    return render_template("files.html", files=fs, apps=apps)


@bp.route("/files/upload", methods=["POST"])
def file_upload():
    aid = int(request.form["app_id"])
    f = request.files.get("file")
    if not f: return redirect(url_for("admin.files"))
    safe = secure_filename(f.filename)
    folder = os.path.join(current_app.config["FILES_DIR"], str(aid))
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, safe)
    f.save(path)
    sf = StoredFile(
        app_id=aid, name=safe, path=path, size=os.path.getsize(path),
        min_sub_level=int(request.form.get("min_sub_level", 0) or 0)
    )
    db.session.add(sf); db.session.commit()
    return redirect(url_for("admin.files"))


@bp.route("/files/<int:fid>/delete", methods=["POST"])
def file_delete(fid):
    sf = StoredFile.query.get_or_404(fid)
    try: os.remove(sf.path)
    except OSError: pass
    db.session.delete(sf); db.session.commit()
    return redirect(url_for("admin.files"))


# ==================== WEBHOOKS ====================
@bp.route("/webhooks")
def webhooks():
    hooks = Webhook.query.order_by(Webhook.id.desc()).all()
    apps = Application.query.all()
    return render_template("webhooks.html", hooks=hooks, apps=apps)


@bp.route("/webhooks/new", methods=["POST"])
def hook_new():
    h = Webhook(
        app_id=int(request.form["app_id"]),
        url=request.form["url"],
        events=request.form.get("events", "login,fail,ban")
    )
    db.session.add(h); db.session.commit()
    return redirect(url_for("admin.webhooks"))


@bp.route("/webhooks/<int:hid>/toggle", methods=["POST"])
def hook_toggle(hid):
    h = Webhook.query.get_or_404(hid); h.active = not h.active
    db.session.commit(); return redirect(url_for("admin.webhooks"))


@bp.route("/webhooks/<int:hid>/delete", methods=["POST"])
def hook_delete(hid):
    Webhook.query.filter_by(id=hid).delete()
    db.session.commit(); return redirect(url_for("admin.webhooks"))


# ==================== LOGS ====================
@bp.route("/logs")
def logs():
    aid = request.args.get("app", type=int)
    q = LogEntry.query
    if aid: q = q.filter_by(app_id=aid)
    raw = q.order_by(LogEntry.id.desc()).limit(500).all()
    for l in raw:
        l.ts = datetime.fromtimestamp(l.ts, tz=timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
    return render_template("logs.html",
        logs=raw, apps=Application.query.all(), filter_app=aid)

# ==================== LICENSE — DURATION EDIT ====================
@bp.route("/licenses/<int:lid>/set_duration", methods=["POST"])
def license_set_duration(lid):
    """Overwrite duration_days. If already activated, recompute expires_at from activated_at."""
    lic = License.query.get_or_404(lid)
    try:
        days = int(request.form.get("days", "0"))
    except ValueError:
        days = 0
    if days < 1:
        flash("Durée invalide", "error")
        return redirect(url_for("admin.licenses"))
    lic.duration_days = days
    if lic.activated_at:
        lic.expires_at = lic.activated_at + days * 86400
    db.session.commit()
    flash(f"Durée mise à jour: {days} jour(s).", "ok")
    return redirect(url_for("admin.licenses"))


@bp.route("/licenses/<int:lid>/add_time", methods=["POST"])
def license_add_time(lid):
    """Add N days. If activated, extend expires_at. Else extend duration_days."""
    lic = License.query.get_or_404(lid)
    try:
        days = int(request.form.get("days", "0"))
    except ValueError:
        days = 0
    if days < 1:
        flash("Nombre de jours invalide", "error")
        return redirect(url_for("admin.licenses"))
    if lic.activated_at and lic.expires_at:
        lic.expires_at = int(lic.expires_at) + days * 86400
    else:
        lic.duration_days = (lic.duration_days or 0) + days
    db.session.commit()
    flash(f"+{days} jour(s) ajouté(s) à la clé.", "ok")
    return redirect(url_for("admin.licenses"))


# ==================== LOGS — CLEAR ====================
@bp.route("/logs/clear", methods=["POST"])
def logs_clear():
    n = LogEntry.query.delete()
    db.session.commit()
    flash(f"{n} log(s) supprimé(s).", "ok")
    ref = request.referrer or url_for("admin.logs")
    return redirect(ref)

@bp.route("/apps/<int:aid>/purge_hwids", methods=["POST"])
def app_purge_hwids(aid):
    """Wipe TOUTES les bindings HWID + sessions client d'une app d'un coup.
    Utile pour repartir de zero apres beaucoup de tests."""
    lic_ids = [l.id for l in License.query.filter_by(app_id=aid).all()]
    n_binds = HwidBinding.query.filter(HwidBinding.license_id.in_(lic_ids)).delete(
        synchronize_session=False) if lic_ids else 0
    n_sess = ClientSession.query.filter_by(app_id=aid).delete(
        synchronize_session=False)
    db.session.commit()
    flash(f"Purge OK: {n_binds} HWID binding(s), {n_sess} session(s) supprime(s).", "ok")
    return redirect(request.referrer or url_for("admin.app_detail", aid=aid))

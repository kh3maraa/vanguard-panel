from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from ..models import AdminUser
from ..extensions import limiter, db

bp = Blueprint("auth", __name__, url_prefix="/auth")


@bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for("admin.dashboard"))
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        user = AdminUser.query.filter_by(username=u).first()
        if user and user.check_password(p):
            login_user(user, remember=False)
            return redirect(url_for("admin.dashboard"))
        flash("Identifiants invalides", "error")
    registration_open = AdminUser.query.count() == 0
    return render_template("login.html", registration_open=registration_open)


@bp.route("/register", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def register():
    # Bootstrap: seul le premier admin peut être créé via cette route
    if AdminUser.query.count() > 0:
        flash("Inscription fermée : un administrateur existe déjà.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        p2 = request.form.get("password2", "")
        if not u or len(u) < 3:
            flash("Nom d'utilisateur trop court (min 3).", "error")
            return render_template("register.html")
        if len(p) < 8:
            flash("Mot de passe trop court (min 8 caractères).", "error")
            return render_template("register.html")
        if p != p2:
            flash("Les mots de passe ne correspondent pas.", "error")
            return render_template("register.html")
        user = AdminUser(username=u)
        user.set_password(p)
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=False)
        flash("Compte administrateur créé. Bienvenue.", "success")
        return redirect(url_for("admin.dashboard"))

    return render_template("register.html")


@bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

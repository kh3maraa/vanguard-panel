from functools import wraps
from flask import request, jsonify, g
from .models import Application


def require_app(fn):
    @wraps(fn)
    def w(*a, **kw):
        name = request.headers.get("X-App-Name") or request.args.get("app")
        if not name:
            return jsonify(success=False, message="missing app"), 400
        app = Application.query.filter_by(name=name).first()
        if not app:
            return jsonify(success=False, message="unknown app"), 404
        if app.disabled:
            return jsonify(success=False, message=app.disabled_message), 403
        g.app = app
        return fn(*a, **kw)
    return w

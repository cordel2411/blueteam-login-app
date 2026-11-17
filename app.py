import os, sqlite3, logging, time
from datetime import timedelta
from functools import wraps
from flask import (Flask, request, session, redirect, url_for,
                   render_template, g)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.environ.get("DB_PATH", os.path.join(BASE, "users.db"))
LOG = os.environ.get("AUTH_LOG", os.path.join(BASE, "auth.log"))
MAX_FAILS, LOCK_SECONDS = 5, 15 * 60

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)  # behind Nginx
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],            # never hard-code
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "1") == "1",
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=20),
    MAX_CONTENT_LENGTH=16 * 1024,
)
CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app,
                  default_limits=["200 per hour"], storage_uri="memory://")
ph = PasswordHasher()
DUMMY_HASH = ph.hash("not-a-real-password")  # equalises timing for unknown users

logging.basicConfig(filename=LOG, level=logging.INFO,
                    format="%(asctime)s %(message)s")
log = logging.getLogger("auth")


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    d = g.pop("db", None)
    if d:
        d.close()


def login_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if "uid" not in session:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


@app.after_request
def headers(resp):
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'; base-uri 'self'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers.pop("Server", None)
    return resp


@app.route("/")
def index():
    return redirect(url_for("dashboard" if "uid" in session else "login"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("10 per minute", methods=["POST"])
def login():
    error = None
    if request.method == "POST":
        ip = get_remote_address()
        username = request.form.get("username", "").strip()[:64]
        password = request.form.get("password", "")[:128]
        now = int(time.time())
        row = db().execute(
            "SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        locked = bool(row and row["locked_until"] > now)
        ok = False
        try:
            ph.verify(row["pw_hash"] if row else DUMMY_HASH, password)
            ok = row is not None and not locked
        except (VerifyMismatchError, Exception):
            ok = False
        if ok:
            session.clear()                      # prevents session fixation
            session["uid"], session["user"] = row["id"], row["username"]
            session.permanent = True
            db().execute("UPDATE users SET failed=0, locked_until=0 WHERE id=?",
                         (row["id"],))
            db().commit()
            log.info("LOGIN_OK user=%r ip=%s", username, ip)
            return redirect(url_for("dashboard"))
        if row and not locked:
            fails = row["failed"] + 1
            until = now + LOCK_SECONDS if fails >= MAX_FAILS else 0
            db().execute("UPDATE users SET failed=?, locked_until=? WHERE id=?",
                         (0 if until else fails, until, row["id"]))
            db().commit()
        log.warning("LOGIN_FAIL user=%r ip=%s locked=%s", username, ip, locked)
        error = "Invalid username or password."  # same message every time
    return render_template("login.html", error=error)


@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=session["user"])


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.errorhandler(404)
def nf(_): return "Not found", 404


@app.errorhandler(429)
def rl(_): return "Too many requests. Slow down.", 429


@app.errorhandler(500)
def err(_): return "Server error", 500

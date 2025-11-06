import os, sqlite3
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, flash, redirect, request, session, url_for
from flask_session import Session
from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.routing import BuildError

app = Flask(__name__)
app.secret_key = "dev"

app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

basedir = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(basedir, "expense.db")
def _ensure_fresh_db(path):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        open(path, "a").close()
        return True
    try:
        con = sqlite3.connect(path)
        ok = con.execute("PRAGMA integrity_check").fetchone()[0]
        con.close()
        if ok != "ok":
            os.remove(path)             
            open(path, "a").close()    
            return True
    except Exception:
        if os.path.exists(path):
            os.remove(path)
        open(path, "a").close()
        return True
    return False

_ensure_fresh_db(DB_PATH)
db = SQL(f"sqlite:///{DB_PATH}")

def init_db():
    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            hash TEXT NOT NULL
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        )
    """)

    db.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            date TEXT NOT NULL,
            merchant TEXT NOT NULL,
            category_id INTEGER,
            amount REAL NOT NULL,
            note TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id),
            FOREIGN KEY(category_id) REFERENCES categories(id)
        )
    """)
    for nm in ("Food", "Transport", "Shopping", "Bills", "Entertainment", "Health", "Other"):
        db.execute("INSERT OR IGNORE INTO categories (name) VALUES (?)", nm)
with app.app_context():
    init_db()

@app.before_request
def hydrate_user_name():
    uid = session.get("user_id")
    if uid and not session.get("user_name"):
        r = db.execute("SELECT name FROM users WHERE id = ?", uid)
        if r:
            session["user_name"] = r[0]["name"]
def fetch_categories():
    return db.execute("SELECT id, name FROM categories ORDER BY name")


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session or not session["user_id"]:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated_function


def _go_home():
    """Safe redirect to your home page regardless of endpoint name."""
    try:
        return redirect(url_for("wlcm"))
    except BuildError:
        try:
            return redirect(url_for("home"))
        except BuildError:
            return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("wlcm"))
        return _go_home()

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""
        confirm  = request.form.get("confirm")  or ""

        # validation
        if not name or not email or not password or not confirm:
            return render_template("register.html", error="All fields are required.", prev={"name": name, "email": email})
            return render_template("register.html",
                                   error="All fields are required.",
                                   prev={"name": name, "email": email})
        if password != confirm:
            return render_template("register.html", error="Passwords do not match.", prev={"name": name, "email": email})

        try:
            hash_pw = generate_password_hash(password)
            db.execute(
                "INSERT INTO users (name, email, hash) VALUES (?, ?, ?)",
                name, email, hash_pw
            )
        except Exception:
            return render_template("register.html", error="Email already registered.", prev={"name": name, "email": email})

        row = db.execute("SELECT id FROM users WHERE email = ?", email)
        session["user_id"] = row[0]["id"]
        session["user_name"] = row[0]["name"]
        return redirect(url_for("wlcm"))
            return render_template("register.html",
                                   error="Passwords do not match.",
                                   prev={"name": name, "email": email})

        # unique email?
        if db.execute("SELECT 1 FROM users WHERE email = ?", email):
            return render_template("register.html",
                                   error="Email already registered. Please log in.",
                                   prev={"name": name, "email": email})

        # create user
        hash_pw = generate_password_hash(password)
        db.execute("INSERT INTO users (name, email, hash) VALUES (?, ?, ?)",
                   name, email, hash_pw)

        # fetch id & name, log them in
        row = db.execute("SELECT id, name FROM users WHERE email = ?", email)[0]
        session.clear()
        session["user_id"] = row["id"]
        session["user_name"] = row["name"]
        return _go_home()

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("wlcm"))
        return _go_home()

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            return render_template("login.html", error="Please fill out all fields.", prev={"email": email})
            return render_template("login.html",
                                   error="Please fill out all fields.",
                                   prev={"email": email})

        rows = db.execute("SELECT * FROM users WHERE email = ?", email)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return render_template("login.html", error="Invalid email or password.", prev={"email": email})
        rows = db.execute("SELECT id, name, hash FROM users WHERE email = ?", email)
        if not rows or not check_password_hash(rows[0]["hash"], password):
            return render_template("login.html",
                                   error="Invalid email or password.",
                                   prev={"email": email})

        session.clear()
        session["user_id"] = rows[0]["id"]
        return redirect(url_for("wlcm"))
        session["user_name"] = rows[0]["name"]
        return _go_home()

    return render_template("login.html")
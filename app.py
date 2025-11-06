import os
from datetime import datetime
from functools import wraps

from flask import Flask, render_template, flash, redirect, request, session, url_for
from flask_session import Session
from cs50 import SQL
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = "dev"

app.config["TEMPLATES_AUTO_RELOAD"] = True
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

basedir = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(basedir, "expense.db")
db = SQL(f"sqlite:///{DB_PATH}?check_same_thread=False")


@app.before_request
def ensure_schema():
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

    for nm in ("Food", "Transport", "Shopping", "Bills", "Entertainment", "Health", "Other"):
        db.execute("INSERT OR IGNORE INTO categories (name) VALUES (?)", nm)

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

@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("wlcm"))

    if request.method == "POST":
        name = (request.form.get("name") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if not name or not email or not password or not confirm:
            return render_template("register.html", error="All fields are required.", prev={"name": name, "email": email})
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

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("wlcm"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""

        if not email or not password:
            return render_template("login.html", error="Please fill out all fields.", prev={"email": email})

        rows = db.execute("SELECT * FROM users WHERE email = ?", email)
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], password):
            return render_template("login.html", error="Invalid email or password.", prev={"email": email})

        session["user_id"] = rows[0]["id"]
        return redirect(url_for("wlcm"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"], endpoint="wlcm")
@login_required
def dashboard():
    user_id = session["user_id"]

    if request.method == "POST":
        tb = request.form.get("total_balance", type=float)
        session["total_balance"] = tb if tb is not None else 0.0

    total_balance = float(session.get("total_balance", 0.0))

    total_spend = float(
        db.execute(
            "SELECT COALESCE(SUM(amount),0) AS s FROM transactions WHERE user_id = ?",
            user_id
        )[0]["s"] or 0.0
    )
    remaining = total_balance - total_spend
    percent_saved = (remaining / total_balance * 100.0) if total_balance > 0 else 0.0

    recent_rows = db.execute(
        """
        SELECT t.date,
               t.merchant,
               COALESCE(c.name, 'Uncategorized') AS category,
               t.amount
        FROM transactions t
        LEFT JOIN categories c ON c.id = t.category_id
        WHERE t.user_id = ?
        ORDER BY t.date DESC, t.id DESC
        LIMIT 10
        """,
        user_id
    )

    grouped_recent = {}
    for r in recent_rows:
        cat = r["category"]
        grouped_recent.setdefault(cat, []).append({
            "date": r["date"],
            "merchant": r["merchant"],
            "amount": float(r["amount"] or 0.0),
        })

    cat_rows = db.execute(
        """
        SELECT COALESCE(c.name, 'Uncategorized') AS category,
               COALESCE(SUM(t.amount), 0)       AS total
        FROM transactions t
        LEFT JOIN categories c ON c.id = t.category_id
        WHERE t.user_id = ?
        GROUP BY COALESCE(c.name, 'Uncategorized')
        ORDER BY total DESC
        """,
        user_id
    )

    total_sum = float(sum(r["total"] for r in cat_rows) or 1.0)
    slices, offset = [], 25
    cls_cycle = ["seg-1", "seg-2", "seg-3", "seg-4", "seg-5", "seg-6"]
    for i, r in enumerate(cat_rows):
        amt = float(r["total"] or 0.0)
        pct = (amt * 100.0) / total_sum
        slices.append({
            "label": r["category"],
            "amount": amt,
            "percent": pct,
            "dasharray": f"{pct:.0f} {100 - pct:.0f}",
            "offset": offset,
            "cls": f"donut-segment {cls_cycle[i % len(cls_cycle)]}",
        })
        offset += pct

    return render_template(
        "wlcm.html",
        total_balance=total_balance,
        total_spend=total_spend,
        remaining=remaining,
        percent_saved=percent_saved,
        recent=recent_rows,
        grouped_recent=grouped_recent,
        slices=slices
    )


@app.route("/transactions", methods=["GET", "POST"])
@login_required
def transactions():
    user_id = session["user_id"]

    if request.method == "POST":
        date_ = request.form.get("date") or datetime.now().strftime("%Y-%m-%d")
        merchant = (request.form.get("merchant") or "").strip()
        amount = request.form.get("amount", type=float)

        category_id = request.form.get("category_id", type=int)
        category_name = (request.form.get("category") or "").strip()

        if not merchant or amount is None or amount <= 0:
            flash("Please enter a merchant and a positive amount.")
            return redirect(url_for("transactions"))

        if not category_id and category_name:
            row = db.execute(
                "SELECT id FROM categories WHERE user_id = ? AND name = ?",
                user_id, category_name
            )
            if row:
                category_id = row[0]["id"]
            else:
                db.execute(
                    "INSERT INTO categories (user_id, name) VALUES (?, ?)",
                    user_id, category_name
                )
                category_id = db.execute(
                    "SELECT id FROM categories WHERE user_id = ? AND name = ?",
                    user_id, category_name
                )[0]["id"]

        db.execute(
            "INSERT INTO transactions (user_id, date, merchant, category_id, amount) VALUES (?, ?, ?, ?, ?)",
            user_id, date_, merchant, category_id, float(amount)
        )
        flash("Transaction added successfully!")
        return redirect(url_for("transactions"))

    txns = db.execute(
        """
        SELECT t.id, t.date, t.merchant,
               COALESCE(c.name, 'Uncategorized') AS category,
               t.amount
        FROM transactions t
        LEFT JOIN categories c ON c.id = t.category_id
        WHERE t.user_id = ?
        ORDER BY t.date DESC, t.id DESC
        """,
        user_id
    )

    categories_list = db.execute(
        "SELECT id, name FROM categories WHERE user_id = ? ORDER BY name",
        user_id
    )

    total_spend = float(
        db.execute("SELECT COALESCE(SUM(amount), 0) AS s FROM transactions WHERE user_id = ?", user_id)[0]["s"] or 0.0
    )
    total_balance = float(session.get("total_balance", 0.0))
    remaining = total_balance - total_spend
    percent_saved = (remaining / total_balance * 100.0) if total_balance > 0 else 0.0

    return render_template(
        "transactions.html",
        txns=txns,
        categories=categories_list,
        total_balance=total_balance,
        total_spend=total_spend,
        remaining=remaining,
        percent_saved=percent_saved
    )


def ensure_default_categories_for(user_id: int):
    have = db.execute("SELECT 1 FROM categories WHERE user_id = ? LIMIT 1", user_id)
    if not have:
        for nm in ("Food", "Transport", "Shopping", "Bills", "Entertainment", "Health", "Other"):
            db.execute("INSERT INTO categories (user_id, name) VALUES (?, ?)", user_id, nm)
def fetch_categories():
    return db.execute(
        "SELECT id, name FROM categories WHERE user_id = ? ORDER BY name",
        session.get("user_id", 1)
    )


@app.route("/categories")
@login_required
def categories():
    user_id = session["user_id"]

    rows = db.execute(
        """
        SELECT COALESCE(c.name, 'Uncategorized') AS category,
               COALESCE(SUM(t.amount), 0)        AS total,
               COUNT(t.id)                        AS count
        FROM categories c
        LEFT JOIN transactions t
               ON t.category_id = c.id AND t.user_id = ?
        GROUP BY COALESCE(c.name, 'Uncategorized')
        ORDER BY total DESC
        """,
        user_id
    )

    grand_total = float(sum(r["total"] for r in rows) or 0.0)
    top = rows[:5] 

    return render_template(
        "categories.html",
        rows=rows,
        top=top,
        grand_total=grand_total
    )




if __name__ == "__main__":
    app.debug = True
    app.config["PROPAGATE_EXCEPTIONS"] = True

    print("DB file path:", os.path.abspath("expense.db"))
    print(app.url_map)
    app.run(debug=True)


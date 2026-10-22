import os
import re
import secrets
import sqlite3

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signup.db")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
# Deliberately loose: just enough to catch typos, not a full RFC 5322 check.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = Flask(__name__)
# Set SECRET_KEY in the environment so sessions survive restarts.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL
            )
            """
        )
        # Add columns introduced after the first version of the schema, so
        # existing databases keep working without being recreated.
        columns = {row[1] for row in db.execute("PRAGMA table_info(users)")}
        for name, ddl in (
            ("full_name", "TEXT"),
            ("email", "TEXT COLLATE NOCASE"),
            ("created_at", "TEXT"),
        ):
            if name not in columns:
                db.execute(f"ALTER TABLE users ADD COLUMN {name} {ddl}")
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users (email)")


def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_db().execute(
        "SELECT id, username, full_name, email, created_at FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


@app.route("/")
def index():
    return render_template("index.html", user=current_user())


def validate_registration(form):
    """Return (values, errors) where errors maps field name to a message."""
    values = {
        "full_name": form.get("full_name", "").strip(),
        "email": form.get("email", "").strip(),
        "username": form.get("username", "").strip(),
    }
    password = form.get("password", "")
    confirm = form.get("confirm_password", "")
    errors = {}

    if not values["full_name"]:
        errors["full_name"] = "Please enter your name."
    elif len(values["full_name"]) > 100:
        errors["full_name"] = "Name must be 100 characters or fewer."

    if not values["email"]:
        errors["email"] = "Email is required."
    elif not EMAIL_RE.match(values["email"]):
        errors["email"] = "Enter a valid email address."

    if not values["username"]:
        errors["username"] = "Username is required."
    elif not USERNAME_RE.match(values["username"]):
        errors["username"] = "Use 3–30 letters, numbers, dots, dashes or underscores."

    if not password:
        errors["password"] = "Password is required."
    elif len(password) < 8:
        errors["password"] = "Password must be at least 8 characters."
    elif not (re.search(r"[A-Za-z]", password) and re.search(r"\d", password)):
        errors["password"] = "Password must include at least one letter and one number."

    if "password" not in errors and password != confirm:
        errors["confirm_password"] = "Passwords do not match."

    if not form.get("terms"):
        errors["terms"] = "You must agree to the terms to continue."

    db = get_db()
    if "username" not in errors and db.execute(
        "SELECT 1 FROM users WHERE username = ?", (values["username"],)
    ).fetchone():
        errors["username"] = "That username is already taken."
    if "email" not in errors and db.execute(
        "SELECT 1 FROM users WHERE email = ?", (values["email"],)
    ).fetchone():
        errors["email"] = "An account with this email already exists."

    return values, errors


@app.route("/register", methods=["GET", "POST"])
def register():
    if session.get("user_id"):
        return redirect(url_for("index"))

    values, errors = {}, {}
    if request.method == "POST":
        values, errors = validate_registration(request.form)

        if not errors:
            # generate_password_hash creates a random salt and stores it with
            # the hash as "method$salt$hash"; the plain password is never saved.
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, full_name, email, password_hash, created_at)"
                    " VALUES (?, ?, ?, ?, datetime('now'))",
                    (
                        values["username"],
                        values["full_name"],
                        values["email"],
                        generate_password_hash(request.form["password"]),
                    ),
                )
                db.commit()
            except sqlite3.IntegrityError:
                # Lost a race with another signup using the same name or email.
                errors["username"] = "That username or email is already in use."
            else:
                flash("Account created! Please log in.", "success")
                return redirect(url_for("login", username=values["username"]))

    return render_template("register.html", values=values, errors=errors)


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("index"))

    # Accept either a username or an email address as the login identifier.
    identifier = request.values.get("username", "").strip()
    if request.method == "POST":
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ? OR email = ?",
            (identifier, identifier),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.", "error")
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))

    return render_template("login.html", username=identifier)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)

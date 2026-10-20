import os
import secrets
import sqlite3

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signup.db")

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


def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    return get_db().execute("SELECT id, username FROM users WHERE id = ?", (user_id,)).fetchone()


@app.route("/")
def index():
    return render_template("index.html", user=current_user())


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        error = None
        if not username:
            error = "Username is required."
        elif not password:
            error = "Password is required."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."

        if error is None:
            # generate_password_hash creates a random salt and stores it with
            # the hash as "method$salt$hash"; the plain password is never saved.
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = f"Username {username!r} is already taken."
            else:
                flash("Account created. Please log in.")
                return redirect(url_for("login"))

        flash(error)

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username or password.")
        else:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.")
    return redirect(url_for("index"))


init_db()

if __name__ == "__main__":
    app.run(debug=True)

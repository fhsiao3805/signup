import os
import re
import secrets
import sqlite3
from datetime import date, datetime, time, timedelta

from flask import Flask, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signup.db")

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,30}$")
# Deliberately loose: just enough to catch typos, not a full RFC 5322 check.
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# Office hours run Monday to Friday, 2:00–4:00 pm, in half-hour slots.
SLOT_TIMES = [time(14, 0), time(14, 30), time(15, 0), time(15, 30)]
SLOT_LENGTH = timedelta(minutes=30)

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
        # The UNIQUE constraint is what stops two people booking the same slot.
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS bookings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users (id),
                slot_date TEXT NOT NULL,
                slot_time TEXT NOT NULL,
                created_at TEXT NOT NULL,
                UNIQUE (slot_date, slot_time)
            )
            """
        )


def current_user():
    user_id = session.get("user_id")
    if user_id is None:
        return None
    # The first person to register is the administrator.
    return get_db().execute(
        "SELECT id, username, full_name, email, created_at,"
        " id = (SELECT MIN(id) FROM users) AS is_admin"
        " FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()


def week_start(day):
    return day - timedelta(days=day.weekday())


def requested_week(value):
    """Return the Monday of the week to show, from a ?week=YYYY-MM-DD value."""
    try:
        return week_start(date.fromisoformat(value or ""))
    except ValueError:
        today = date.today()
        # On weekends this week's slots are over, so start with the next week.
        if today.weekday() >= 5:
            today += timedelta(days=7)
        return week_start(today)


def parse_slot(day_text, time_text):
    """Return the slot's start as a datetime, or None if it isn't a real slot."""
    try:
        day = date.fromisoformat(day_text or "")
    except ValueError:
        return None
    if day.weekday() >= 5:
        return None
    for slot_time in SLOT_TIMES:
        if slot_time.strftime("%H:%M") == time_text:
            return datetime.combine(day, slot_time)
    return None


def clock(t):
    return t.strftime("%I:%M").lstrip("0")


def build_week(user, monday):
    """Lay out the week's slots as the given user is allowed to see them."""
    days = [monday + timedelta(days=i) for i in range(5)]
    rows = get_db().execute(
        "SELECT b.id, b.user_id, b.slot_date, b.slot_time, u.full_name, u.username"
        " FROM bookings b JOIN users u ON u.id = b.user_id"
        " WHERE b.slot_date BETWEEN ? AND ?",
        (days[0].isoformat(), days[-1].isoformat()),
    )
    booked = {(row["slot_date"], row["slot_time"]): row for row in rows}
    now = datetime.now()

    week = []
    for day in days:
        slots = []
        for slot_time in SLOT_TIMES:
            key = slot_time.strftime("%H:%M")
            start = datetime.combine(day, slot_time)
            booking = booked.get((day.isoformat(), key))
            mine = booking is not None and booking["user_id"] == user["id"]
            slots.append({
                "date": day.isoformat(),
                "time": key,
                "label": f"{clock(start)} – {clock(start + SLOT_LENGTH)} pm",
                "past": start <= now,
                "taken": booking is not None,
                "mine": mine,
                "booking_id": booking["id"] if mine else None,
                # Only the administrator gets to know who booked a slot.
                "name": (booking["full_name"] or booking["username"])
                if booking is not None and user["is_admin"] else None,
            })
        week.append({"date": day, "today": day == now.date(), "slots": slots})
    return week


@app.route("/")
def index():
    user = current_user()
    if user is None:
        return render_template("index.html", user=None)

    monday = requested_week(request.args.get("week"))
    return render_template(
        "index.html",
        user=user,
        week=build_week(user, monday),
        monday=monday,
        prev_week=(monday - timedelta(days=7)).isoformat(),
        next_week=(monday + timedelta(days=7)).isoformat(),
        this_week=requested_week(None),
    )


@app.route("/book", methods=["POST"])
def book():
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    start = parse_slot(request.form.get("date"), request.form.get("time"))
    if start is None:
        flash("That isn't an office hours slot.", "error")
        return redirect(url_for("index"))

    if start <= datetime.now():
        flash("That slot has already started.", "error")
    else:
        try:
            db = get_db()
            db.execute(
                "INSERT INTO bookings (user_id, slot_date, slot_time, created_at)"
                " VALUES (?, ?, ?, datetime('now'))",
                (user["id"], start.date().isoformat(), start.strftime("%H:%M")),
            )
            db.commit()
        except sqlite3.IntegrityError:
            flash("Sorry, that slot has just been taken.", "error")
        else:
            flash(f"Booked {start:%A, %B} {start.day} at {clock(start)} pm.", "success")
    return redirect(url_for("index", week=week_start(start.date()).isoformat()))


@app.route("/bookings/<int:booking_id>/cancel", methods=["POST"])
def cancel_booking(booking_id):
    user = current_user()
    if user is None:
        return redirect(url_for("login"))

    db = get_db()
    # Matching on user_id means people can only cancel their own bookings.
    booking = db.execute(
        "SELECT slot_date, slot_time FROM bookings WHERE id = ? AND user_id = ?",
        (booking_id, user["id"]),
    ).fetchone()
    if booking is None:
        flash("That booking doesn't exist.", "error")
        return redirect(url_for("index"))

    start = parse_slot(booking["slot_date"], booking["slot_time"])
    if start <= datetime.now():
        flash("That slot has already started, so it can't be cancelled.", "error")
    else:
        db.execute("DELETE FROM bookings WHERE id = ?", (booking_id,))
        db.commit()
        flash(f"Cancelled your booking on {start:%A, %B} {start.day} at {clock(start)} pm.", "info")
    return redirect(url_for("index", week=week_start(start.date()).isoformat()))


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

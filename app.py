"""UniFlow local web prototype for the ICT project.

This is a small educational prototype using Flask + SQLite. It is designed for
local demonstration, not direct deployment to the public internet.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import base64
import ipaddress
from urllib.parse import urlparse
import hmac
import os
import secrets
import sqlite3
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo
from functools import wraps
from pathlib import Path
from typing import Callable, Optional

from flask import (
    Flask,
    abort,
    flash,
    g,
    redirect,
    render_template,
    request,
    session,
    Response,
    jsonify,
    send_from_directory,
    url_for,
)

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "uniflow.db"
PASSWORD_ITERATIONS = 200_000
ASTANA_TZ = ZoneInfo("Asia/Almaty")  # Kazakhstan (Astana), UTC+05.


def astana_now() -> datetime:
    """Use a stable campus timezone regardless of the visitor/server OS timezone."""
    return datetime.now(ASTANA_TZ)


def campus_booking_hours() -> tuple[int, int, frozenset[int]]:
    """Demo policy: Mon-Fri 09-18; adjust these env vars for lab-specific rules."""
    try:
        opening = int(os.getenv("UNIFLOW_OPEN_HOUR", "9"))
        closing = int(os.getenv("UNIFLOW_CLOSE_HOUR", "18"))
        days = frozenset(int(value.strip()) for value in os.getenv("UNIFLOW_BOOKING_DAYS", "0,1,2,3,4").split(","))
        if not 0 <= opening < closing <= 23 or not days or not days.issubset(set(range(7))):
            raise ValueError("Invalid booking calendar")
        return opening, closing, days
    except ValueError as error:
        raise RuntimeError("Invalid UniFlow opening-hour configuration") from error


def get_or_create_vapid_keys(storage_path: Path) -> tuple[str, str]:
    """Create one persistent P-256 VAPID private key in the ignored instance folder."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    storage_path.mkdir(parents=True, exist_ok=True)
    private_path = storage_path / "vapid_private.pem"
    if private_path.exists():
        private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    else:
        private = ec.generate_private_key(ec.SECP256R1())
        pem = private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        # This is a local dev prototype, not a multi-instance deployment.
        fd = os.open(str(private_path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(pem)
    key_bytes = private.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    public_key = base64.urlsafe_b64encode(key_bytes).decode("ascii").rstrip("=")
    return public_key, str(private_path)


def safe_push_endpoint(endpoint: str) -> bool:
    """Avoid using an arbitrary push URL as a server-side request target."""
    try:
        parsed = urlparse(endpoint)
        host = (parsed.hostname or "").lower()
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            return False
        allowed_push_domains = (
            host == "fcm.googleapis.com"
            or host == "updates.push.services.mozilla.com"
            or host.endswith(".notify.windows.com")
            or host == "web.push.apple.com"
            or host.endswith(".push.apple.com")
        )
        if not allowed_push_domains:
            return False
        try:
            ipaddress.ip_address(host)
            return False
        except ValueError:
            pass
        return len(endpoint) <= 2048
    except ValueError:
        return False



def hash_password(password: str) -> str:
    """Store password using PBKDF2-HMAC-SHA256 with a fresh random salt."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS
    )
    return f"pbkdf2_sha256${PASSWORD_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_value: str) -> bool:
    """Verify app hashes and the legacy salt:hash format from Assignment 3."""
    try:
        if stored_value.startswith("pbkdf2_sha256$"):
            algorithm, iterations_s, salt_hex, digest_hex = stored_value.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            iterations = int(iterations_s)
            if iterations < 100_000 or iterations > 2_000_000:
                return False
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, iterations
            )
            return hmac.compare_digest(actual, expected)

        # The original password_hash_demo.py stores: salt_hex:hash_hex
        if ":" in stored_value:
            salt_hex, digest_hex = stored_value.split(":", 1)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
            actual = hashlib.pbkdf2_hmac(
                "sha256", password.encode("utf-8"), salt, 100_000
            )
            return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False
    # Seed data such as "hash_001" is placeholder data, not a real password hash.
    return False


def create_app(database_path: Optional[str | Path] = None) -> Flask:
    app = Flask(__name__)
    app.config.update(
        DATABASE=str(database_path or os.environ.get("UNIFLOW_DB", DEFAULT_DB)),
        SECRET_KEY=os.environ.get("UNIFLOW_SECRET_KEY") or secrets.token_hex(32),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,  # Local HTTP demo only. Use HTTPS in deployment.
        MAX_CONTENT_LENGTH=1 * 1024 * 1024,
    )

    open_hour, close_hour, booking_days = campus_booking_hours()
    vapid_public_key, vapid_private_file = get_or_create_vapid_keys(BASE_DIR / "instance")
    app.config.update(
        BOOKING_OPEN_HOUR=open_hour,
        BOOKING_CLOSE_HOUR=close_hour,
        BOOKING_DAYS=booking_days,
        VAPID_PRIVATE_FILE=vapid_private_file,
        VAPID_PUBLIC_KEY=vapid_public_key,
    )

    def within_booking_hours(on_day: date, start_at, end_at) -> bool:
        return (on_day.weekday() in booking_days and
                start_at.minute == 0 and start_at.second == 0 and
                end_at.minute == 0 and end_at.second == 0 and
                open_hour <= start_at.hour < close_hour and
                open_hour < end_at.hour <= close_hour and
                end_at.hour == start_at.hour + 1)

    def get_db() -> sqlite3.Connection:
        if "db" not in g:
            db_path = Path(app.config["DATABASE"])
            if not db_path.exists():
                raise RuntimeError(
                    f"Database not found: {db_path}. Put uniflow.db next to app.py."
                )
            connection = sqlite3.connect(str(db_path), timeout=5)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys = ON")
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS Notifications (
                    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    body TEXT NOT NULL,
                    url TEXT NOT NULL,
                    is_read INTEGER NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES Users(user_id)
                );
                CREATE TABLE IF NOT EXISTS PushSubscriptions (
                    subscription_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    endpoint TEXT NOT NULL UNIQUE,
                    p256dh TEXT NOT NULL,
                    auth TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(user_id) REFERENCES Users(user_id)
                );
            """)
            g.db = connection
        return g.db

    @app.teardown_appcontext
    def close_db(_error=None) -> None:
        db = g.pop("db", None)
        if db is not None:
            db.close()

    @app.before_request
    def csrf_setup_and_check() -> None:
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        if request.method == "POST":
            submitted = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
            known = session.get("csrf_token", "")
            if not submitted or not known or not hmac.compare_digest(submitted, known):
                abort(400, description="Invalid form token. Refresh the page and try again.")

    @app.after_request
    def add_security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self'; img-src 'self' data:; "
            "script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'",
        )
        return response

    @app.context_processor
    def inject_template_helpers():
        return {
            "csrf_token": lambda: session.get("csrf_token", ""),
            "current_user": session.get("user"),
            "today_iso": astana_now().date().isoformat(),
            "now_time": astana_now().strftime("%H:%M"),
            "booking_hours": f"{open_hour:02d}:00–{close_hour:02d}:00",
            "booking_days_text": "Monday–Friday" if booking_days == frozenset(range(5)) else ", ".join(("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")[d] for d in sorted(booking_days)),
            "push_vapid_public_key": vapid_public_key,
        }

    def create_notification(db: sqlite3.Connection, user_id: int, title: str, body: str, link: str) -> None:
        db.execute(
            "INSERT INTO Notifications (user_id, title, body, url) VALUES (?, ?, ?, ?)",
            (user_id, title, body, link),
        )

    def notify_web_push(db: sqlite3.Connection, user_id: int, title: str, body: str, link: str) -> dict[str, object]:
        """Send Web Push and retain a safe diagnostic when a provider rejects a subscription."""
        subscribers = db.execute(
            "SELECT endpoint, p256dh, auth FROM PushSubscriptions WHERE user_id=? LIMIT 10",
            (user_id,),
        ).fetchall()
        result: dict[str, object] = {"subscribers": len(subscribers), "sent": 0, "failed": 0,
                                    "last_status": None, "last_error": ""}
        if not subscribers:
            return result
        try:
            from pywebpush import webpush, WebPushException
        except ImportError:
            app.logger.warning("pywebpush not installed; in-app notifications still work")
            result["failed"] = len(subscribers)
            return result
        payload = json.dumps({"title": title, "body": body, "url": link})
        for subscription in subscribers:
            try:
                webpush(
                    subscription_info={
                        "endpoint": subscription["endpoint"],
                        "keys": {"p256dh": subscription["p256dh"], "auth": subscription["auth"]},
                    },
                    data=payload,
                    vapid_private_key=app.config["VAPID_PRIVATE_FILE"],
                    vapid_claims={"sub": os.getenv("UNIFLOW_PUSH_CONTACT", "mailto:demo@example.org")},
                    ttl=60 * 60,
                    timeout=4,
                )
                result["sent"] += 1
            except WebPushException as error:
                result["failed"] += 1
                status = getattr(error, "status_code", None)
                response = getattr(error, "response", None)
                detail = (getattr(response, "text", "") or "").strip().replace("\n", " ")[:240]
                result["last_status"] = status
                result["last_error"] = detail
                if status in (401, 403, 404, 410):
                    # These subscriptions cannot be used with the current server key/auth.
                    db.execute("DELETE FROM PushSubscriptions WHERE endpoint=?", (subscription["endpoint"],))
                    db.commit()
                app.logger.warning("Could not send Web Push (HTTP %s): %s; provider response: %s",
                                   status, type(error).__name__, detail or "<empty>")
            except Exception as error:
                result["failed"] += 1
                app.logger.warning("Could not send Web Push: %s", type(error).__name__)
        return result

    def login_required(view: Callable):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not session.get("user"):
                flash("Please log in to continue.", "info")
                return redirect(url_for("login", next=request.path))
            return view(*args, **kwargs)
        return wrapped

    def admin_required(view: Callable):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = session.get("user")
            if not user:
                flash("Please log in with an administrator account.", "info")
                return redirect(url_for("login", next=request.path))
            if user.get("role") != "admin":
                abort(403)
            return view(*args, **kwargs)
        return wrapped

    @app.errorhandler(400)
    def bad_request(error):
        return render_template("error.html", code=400, message=getattr(error, "description", "Invalid request.")), 400

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You do not have permission to view this page."), 403

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("error.html", code=404, message="The page you requested was not found."), 404

    @app.route("/")
    def index():
        db = get_db()
        q = request.args.get("q", "").strip()[:100]
        category = request.args.get("category", "").strip()[:80]
        building = request.args.get("building", "").strip()[:80]
        status = request.args.get("status", "").strip()[:30]
        sql = "SELECT equipment_id, name, category, building, status FROM Equipment WHERE 1=1"
        params: list[str] = []
        if q:
            sql += " AND (name LIKE ? OR category LIKE ? OR building LIKE ?)"
            pattern = f"%{q}%"
            params.extend([pattern, pattern, pattern])
        if category:
            sql += " AND category = ?"
            params.append(category)
        if building:
            sql += " AND building = ?"
            params.append(building)
        if status in {"available", "in_use", "maintenance"}:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY CASE status WHEN 'available' THEN 0 ELSE 1 END, name"
        equipment = db.execute(sql, params).fetchall()
        categories = db.execute("SELECT DISTINCT category FROM Equipment ORDER BY category").fetchall()
        buildings = db.execute("SELECT DISTINCT building FROM Equipment ORDER BY building").fetchall()
        stats = {
            "equipment": db.execute("SELECT COUNT(*) FROM Equipment").fetchone()[0],
            "available": db.execute("SELECT COUNT(*) FROM Equipment WHERE status='available'").fetchone()[0],
            "reservations": db.execute("SELECT COUNT(*) FROM Reservations").fetchone()[0],
        }
        return render_template(
            "index.html", equipment=equipment, categories=categories, buildings=buildings,
            q=q, selected_category=category, selected_building=building,
            selected_status=status, stats=stats,
        )

    @app.get("/equipment/<int:equipment_id>/slots")
    @login_required
    def equipment_slots(equipment_id: int):
        """Display available one-hour slots for a selected date (local demo time)."""
        if session["user"]["role"] != "student":
            abort(403)
        db = get_db()
        equipment = db.execute(
            "SELECT equipment_id, name, category, building, status FROM Equipment WHERE equipment_id=?",
            (equipment_id,),
        ).fetchone()
        if equipment is None:
            abort(404)

        selected_date = request.args.get("date", astana_now().date().isoformat())
        try:
            selected = date.fromisoformat(selected_date)
        except ValueError:
            flash("Choose a valid date.", "error")
            return redirect(url_for("equipment_slots", equipment_id=equipment_id))
        if selected < astana_now().date():
            flash("Choose today or a future date.", "error")
            return redirect(url_for("equipment_slots", equipment_id=equipment_id))

        booked = db.execute(
            """SELECT start_time, end_time FROM Reservations
               WHERE equipment_id=? AND reservation_date=? AND status IN ('pending','approved')""",
            (equipment_id, selected.isoformat()),
        ).fetchall()
        slots = []
        for hour in range(open_hour, close_hour):
            start = f"{hour:02d}:00"
            end = f"{hour+1:02d}:00"
            future = datetime.combine(selected, datetime.strptime(start, "%H:%M").time(), tzinfo=ASTANA_TZ) > astana_now()
            free = equipment["status"] == "available" and selected.weekday() in booking_days and future and not any(
                r["start_time"] < end and r["end_time"] > start for r in booked
            )
            slots.append({"start": start, "end": end, "available": free})
        return render_template(
            "equipment_slots.html", equipment=equipment, slots=slots,
            selected_date=selected.isoformat(),
            selected_date_is_closed=selected.weekday() not in booking_days,
        )

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            name = request.form.get("full_name", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            if not name or len(name) > 100:
                flash("Enter your full name (maximum 100 characters).", "error")
            elif not email.endswith("@university.kz") or len(email) > 254:
                flash("Use your university email ending in @university.kz.", "error")
            elif len(password) < 8:
                flash("Password must contain at least 8 characters.", "error")
            elif password != confirm:
                flash("The passwords do not match.", "error")
            else:
                db = get_db()
                try:
                    cursor = db.execute(
                        "INSERT INTO Users (full_name, university_email, password_hash, role) VALUES (?, ?, ?, 'student')",
                        (name, email, hash_password(password)),
                    )
                    db.commit()
                    session.clear()
                    session["user"] = {
                        "user_id": cursor.lastrowid, "full_name": name,
                        "email": email, "role": "student",
                    }
                    session["csrf_token"] = secrets.token_urlsafe(32)
                    flash("Account created. Welcome to UniFlow!", "success")
                    return redirect(url_for("index"))
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash("An account with this university email already exists.", "error")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            row = get_db().execute(
                "SELECT user_id, full_name, university_email, password_hash, role FROM Users WHERE university_email = ?",
                (email,),
            ).fetchone()
            if row and verify_password(password, row["password_hash"]):
                session.clear()
                session["user"] = {
                    "user_id": row["user_id"], "full_name": row["full_name"],
                    "email": row["university_email"], "role": row["role"],
                }
                session["csrf_token"] = secrets.token_urlsafe(32)
                flash(f"Welcome back, {row['full_name']}!", "success")
                target = request.args.get("next", "")
                if target.startswith("/") and not target.startswith("//"):
                    return redirect(target)
                return redirect(url_for("admin_dashboard" if row["role"] == "admin" else "index"))
            flash("Email or password is incorrect. Seeded test users have placeholder passwords; create an account or configure an admin with setup_admin.py.", "error")
        return render_template("login.html")

    @app.post("/logout")
    @login_required
    def logout():
        # Stop sending private booking notifications to this browser after logout.
        if session.get("push_endpoint") and session.get("user"):
            db = get_db()
            db.execute("DELETE FROM PushSubscriptions WHERE endpoint=? AND user_id=?",
                       (session["push_endpoint"], session["user"]["user_id"]))
            db.commit()
        session.clear()
        flash("You have been logged out.", "info")
        return redirect(url_for("index"))

    @app.post("/reserve")
    @login_required
    def reserve():
        user = session["user"]
        if user["role"] != "student":
            abort(403)
        try:
            equipment_id = int(request.form.get("equipment_id", ""))
        except ValueError:
            flash("Choose valid equipment.", "error")
            return redirect(url_for("index"))
        reservation_date = request.form.get("reservation_date", "").strip()
        start_time = request.form.get("start_time", "").strip()
        end_time = request.form.get("end_time", "").strip()
        try:
            date_value = date.fromisoformat(reservation_date)
            start_value = datetime.strptime(start_time, "%H:%M").time()
            end_value = datetime.strptime(end_time, "%H:%M").time()
        except ValueError:
            flash("Enter a valid date and time.", "error")
            return redirect(url_for("index"))
        if date_value < astana_now().date():
            flash("The reservation date cannot be in the past.", "error")
            return redirect(url_for("index"))
        if datetime.combine(date_value, start_value, tzinfo=ASTANA_TZ) <= astana_now():
            flash("Choose a starting time in the future.", "error")
            return redirect(url_for("index"))
        if not within_booking_hours(date_value, start_value, end_value):
            flash(f"Bookings are allowed only on {', '.join(('Mon','Tue','Wed','Thu','Fri','Sat','Sun')[d] for d in sorted(booking_days))} between {open_hour:02d}:00 and {close_hour:02d}:00 (Astana time).", "error")
            return redirect(url_for("equipment_slots", equipment_id=equipment_id))
        if end_value <= start_value:
            flash("The end time must be later than the start time.", "error")
            return redirect(url_for("index"))

        db = get_db()
        equipment = db.execute(
            "SELECT equipment_id, status FROM Equipment WHERE equipment_id = ?", (equipment_id,)
        ).fetchone()
        if not equipment or equipment["status"] != "available":
            flash("That equipment is not currently available for booking.", "error")
            return redirect(url_for("index"))
        conflict = db.execute(
            """SELECT 1 FROM Reservations
               WHERE equipment_id = ? AND reservation_date = ?
                 AND status IN ('pending', 'approved')
                 AND start_time < ? AND end_time > ? LIMIT 1""",
            (equipment_id, reservation_date, end_time, start_time),
        ).fetchone()
        if conflict:
            flash("That time slot conflicts with an existing pending or approved reservation.", "error")
            return redirect(url_for("index"))
        cursor = db.execute(
            """INSERT INTO Reservations
               (user_id, equipment_id, reservation_date, start_time, end_time, status, admin_comment)
               VALUES (?, ?, ?, ?, ?, 'pending', NULL)""",
            (user["user_id"], equipment_id, reservation_date, start_time, end_time),
        )
        reservation_id = cursor.lastrowid
        create_notification(db, user["user_id"], "Booking request received",
                            f"Reservation #{reservation_id} is pending administrator approval.", url_for("my_reservations"))
        admin_ids = [r[0] for r in db.execute("SELECT user_id FROM Users WHERE role='admin'").fetchall()]
        for admin_id in admin_ids:
            create_notification(db, admin_id, "New booking request", f"Request #{reservation_id} needs review.", url_for("admin_dashboard"))
        db.commit()
        # Confirm the request to the student who submitted it, and alert opted-in admins.
        notify_web_push(db, user["user_id"], "UniFlow · Booking received",
                        f"Your booking #{reservation_id} is pending administrator approval.", url_for("my_reservations"))
        for admin_id in admin_ids:
            notify_web_push(db, admin_id, "UniFlow · New request", f"Booking #{reservation_id} needs review.", url_for("admin_dashboard"))
        flash(f"Reservation #{reservation_id} submitted for administrator approval.", "success")
        return redirect(url_for("my_reservations"))

    @app.route("/my-reservations")
    @login_required
    def my_reservations():
        rows = get_db().execute(
            """SELECT r.reservation_id, r.reservation_date, r.start_time, r.end_time,
                      r.status, r.admin_comment, e.name AS equipment_name, e.building
               FROM Reservations r JOIN Equipment e ON e.equipment_id = r.equipment_id
               WHERE r.user_id = ? ORDER BY r.reservation_date DESC, r.start_time DESC""",
            (session["user"]["user_id"],),
        ).fetchall()
        return render_template("my_reservations.html", reservations=rows)

    def can_cancel_reservation(reservation_date: str, start_time: str, status: str) -> bool:
        """A student may cancel pending or approved bookings before their start time."""
        if status not in {"pending", "approved"}:
            return False
        try:
            start_at = datetime.strptime(
                f"{reservation_date} {start_time}", "%Y-%m-%d %H:%M"
            )
        except (TypeError, ValueError):
            return False
        return start_at.replace(tzinfo=ASTANA_TZ) > astana_now()

    @app.get("/reservations/<int:reservation_id>/cancel/confirm")
    @login_required
    def confirm_cancel_reservation(reservation_id: int):
        if session["user"].get("role") != "student":
            abort(403)
        row = get_db().execute(
            """SELECT r.reservation_id, r.reservation_date, r.start_time, r.end_time,
                      r.status, e.name AS equipment_name
               FROM Reservations r JOIN Equipment e ON e.equipment_id=r.equipment_id
               WHERE r.reservation_id=? AND r.user_id=?""",
            (reservation_id, session["user"]["user_id"]),
        ).fetchone()
        if row is None:
            abort(404)
        if not can_cancel_reservation(row["reservation_date"], row["start_time"], row["status"]):
            flash("This reservation can no longer be cancelled.", "error")
            return redirect(url_for("my_reservations"))
        return render_template("cancel_confirm.html", reservation=row)

    @app.post("/reservations/<int:reservation_id>/cancel")
    @login_required
    def cancel_reservation(reservation_id: int):
        user = session["user"]
        if user.get("role") != "student":
            abort(403)
        db = get_db()
        row = db.execute(
            """SELECT reservation_date, start_time, status
               FROM Reservations WHERE reservation_id=? AND user_id=?""",
            (reservation_id, user["user_id"]),
        ).fetchone()
        if row and can_cancel_reservation(row["reservation_date"], row["start_time"], row["status"]):
            cursor = db.execute(
                """UPDATE Reservations SET status='cancelled'
                   WHERE reservation_id=? AND user_id=? AND status IN ('pending','approved')""",
                (reservation_id, user["user_id"]),
            )
            db.commit()
            if cursor.rowcount:
                create_notification(db, user["user_id"], "Booking cancelled", f"Reservation #{reservation_id} was cancelled.", url_for("my_reservations"))
                admin_ids = [r[0] for r in db.execute("SELECT user_id FROM Users WHERE role='admin'").fetchall()]
                for admin_id in admin_ids:
                    create_notification(db, admin_id, "Booking cancelled", f"Reservation #{reservation_id} was cancelled.", url_for("admin_dashboard"))
                db.commit()
                for admin_id in admin_ids:
                    notify_web_push(db, admin_id, "UniFlow · Cancellation", f"Booking #{reservation_id} was cancelled.", url_for("admin_dashboard"))
                flash(f"Reservation #{reservation_id} cancelled.", "success")
            else:
                flash("This reservation can no longer be cancelled.", "error")
        else:
            flash("Only your pending or approved reservations before their start time can be cancelled.", "error")
        return redirect(url_for("my_reservations"))

    @app.route("/admin", methods=["GET"])
    @admin_required
    def admin_dashboard():
        db = get_db()
        status_filter = request.args.get("status", "").strip()
        allowed_status = {"pending", "approved", "rejected", "cancelled"}
        sql = """SELECT r.reservation_id, r.reservation_date, r.start_time, r.end_time,
                        r.status, r.admin_comment, u.full_name, u.university_email,
                        e.name AS equipment_name, e.building
                 FROM Reservations r
                 JOIN Users u ON u.user_id = r.user_id
                 JOIN Equipment e ON e.equipment_id = r.equipment_id"""
        params: list[str] = []
        if status_filter in allowed_status:
            sql += " WHERE r.status = ?"
            params.append(status_filter)
        sql += " ORDER BY CASE r.status WHEN 'pending' THEN 0 ELSE 1 END, r.reservation_date DESC, r.start_time"
        reservations = db.execute(sql, params).fetchall()
        equipment = db.execute("SELECT * FROM Equipment ORDER BY name").fetchall()
        users = db.execute("SELECT user_id, full_name, university_email, role FROM Users ORDER BY full_name").fetchall()
        stats = {
            "pending": db.execute("SELECT COUNT(*) FROM Reservations WHERE status='pending'").fetchone()[0],
            "approved": db.execute("SELECT COUNT(*) FROM Reservations WHERE status='approved'").fetchone()[0],
            "equipment": len(equipment),
            "users": len(users),
            "reservations": db.execute("SELECT COUNT(*) FROM Reservations").fetchone()[0],
        }
        status_breakdown = db.execute(
            "SELECT status, COUNT(*) AS total FROM Reservations GROUP BY status ORDER BY status"
        ).fetchall()
        top_equipment = db.execute(
            """SELECT e.name, COUNT(r.reservation_id) AS request_count
               FROM Equipment e
               LEFT JOIN Reservations r ON r.equipment_id=e.equipment_id
               GROUP BY e.equipment_id, e.name
               ORDER BY request_count DESC, e.name ASC
               LIMIT 5"""
        ).fetchall()
        return render_template(
            "admin.html", reservations=reservations, equipment=equipment,
            users=users, stats=stats, status_filter=status_filter,
            status_breakdown=status_breakdown, top_equipment=top_equipment,
        )

    @app.get("/admin/reservations/export")
    @admin_required
    def export_reservations_csv():
        """Export reservation records; restricted to administrators."""
        status_filter = request.args.get("status", "").strip()
        allowed_status = {"pending", "approved", "rejected", "cancelled"}
        sql = """SELECT r.reservation_id, u.full_name, u.university_email,
                        e.name AS equipment_name, e.building, r.reservation_date,
                        r.start_time, r.end_time, r.status, r.admin_comment
                 FROM Reservations r
                 JOIN Users u ON u.user_id=r.user_id
                 JOIN Equipment e ON e.equipment_id=r.equipment_id"""
        params = []
        if status_filter in allowed_status:
            sql += " WHERE r.status=?"
            params.append(status_filter)
        sql += " ORDER BY r.reservation_date, r.start_time, r.reservation_id"
        rows = get_db().execute(sql, params).fetchall()

        output = io.StringIO(newline="")
        output.write("\ufeff")  # UTF-8 BOM helps spreadsheet applications detect Unicode.
        writer = csv.writer(output)
        writer.writerow([
            "Reservation ID", "Student Name", "University Email", "Equipment",
            "Building", "Reservation Date", "Start Time", "End Time", "Status", "Admin Comment",
        ])
        for row in rows:
            values = []
            for value in row:
                cell = "" if value is None else str(value)
                # Avoid formula execution if an imported value is opened in a spreadsheet.
                if cell.startswith(("=", "+", "-", "@", "\t", "\r")):
                    cell = "'" + cell
                values.append(cell)
            writer.writerow(values)

        filename = "uniflow_reservations.csv"
        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": f"attachment; filename={filename}"},
        )

    @app.get("/admin/reports/equipment-utilization.csv")
    @admin_required
    def export_equipment_utilization_csv():
        """Export an equipment-level utilisation summary for administrators."""
        rows = get_db().execute(
            """SELECT e.equipment_id, e.name, e.category, e.building, e.status,
                      COUNT(r.reservation_id) AS total_requests,
                      SUM(CASE WHEN r.status='approved' THEN 1 ELSE 0 END) AS approved_reservations,
                      SUM(CASE WHEN r.status='approved' THEN
                        (CAST(substr(r.end_time,1,2) AS INTEGER) * 60 + CAST(substr(r.end_time,4,2) AS INTEGER)) -
                        (CAST(substr(r.start_time,1,2) AS INTEGER) * 60 + CAST(substr(r.start_time,4,2) AS INTEGER))
                        ELSE 0 END) AS approved_minutes
               FROM Equipment e
               LEFT JOIN Reservations r ON r.equipment_id=e.equipment_id
               GROUP BY e.equipment_id, e.name, e.category, e.building, e.status
               ORDER BY total_requests DESC, e.name ASC"""
        ).fetchall()

        output = io.StringIO(newline="")
        output.write("\ufeff")
        writer = csv.writer(output)
        writer.writerow([
            "Equipment ID", "Equipment", "Category", "Building", "Equipment Status",
            "Total Reservation Requests", "Approved Reservations", "Approved Booked Hours",
        ])
        for row in rows:
            name = str(row[1] or "")
            if name.startswith(("=", "+", "-", "@", "\t", "\r")):
                name = "'" + name
            category = str(row[2] or "")
            building = str(row[3] or "")
            equipment_status = str(row[4] or "")
            for value_name, value in (("category", category), ("building", building), ("status", equipment_status)):
                if value.startswith(("=", "+", "-", "@", "\t", "\r")):
                    if value_name == "category": category = "'" + value
                    elif value_name == "building": building = "'" + value
                    else: equipment_status = "'" + value
            writer.writerow([
                row[0], name, category, building, equipment_status, row[5] or 0,
                row[6] or 0, f"{(row[7] or 0) / 60:.2f}",
            ])

        return Response(
            output.getvalue(),
            mimetype="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=uniflow_equipment_utilization.csv"},
        )

    @app.post("/admin/reservations/<int:reservation_id>")
    @admin_required
    def admin_update_reservation(reservation_id: int):
        action = request.form.get("action", "")
        comment = request.form.get("admin_comment", "").strip()[:300] or None
        if action not in {"approved", "rejected"}:
            abort(400, description="Choose approve or reject.")
        db = get_db()
        target = db.execute("SELECT user_id FROM Reservations WHERE reservation_id=? AND status='pending'", (reservation_id,)).fetchone()
        cursor = db.execute(
            "UPDATE Reservations SET status=?, admin_comment=? WHERE reservation_id=? AND status='pending'",
            (action, comment, reservation_id),
        )
        if cursor.rowcount and target:
            recipient = target["user_id"]
            title = "Reservation approved" if action == "approved" else "Reservation rejected"
            body = f"Your booking #{reservation_id} was {action}."
            create_notification(db, recipient, title, body, url_for("my_reservations"))
        db.commit()
        if cursor.rowcount:
            notify_web_push(db, recipient, "UniFlow · " + title, body, url_for("my_reservations"))
            flash(f"Reservation #{reservation_id} {action}.", "success")
        else:
            flash("This reservation no longer has pending status.", "error")
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/equipment")
    @admin_required
    def admin_add_equipment():
        name = request.form.get("name", "").strip()[:100]
        category = request.form.get("category", "").strip()[:80]
        building = request.form.get("building", "").strip()[:80]
        status = request.form.get("status", "available")
        if not name or not category or not building:
            flash("Name, category and building are required.", "error")
        elif status not in {"available", "in_use", "maintenance"}:
            abort(400, description="Invalid equipment status.")
        else:
            db = get_db()
            db.execute(
                "INSERT INTO Equipment (name, category, building, status) VALUES (?, ?, ?, ?)",
                (name, category, building, status),
            )
            db.commit()
            flash("Equipment added successfully.", "success")
        return redirect(url_for("admin_dashboard"))

    @app.post("/admin/equipment/<int:equipment_id>/edit")
    @admin_required
    def admin_edit_equipment(equipment_id: int):
        name = request.form.get("name", "").strip()
        category = request.form.get("category", "").strip()
        building = request.form.get("building", "").strip()
        status = request.form.get("status", "")
        if not all((name, category, building)) or len(name) > 100 or len(category) > 80 or len(building) > 80:
            flash("Enter a name, category and building within the allowed lengths.", "error")
            return redirect(url_for("admin_dashboard") + "#manage-equipment")
        if status not in {"available", "in_use", "maintenance"}:
            abort(400, description="Invalid equipment status.")
        db = get_db()
        cursor = db.execute(
            "UPDATE Equipment SET name=?, category=?, building=?, status=? WHERE equipment_id=?",
            (name, category, building, status, equipment_id),
        )
        db.commit()
        flash("Equipment details updated." if cursor.rowcount else "Equipment was not found.",
              "success" if cursor.rowcount else "error")
        return redirect(url_for("admin_dashboard") + "#manage-equipment")

    @app.post("/admin/equipment/<int:equipment_id>/status")
    @admin_required
    def admin_update_equipment_status(equipment_id: int):
        status = request.form.get("status", "")
        if status not in {"available", "in_use", "maintenance"}:
            abort(400, description="Invalid equipment status.")
        db = get_db()
        cursor = db.execute("UPDATE Equipment SET status=? WHERE equipment_id=?", (status, equipment_id))
        db.commit()
        if cursor.rowcount:
            flash("Equipment status updated.", "success")
        else:
            flash("Equipment was not found.", "error")
        return redirect(url_for("admin_dashboard"))

    @app.get("/api/notifications")
    @login_required
    def api_notifications():
        user_id = session["user"]["user_id"]
        db = get_db()
        rows = db.execute(
            "SELECT notification_id, title, body, url, is_read, created_at FROM Notifications "
            "WHERE user_id=? ORDER BY notification_id DESC LIMIT 25", (user_id,)
        ).fetchall()
        unread = db.execute("SELECT COUNT(*) FROM Notifications WHERE user_id=? AND is_read=0", (user_id,)).fetchone()[0]
        response = jsonify({"notifications": [dict(r) for r in rows], "unread": unread})
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.post("/api/notifications/read")
    @login_required
    def mark_notifications_read():
        db = get_db()
        db.execute("UPDATE Notifications SET is_read=1 WHERE user_id=?", (session["user"]["user_id"],))
        db.commit()
        return jsonify({"ok": True})

    @app.get("/sw.js")
    def service_worker():
        response = send_from_directory(app.static_folder, "sw.js", mimetype="application/javascript")
        response.headers["Service-Worker-Allowed"] = "/"
        response.headers["Cache-Control"] = "no-cache"
        return response

    @app.post("/api/push/subscribe")
    @login_required
    def subscribe_web_push():
        data = request.get_json(silent=True)
        if not isinstance(data, dict):
            abort(400, description="Invalid push subscription")
        endpoint = data.get("endpoint", "")
        keys = data.get("keys", {})
        if not isinstance(endpoint, str) or not isinstance(keys, dict):
            abort(400, description="Invalid subscription payload")
        p256dh, auth = keys.get("p256dh", ""), keys.get("auth", "")
        if not (safe_push_endpoint(endpoint) and isinstance(p256dh, str)
                and isinstance(auth, str) and 20 <= len(p256dh) <= 200 and 8 <= len(auth) <= 100):
            abort(400, description="Invalid push endpoint or keys")
        db = get_db()
        db.execute(
            "INSERT INTO PushSubscriptions(user_id, endpoint, p256dh, auth) VALUES(?,?,?,?) "
            "ON CONFLICT(endpoint) DO UPDATE SET user_id=excluded.user_id, p256dh=excluded.p256dh, auth=excluded.auth",
            (session["user"]["user_id"], endpoint, p256dh, auth),
        )
        db.commit()
        session["push_endpoint"] = endpoint
        return jsonify({"ok": True})

    @app.post("/api/push/test")
    @login_required
    def test_web_push():
        user_id = session["user"]["user_id"]
        result = notify_web_push(
            get_db(), user_id, "UniFlow · Test notification",
            "Web Push is connected to this browser and account.", url_for("my_reservations")
        )
        if result["subscribers"] == 0:
            return jsonify({"ok": False, "error": "No Push subscription is saved for this account. Enable Push first."}), 409
        if result["sent"] == 0:
            status = result.get("last_status")
            message = "The push service rejected this subscription."
            if status in (401, 403):
                message = "The push service rejected the VAPID authentication or an old browser subscription."
            return jsonify({"ok": False, "error": message,
                            "detail": result.get("last_error", ""),
                            "renew": status in (401, 403, 404, 410)}), 502
        return jsonify({"ok": True, **result})

    @app.post("/api/push/unsubscribe")
    @login_required
    def unsubscribe_web_push():
        data = request.get_json(silent=True) or {}
        endpoint = data.get("endpoint", "")
        if not isinstance(endpoint, str) or len(endpoint) > 2048:
            abort(400, description="Invalid endpoint")
        db = get_db()
        db.execute("DELETE FROM PushSubscriptions WHERE endpoint=? AND user_id=?", (endpoint, session["user"]["user_id"]))
        db.commit()
        if session.get("push_endpoint") == endpoint:
            session.pop("push_endpoint", None)
        return jsonify({"ok": True})

    return app


app = create_app()

if __name__ == "__main__":
    # For local classroom use. Do not expose this development server publicly.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)

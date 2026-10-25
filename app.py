from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    flash,
    request
)

import os
import tempfile
import sqlite3
import pandas as pd
import subprocess
import sys

from pathlib import Path


# ==========================================
# APPLICATION CONFIGURATION
# ==========================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY",
    "cybersecurity-demo-secret-key"
)

BASE_DIR = Path(__file__).resolve().parent

DATABASE = BASE_DIR / "security.db"
LOG_FILE = BASE_DIR / "security_logs.csv"
ALERTS_FILE = BASE_DIR / "alerts.csv"
DETECTOR_FILE = BASE_DIR / "detector.py"


REQUIRED_COLUMNS = {
    "timestamp",
    "username",
    "ip_address",
    "event_type",
    "status",
    "resource"
}


ALERT_COLUMNS = [
    "username",
    "ip_address",
    "failed_logins",
    "denied_access",
    "risk_score",
    "severity",
    "reason"
]


ALLOWED_SEVERITIES = {
    "Low",
    "Medium",
    "High",
    "Critical"
}


ALLOWED_STATUSES = {
    "Open",
    "Investigating",
    "Resolved"
}


# Number of events in the latest analyzed dataset.
# This resets when the Flask application restarts.

latest_event_count = None


# ==========================================
# DATABASE CONNECTION
# ==========================================

def get_db_connection():

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    return connection


# ==========================================
# DATABASE INITIALIZATION AND MIGRATION
# ==========================================

def initialize_database():

    connection = get_db_connection()

    try:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                username TEXT NOT NULL,

                ip_address TEXT,

                failed_logins INTEGER DEFAULT 0,

                denied_access INTEGER DEFAULT 0,

                risk_score INTEGER DEFAULT 0,

                severity TEXT,

                reason TEXT,

                status TEXT DEFAULT 'Open',

                detected_at TEXT

            )
        """)

        # Check existing database columns.
        # This allows older databases to be upgraded safely.

        existing_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(alerts)"
            ).fetchall()
        }

        if "detected_at" not in existing_columns:

            connection.execute("""
                ALTER TABLE alerts
                ADD COLUMN detected_at TEXT
            """)

        if "status" not in existing_columns:

            connection.execute("""
                ALTER TABLE alerts
                ADD COLUMN status TEXT DEFAULT 'Open'
            """)

        connection.commit()

    finally:

        connection.close()


# ==========================================
# IMPORT ALERTS WITHOUT DELETING HISTORY
# ==========================================

def import_alerts():

    if not ALERTS_FILE.exists():

        raise RuntimeError(
            "The detector did not create alerts.csv."
        )

    alerts = pd.read_csv(ALERTS_FILE)

    if not set(ALERT_COLUMNS).issubset(alerts.columns):

        raise RuntimeError(
            "The detector produced an invalid alerts.csv file."
        )

    connection = get_db_connection()

    inserted_count = 0

    try:

        for _, alert in alerts.iterrows():

            username = str(alert["username"])

            ip_address = str(alert["ip_address"])

            failed_logins = int(alert["failed_logins"])

            denied_access = int(alert["denied_access"])

            risk_score = int(alert["risk_score"])

            severity = str(alert["severity"])

            reason = str(alert["reason"])

            # Avoid importing the same alert repeatedly.
            # Existing statuses and timestamps are preserved.

            existing_alert = connection.execute("""
                SELECT id
                FROM alerts
                WHERE username = ?
                  AND ip_address = ?
                  AND failed_logins = ?
                  AND denied_access = ?
                  AND risk_score = ?
                  AND severity = ?
                  AND reason = ?
                LIMIT 1
            """, (
                username,
                ip_address,
                failed_logins,
                denied_access,
                risk_score,
                severity,
                reason
            )).fetchone()

            if existing_alert:

                continue

            detected_at = pd.Timestamp.now(
                tz="UTC"
            ).isoformat(timespec="seconds")

            connection.execute("""
                INSERT INTO alerts (
                    username,
                    ip_address,
                    failed_logins,
                    denied_access,
                    risk_score,
                    severity,
                    reason,
                    status,
                    detected_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, 'Open', ?)
            """, (
                username,
                ip_address,
                failed_logins,
                denied_access,
                risk_score,
                severity,
                reason,
                detected_at
            ))

            inserted_count += 1

        connection.commit()

        return inserted_count

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# ==========================================
# VALIDATE CSV FILES
# ==========================================

def validate_csv(file_path):

    try:

        logs = pd.read_csv(file_path)

    except (
        pd.errors.EmptyDataError,
        pd.errors.ParserError,
        UnicodeDecodeError
    ):

        return (
            False,
            "The uploaded file is not a readable CSV."
        )

    if not REQUIRED_COLUMNS.issubset(logs.columns):

        missing = sorted(
            REQUIRED_COLUMNS - set(logs.columns)
        )

        return (
            False,
            "Missing required columns: "
            + ", ".join(missing)
        )

    if logs.empty:

        return (
            False,
            "The uploaded CSV contains no security events."
        )

    if (
        logs["username"]
        .fillna("")
        .astype(str)
        .str.strip()
        .eq("")
        .any()
    ):

        return (
            False,
            "Every event must have a username."
        )

    return True, logs


# ==========================================
# RUN THREAT DETECTION
# ==========================================

def run_detection(file_path):

    global latest_event_count

    if not DETECTOR_FILE.exists():

        return False, "detector.py was not found."

    try:

        # Validate the input CSV first.

        valid, result = validate_csv(file_path)

        if not valid:

            return False, result

        logs = result

        # Run detector.py using the same Python environment
        # that is running the Flask application.

        process_code = (
            "import sys; "
            "from pathlib import Path; "
            f"sys.path.insert(0, {str(BASE_DIR)!r}); "
            "from detector import analyze_logs; "
            f"success = analyze_logs({str(file_path)!r}); "
            "sys.exit(0 if success else 1)"
        )

        process = subprocess.run(
            [sys.executable, "-c", process_code],
            cwd=str(BASE_DIR),
            capture_output=True,
            text=True,
            timeout=30
        )

        if process.returncode != 0:

            error_message = (
                process.stderr.strip()
                or process.stdout.strip()
            )

            if not error_message:

                error_message = (
                    "Please check the uploaded CSV and detector.py."
                )

            return (
                False,
                "Detection failed. "
                + error_message[-700:]
            )

        if not ALERTS_FILE.exists():

            return (
                False,
                "The detector did not produce alerts.csv."
            )

        # Import new findings without deleting old alerts.

        new_alert_count = import_alerts()

        latest_event_count = len(logs)

        return True, (
            f"Analysis completed successfully. "
            f"Processed {latest_event_count} security events. "
            f"Added {new_alert_count} new alerts."
        )

    except subprocess.TimeoutExpired:

        return (
            False,
            "Analysis took too long. Please try a smaller CSV file."
        )

    except Exception as error:

        app.logger.exception(
            "Security log analysis failed"
        )

        return False, f"Analysis failed: {error}"


# ==========================================
# DASHBOARD
# ==========================================

@app.route("/")
def dashboard():

    # Read the current search and filter values.

    search_username = request.args.get(
        "username", ""
    ).strip()

    selected_severity = request.args.get(
        "severity", ""
    ).strip().title()

    selected_status = request.args.get(
        "status", ""
    ).strip().title()

    # Support the shorter "Investigate" spelling too.

    if selected_status == "Investigate":

        selected_status = "Investigating"

    if selected_severity not in ALLOWED_SEVERITIES:

        selected_severity = ""

    if selected_status not in ALLOWED_STATUSES:

        selected_status = ""

    connection = get_db_connection()

    try:

        # Total alerts.

        total_alerts = connection.execute("""
            SELECT COUNT(*)
            FROM alerts
        """).fetchone()[0]

        # High and critical alerts.

        high_risk = connection.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE severity IN ('High', 'Critical')
        """).fetchone()[0]

        # Alerts still open.

        open_alerts = connection.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'Open'
        """).fetchone()[0]

        # Alerts resolved by the administrator.

        resolved_alerts = connection.execute("""
            SELECT COUNT(*)
            FROM alerts
            WHERE status = 'Resolved'
        """).fetchone()[0]

        # Severity chart data.

        severity_counts = connection.execute("""
            SELECT severity, COUNT(*) AS total
            FROM alerts
            GROUP BY severity
        """).fetchall()

        severity_order = [
            "Critical",
            "High",
            "Medium",
            "Low"
        ]

        severity_totals = {
            row["severity"]: row["total"]
            for row in severity_counts
        }

        severity_labels = [
            severity
            for severity in severity_order
            if severity_totals.get(severity, 0) > 0
        ]

        severity_values = [
            severity_totals[severity]
            for severity in severity_labels
        ]

        # Build the alert table query using SQL parameters.

        query = "SELECT * FROM alerts WHERE 1=1"

        parameters = []

        if search_username:

            query += " AND username LIKE ? COLLATE NOCASE"

            parameters.append(
                f"%{search_username}%"
            )

        if selected_severity:

            query += " AND severity = ?"

            parameters.append(
                selected_severity
            )

        if selected_status:

            query += " AND status = ?"

            parameters.append(
                selected_status
            )

        query += " ORDER BY risk_score DESC, id DESC"

        alerts = connection.execute(
            query,
            parameters
        ).fetchall()

    finally:

        connection.close()

    # Calculate the event count.

    if latest_event_count is not None:

        total_events = latest_event_count

    elif LOG_FILE.exists():

        try:

            total_events = len(
                pd.read_csv(LOG_FILE)
            )

        except (
            pd.errors.EmptyDataError,
            pd.errors.ParserError,
            UnicodeDecodeError
        ):

            total_events = 0

    else:

        total_events = 0

    return render_template(
        "index.html",

        total_events=total_events,

        total_alerts=total_alerts,

        high_risk=high_risk,

        open_alerts=open_alerts,

        resolved_alerts=resolved_alerts,

        alerts=alerts,

        severity_labels=severity_labels,

        severity_values=severity_values,

        search_username=search_username,

        selected_severity=selected_severity,

        selected_status=selected_status
    )


# ==========================================
# ANALYZE THE DEFAULT SECURITY LOG FILE
# ==========================================

@app.route("/analyze", methods=["POST"])
def analyze():

    if not LOG_FILE.exists():

        flash(
            "security_logs.csv was not found.",
            "error"
        )

        return redirect(url_for("dashboard"))

    success, message = run_detection(LOG_FILE)

    flash(
        message,
        "success" if success else "error"
    )

    return redirect(url_for("dashboard"))


# ==========================================
# UPLOAD AND ANALYZE A CSV FILE
# ==========================================

@app.route("/upload", methods=["POST"])
def upload_csv():

    uploaded_file = request.files.get("csv_file")

    if (
        uploaded_file is None
        or not uploaded_file.filename
    ):

        flash(
            "Please choose a CSV file first.",
            "error"
        )

        return redirect(url_for("dashboard"))

    if (
        Path(uploaded_file.filename).suffix.lower()
        != ".csv"
    ):

        flash(
            "Please upload a file with a .csv extension.",
            "error"
        )

        return redirect(url_for("dashboard"))

    temporary_path = None

    try:

        # Save the uploaded file temporarily.

        with tempfile.NamedTemporaryFile(
            mode="wb",
            suffix=".csv",
            prefix="cybershield_upload_",
            delete=False
        ) as temporary_file:

            temporary_path = Path(
                temporary_file.name
            )

            uploaded_file.save(temporary_file)

        success, message = run_detection(
            temporary_path
        )

        flash(
            message,
            "success" if success else "error"
        )

    except Exception:

        app.logger.exception(
            "CSV upload failed"
        )

        flash(
            "The uploaded CSV could not be processed.",
            "error"
        )

    finally:

        # Remove the temporary uploaded file.
        # The database and alert history are not deleted.

        if (
            temporary_path is not None
            and temporary_path.exists()
        ):

            temporary_path.unlink()

    return redirect(url_for("dashboard"))


# ==========================================
# UPDATE ALERT STATUS
# ==========================================

@app.route(
    "/update-status/<int:alert_id>/<status>",
    methods=["POST"]
)
def update_status(alert_id, status):

    # Normalize status spelling.

    status = status.strip().title()

    if status == "Investigate":

        status = "Investigating"

    if status not in ALLOWED_STATUSES:

        flash(
            "Invalid alert status.",
            "error"
        )

        return redirect(url_for("dashboard"))

    connection = get_db_connection()

    try:

        result = connection.execute("""
            UPDATE alerts
            SET status = ?
            WHERE id = ?
        """, (
            status,
            alert_id
        ))

        connection.commit()

        if result.rowcount == 0:

            flash(
                "Alert not found.",
                "error"
            )

            return redirect(url_for("dashboard"))

    except Exception:

        connection.rollback()

        app.logger.exception(
            "Alert status update failed"
        )

        flash(
            "Could not update the alert status.",
            "error"
        )

        return redirect(url_for("dashboard"))

    finally:

        connection.close()

    flash(
        f"Alert status updated to {status}.",
        "success"
    )

    return redirect(url_for("dashboard"))


# ==========================================
# INITIALIZE DATABASE
# ==========================================

initialize_database()


# ==========================================
# START FLASK APPLICATION
# ==========================================

if __name__ == "__main__":

    app.run(debug=True)
import pandas as pd
from collections import Counter
from pathlib import Path

# Detection thresholds
FAILED_LOGIN_THRESHOLD = 4
HIGH_FAILED_LOGIN_THRESHOLD = 10
DENIED_ACCESS_THRESHOLD = 2

# Risk score weights
MEDIUM_LOGIN_SCORE = 40
HIGH_LOGIN_SCORE = 70
DENIED_ACCESS_SCORE = 30

BASE_DIR = Path(__file__).resolve().parent
ALERTS_FILE = BASE_DIR / "alerts.csv"

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


def calculate_risk_score(failed_logins, denied_access):
    """Calculate a risk score using explainable detection rules."""

    score = 0

    if failed_logins >= HIGH_FAILED_LOGIN_THRESHOLD:
        score += HIGH_LOGIN_SCORE
    elif failed_logins >= FAILED_LOGIN_THRESHOLD:
        score += MEDIUM_LOGIN_SCORE

    if denied_access >= DENIED_ACCESS_THRESHOLD:
        score += DENIED_ACCESS_SCORE

    return min(score, 100)


def classify_risk(score):
    """Convert the numeric score into a severity level."""

    if score >= 80:
        return "Critical"
    elif score >= 60:
        return "High"
    elif score >= 30:
        return "Medium"
    else:
        return "Low"


def analyze_logs(file_name):
    """Analyze security logs and save detected alerts to alerts.csv."""

    try:
        logs = pd.read_csv(file_name)
    except (
        FileNotFoundError,
        pd.errors.EmptyDataError,
        pd.errors.ParserError,
        PermissionError,
        OSError
    ) as error:
        print(f"Error reading security logs: {error}")
        return False

    # Check required CSV columns.
    if not REQUIRED_COLUMNS.issubset(logs.columns):
        missing = sorted(REQUIRED_COLUMNS - set(logs.columns))
        print("Error: Missing required columns:", ", ".join(missing))
        return False

    if logs.empty:
        print("The security log file contains no events.")
        try:
            pd.DataFrame(columns=ALERT_COLUMNS).to_csv(
                ALERTS_FILE, index=False
            )
            return True
        except OSError as error:
            print(f"Error saving alerts: {error}")
            return False

    # Normalize text values for consistent comparisons.
    for column in [
        "username",
        "ip_address",
        "event_type",
        "status",
        "resource"
    ]:
        logs[column] = (
            logs[column]
            .fillna("")
            .astype(str)
            .str.strip()
            .str.lower()
        )

    # Ignore events without a username.
    logs = logs[logs["username"] != ""]

    if logs.empty:
        print("No usable security events with usernames were found.")
        try:
            pd.DataFrame(columns=ALERT_COLUMNS).to_csv(
                ALERTS_FILE, index=False
            )
            return True
        except OSError as error:
            print(f"Error saving alerts: {error}")
            return False

    # Count failed login attempts for each user.
    failed_logins = Counter(
        logs.loc[
            (logs["event_type"] == "login")
            & (logs["status"] == "failed"),
            "username"
        ]
    )

    # Count denied access attempts for each user.
    denied_access = Counter(
        logs.loc[
            (logs["event_type"] == "access")
            & (logs["status"] == "denied"),
            "username"
        ]
    )

    # Analyze failed logins by source IP address.
    failed_by_ip = Counter(
        logs.loc[
            (logs["event_type"] == "login")
            & (logs["status"] == "failed")
            & (logs["ip_address"] != ""),
            "ip_address"
        ]
    )

    alerts = []

    users = sorted(set(failed_logins) | set(denied_access))

    for username in users:
        failed = failed_logins[username]
        denied = denied_access[username]

        user_logs = logs[logs["username"] == username]

        reasons = []

        # Rule 1: Repeated failed logins.
        if failed >= HIGH_FAILED_LOGIN_THRESHOLD:
            reasons.append(
                f"High number of failed login attempts ({failed})"
            )
        elif failed >= FAILED_LOGIN_THRESHOLD:
            reasons.append(
                f"Repeated failed login attempts ({failed})"
            )

        # Rule 2: Repeated denied access.
        if denied >= DENIED_ACCESS_THRESHOLD:
            reasons.append(
                f"Repeated denied access attempts ({denied})"
            )

        # Rule 3: An IP address has repeated failed logins.
        user_failed_ips = set(
            user_logs.loc[
                (user_logs["event_type"] == "login")
                & (user_logs["status"] == "failed")
                & (user_logs["ip_address"] != ""),
                "ip_address"
            ]
        )

        suspicious_ips = sorted(
            ip for ip in user_failed_ips
            if failed_by_ip[ip] >= FAILED_LOGIN_THRESHOLD
        )

        if suspicious_ips:
            reasons.append(
                "Repeated failed logins from IP: "
                + ", ".join(suspicious_ips)
            )

        # Do not create alerts if no detection rule was triggered.
        if not reasons:
            continue

        score = calculate_risk_score(failed, denied)
        severity = classify_risk(score)

        # Include only IP addresses associated with this user's events.
        ip_addresses = sorted(
            ip for ip in set(user_logs["ip_address"]) if ip
        )

        alerts.append({
            "username": username,
            "ip_address": ", ".join(ip_addresses) or "Unknown",
            "failed_logins": failed,
            "denied_access": denied,
            "risk_score": score,
            "severity": severity,
            "reason": "; ".join(reasons)
        })

    alerts_df = pd.DataFrame(alerts, columns=ALERT_COLUMNS)

    try:
        alerts_df.to_csv(ALERTS_FILE, index=False)
    except (PermissionError, OSError) as error:
        print(f"Error saving alerts: {error}")
        return False

    print("\n===== CYBERSECURITY THREAT DETECTION =====")
    print("Total security events:", len(logs))
    print("Users analyzed:", logs["username"].nunique())
    print("Alerts generated:", len(alerts))
    print("-" * 60)

    for alert in alerts:
        print("Username:", alert["username"])
        print("IP address:", alert["ip_address"])
        print("Failed logins:", alert["failed_logins"])
        print("Denied access:", alert["denied_access"])
        print("Risk score:", alert["risk_score"], "/ 100")
        print("Severity:", alert["severity"])
        print("Reason:", alert["reason"])
        print("-" * 60)

    print("Detection results saved to alerts.csv")

    return True


if __name__ == "__main__":
    default_log_file = BASE_DIR / "security_logs.csv"
    success = analyze_logs(default_log_file)

    if not success:
        raise SystemExit(1)


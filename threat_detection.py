
import pandas as pd

SUSPICIOUS_COMMANDS = [
    "whoami",
    "uname",
    "id",
    "ifconfig",
    "ip addr",
    "pwd",
    "cat /etc/passwd",
    "wget",
    "curl",
    "chmod",
    "sudo",
    "nc ",
    "netcat"
]


def analyze_threats(df):
    results = []

    # Detect repeated failed logins
    failed = df[df["eventid"] == "cowrie.login.failed"]

    attempts = failed.groupby("src_ip").size()

    for ip, count in attempts.items():
        if pd.isna(ip):
            continue

        if count >= 3:
            results.append({
                "Source IP": ip,
                "Severity": "High",
                "Detection": "Repeated failed logins",
                "Evidence": f"{count} failed login attempts"
            })

    # Detect successful logins
    successful = df[df["eventid"] == "cowrie.login.success"]

    for _, row in successful.iterrows():
        results.append({
            "Source IP": row["src_ip"],
            "Severity": "Medium",
            "Detection": "Successful login",
            "Evidence": f"Username: {row['username']}"
        })

    # Detect potentially suspicious commands
    commands = df[df["eventid"] == "cowrie.command.input"]

    for _, row in commands.iterrows():
        command = str(row["input"]).lower()

        if any(item in command for item in SUSPICIOUS_COMMANDS):
            results.append({
                "Source IP": row["src_ip"],
                "Severity": "Medium",
                "Detection": "Suspicious command activity",
                "Evidence": command
            })

    return pd.DataFrame(
        results,
        columns=["Source IP", "Severity", "Detection", "Evidence"]
    )

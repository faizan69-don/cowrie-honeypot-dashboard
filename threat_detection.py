
import pandas as pd
import shlex
import os


def classify_command(command):
    """Classify suspicious commands without arbitrary substring matching."""

    if not isinstance(command, str) or not command.strip():
        return None

    try:
        parts = shlex.split(command.lower())
    except ValueError:
        return None

    if not parts:
        return None

    executable = os.path.basename(parts[0])
    arguments = parts[1:]

    # Reconnaissance and system discovery
    if executable in {
        "whoami", "uname", "id", "ifconfig", "hostname", "pwd"
    }:
        return "Reconnaissance activity"

    if executable == "ip" and arguments and arguments[0] in {
        "addr", "route", "link"
    }:
        return "Network reconnaissance"

    if executable == "cat" and "/etc/passwd" in arguments:
        return "Sensitive file access attempt"

    # Download utilities
    if executable in {"wget", "curl"}:
        return "Suspicious download activity"

    # Permission changes
    if executable == "chmod":
        return "Permission modification attempt"

    # Privilege and network utilities
    if executable == "sudo":
        return "Privilege escalation attempt"

    if executable in {"nc", "netcat", "ncat"}:
        return "Network utility activity"

    return None


def analyze_threats(df):
    results = []

    # Repeated failed login detection
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

    # Successful login detection
    successful = df[df["eventid"] == "cowrie.login.success"]

    for _, row in successful.iterrows():
        results.append({
            "Source IP": row["src_ip"],
            "Severity": "Medium",
            "Detection": "Successful login",
            "Evidence": f"Username: {row['username']}"
        })

    # Command activity detection
    commands = df[df["eventid"] == "cowrie.command.input"]

    for _, row in commands.iterrows():
        command = row["input"]

        detection = classify_command(command)

        if detection:
            results.append({
                "Source IP": row["src_ip"],
                "Severity": "Medium",
                "Detection": detection,
                "Evidence": str(command)
            })

    return pd.DataFrame(
        results,
        columns=["Source IP", "Severity", "Detection", "Evidence"]
    )

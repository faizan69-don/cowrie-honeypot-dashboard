
import json
from collections import Counter

LOG_FILE = "var/log/cowrie/cowrie.json"

events = []

# Read the JSON Lines log file
with open(LOG_FILE, "r") as file:
    for line in file:
        try:
            event = json.loads(line)
            events.append(event)
        except json.JSONDecodeError:
            continue

# Count event types
event_counts = Counter(
    event.get("eventid", "unknown") for event in events
)
# Authentication statistics
failed_logins = sum(
    1 for event in events
    if event.get("eventid") == "cowrie.login.failed"
)

successful_logins = sum(
    1 for event in events
    if event.get("eventid") == "cowrie.login.success"
)

commands_executed = sum(
    1 for event in events
    if event.get("eventid") == "cowrie.command.input"
    and event.get("input", "").strip()
)
# Collect source IP addresses
source_ips = {
    event.get("src_ip")
    for event in events
    if event.get("src_ip")
}

# Count attempted usernames
usernames = Counter(
    event["username"]
    for event in events
    if event.get("username")
)

# Count entered commands
commands = Counter(
    event["input"]
    for event in events
    if event.get("eventid") == "cowrie.command.input"
    and event.get("input")
)

print("\n===== COWRIE HONEYPOT ANALYSIS =====")

print("\nTotal events:", len(events))
print("Unique source IPs:", len(source_ips))
print("Failed logins:", failed_logins)
print("Successful logins:", successful_logins)
print("Non-empty commands:", commands_executed)
print("\nEvent breakdown:")
for event, count in event_counts.most_common():
    print(f"{event}: {count}")

print("\nAttempted usernames:")
for username, count in usernames.most_common(10):
    print(f"{username}: {count}")

print("\nMost entered commands:")
for command, count in commands.most_common(10):
    print(f"{command}: {count}")

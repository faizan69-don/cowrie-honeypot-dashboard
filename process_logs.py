
import json
import pandas as pd

LOG_FILE = "var/log/cowrie/cowrie.json"

# Read Cowrie JSON logs
events = []

with open(LOG_FILE, "r") as file:
    for line in file:
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

# Convert events into a Pandas DataFrame
df = pd.DataFrame(events)

# Select useful fields for analysis
columns = [
    "timestamp",
    "eventid",
    "src_ip",
    "username",
    "password",
    "input",
    "session"
]

df = df.reindex(columns=columns)

# Convert timestamps into datetime values
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

# Save processed data
df.to_csv("cowrie_events.csv", index=False)

print("\n===== PROCESSED COWRIE DATA =====")
print("Total records:", len(df))
print("\nAvailable columns:")
print(df.columns.tolist())

print("\nFirst five records:")
print(df.head())

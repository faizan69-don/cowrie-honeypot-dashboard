
import pandas as pd

# Load processed Cowrie dataset
df = pd.read_csv("cowrie_events.csv")

# Authentication statistics
failed = df[df["eventid"] == "cowrie.login.failed"]
successful = df[df["eventid"] == "cowrie.login.success"]

# Command statistics
commands = df[
    (df["eventid"] == "cowrie.command.input") &
    (df["input"].notna()) &
    (df["input"].str.strip() != "")
]

# Unique source IPs
unique_ips = df["src_ip"].nunique()

print("\n===== SECURITY DASHBOARD STATISTICS =====")

print("\nTotal events:", len(df))
print("Unique IP addresses:", unique_ips)

print("\nAuthentication:")
print("Failed logins:", len(failed))
print("Successful logins:", len(successful))

print("\nTop attempted usernames:")
print(
    failed["username"]
    .value_counts()
    .head(10)
)

print("\nMost entered commands:")
print(
    commands["input"]
    .value_counts()
    .head(10)
)

print("\nEvents per source IP:")
print(df["src_ip"].value_counts())

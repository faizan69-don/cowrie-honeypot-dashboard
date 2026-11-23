
import os
import streamlit as st
import pandas as pd
import plotly.express as px
from streamlit_autorefresh import st_autorefresh

st.set_page_config(
    page_title="Cowrie Honeypot Dashboard",
    page_icon="🛡️",
    layout="wide"
)

DEMO_MODE = os.getenv("COWRIE_DEMO_MODE", "true").lower() == "true"

if not DEMO_MODE:
    st_autorefresh(interval=10_000, key="cowrie_auto_refresh")


@st.cache_data(ttl=10)
def load_data():
    if DEMO_MODE:
        data = pd.read_csv("demo_events.csv")
    else:
        data = pd.read_json("var/log/cowrie/cowrie.json", lines=True)

    required_columns = [
        "timestamp", "eventid", "src_ip",
        "username", "input", "session"
    ]

    for column in required_columns:
        if column not in data.columns:
            data[column] = pd.NA

    return data[required_columns]


df = load_data()
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

st.title("🛡 SSH Honeypot — Threat Analytics")

if DEMO_MODE:
    st.caption("Illustrative demo using synthetic sample data — not live attacks.")
else:
    st.caption("Local Cowrie honeypot log analysis and attack monitoring")

# Sidebar filters
st.sidebar.header("🔎 Dashboard Filters")

event_options = sorted(df["eventid"].dropna().unique())
ip_options = sorted(df["src_ip"].dropna().unique())

selected_events = st.sidebar.multiselect(
    "Select Event Types", event_options, default=event_options
)
selected_ips = st.sidebar.multiselect(
    "Select Source IPs", ip_options, default=ip_options
)

df = df[
    df["eventid"].isin(selected_events)
    & df["src_ip"].isin(selected_ips)
].copy()

st.sidebar.header("📅 Time Range Filter")

valid_dates = df["timestamp"].dropna()

if not valid_dates.empty:
    min_date = valid_dates.min().date()
    max_date = valid_dates.max().date()

    selected_dates = st.sidebar.date_input(
        "Select Date Range",
        value=(min_date, max_date),
        min_value=min_date,
        max_value=max_date
    )

    if len(selected_dates) == 2:
        start_date, end_date = selected_dates
        df = df[
            df["timestamp"].dt.date.between(start_date, end_date)
        ]

# Summary metrics
failed = df[df["eventid"] == "cowrie.login.failed"]
successful = df[df["eventid"] == "cowrie.login.success"]
commands = df[df["eventid"] == "cowrie.command.input"]

col1, col2, col3, col4 = st.columns(4)
col1.metric("Total Events", len(df))
col2.metric("Failed Logins", len(failed))
col3.metric("Successful Logins", len(successful))
col4.metric("Unique Source IPs", df["src_ip"].nunique())

# Event timeline
st.subheader("Attack Activity Timeline")

timeline_data = (
    df.dropna(subset=["timestamp"])
    .set_index("timestamp")
    .resample("1min")
    .size()
    .reset_index(name="Events")
)

fig_timeline = px.line(
    timeline_data,
    x="timestamp",
    y="Events",
    title="Events Over Time",
    markers=True
)
st.plotly_chart(fig_timeline, use_container_width=True)

# Event distribution
st.subheader("Event Type Distribution")

event_data = df["eventid"].value_counts().reset_index()
event_data.columns = ["Event Type", "Count"]

fig_events = px.pie(
    event_data,
    names="Event Type",
    values="Count",
    title="Distribution of Cowrie Events",
    hole=0.4
)
st.plotly_chart(fig_events, use_container_width=True)

# Targeted usernames
st.subheader("Most Targeted Usernames")

username_data = failed["username"].value_counts().reset_index()
username_data.columns = ["Username", "Attempts"]

fig_usernames = px.bar(
    username_data,
    x="Username",
    y="Attempts",
    title="Failed Login Attempts by Username",
    text="Attempts"
)
st.plotly_chart(fig_usernames, use_container_width=True)

# Commands
st.subheader("Top Commands")

command_data = commands["input"].dropna().value_counts().head(10).reset_index()
command_data.columns = ["Command", "Count"]

fig_commands = px.bar(
    command_data,
    x="Count",
    y="Command",
    orientation="h",
    title="Top 10 Commands",
    text="Count"
)
st.plotly_chart(fig_commands, use_container_width=True)

# Session analysis
st.subheader("SSH Session Investigation")

session_data = df.dropna(subset=["session"]).copy()

session_summary = (
    session_data.groupby("session")
    .agg(
        Source_IP=("src_ip", "first"),
        Username=("username", "first"),
        Event_Count=("eventid", "count"),
        First_Seen=("timestamp", "min"),
        Last_Seen=("timestamp", "max")
    )
    .reset_index()
)

st.metric("Unique SSH Sessions", session_summary["session"].nunique())
st.dataframe(session_summary, use_container_width=True, hide_index=True)

# Raw event table
st.subheader("Event Details")
st.dataframe(df, use_container_width=True, hide_index=True)

# Safe CSV report: no passwords are loaded
csv_data = df.to_csv(index=False).encode("utf-8")

st.download_button(
    label="Download Event Report (CSV)",
    data=csv_data,
    file_name="cowrie_demo_investigation_report.csv",
    mime="text/csv"
)

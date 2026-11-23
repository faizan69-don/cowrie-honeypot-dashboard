
# 🛡 Cowrie Honeypot — Threat Analytics Dashboard

A cybersecurity portfolio project that analyzes SSH honeypot activity using Cowrie and visualizes security events with Streamlit.

## Features

- SSH event analytics
- Failed and successful login monitoring
- Attack activity timeline
- Event type distribution
- Targeted username analysis
- Command activity analysis
- SSH session investigation
- Interactive filters
- CSV investigation report export

## Technology Stack

- Python
- Cowrie Honeypot
- Streamlit
- Pandas
- Plotly

## Demo

This repository includes a synthetic sample dataset (`demo_events.csv`) for demonstration purposes.

**The sample data is illustrative. It does not represent real attacks or live internet traffic.**

## Run Locally

Clone the repository:

```bash
git clone https://github.com/faizan69-don/cowrie-honeypot-dashboard.git
cd cowrie-honeypot-dashboard
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Run the demo dashboard:

```bash
COWRIE_DEMO_MODE=true streamlit run app.py
```

## Data Privacy and Safety

- Real Cowrie logs are not included.
- Attempted passwords are not collected by this dashboard.
- The included sample IP addresses are reserved documentation addresses.
- The public demo uses synthetic data only.

## Project Purpose

Built as a hands-on cybersecurity learning project to explore SSH honeypots, security event analysis, and threat visualization.

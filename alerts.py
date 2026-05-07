"""
alerts.py
=========
NetShield AI – Alert Engine
Assigns severity levels, generates alert messages, and formats
threat records for the dashboard.
"""

import pandas as pd
from datetime import datetime

# ─── Severity Thresholds ─────────────────────────────────────────────────────

# Each threat type maps to a base severity.
# DDoS with very high traffic_freq escalates to Critical.
SEVERITY_RULES = {
    "Normal":     "—",
    "DDoS":       "High",
    "PortScan":   "Medium",
    "Suspicious": "Medium",
}

# Traffic frequency thresholds that escalate DDoS to Critical
DDOS_CRITICAL_FREQ = 1000

# Colour coding for badges (used in Streamlit markdown)
SEVERITY_COLORS = {
    "—":        "#4CAF50",   # green  (no threat)
    "Low":      "#FFC107",   # amber
    "Medium":   "#FF9800",   # orange
    "High":     "#F44336",   # red
    "Critical": "#9C27B0",   # purple
}


def assign_severity(row: pd.Series) -> str:
    """Assign a severity string based on predicted label and traffic features."""
    label = row.get("predicted_label", "Normal")
    freq  = row.get("traffic_freq", 0)

    base = SEVERITY_RULES.get(label, "Low")

    # Escalate DDoS with extremely high frequency to Critical
    if label == "DDoS" and freq >= DDOS_CRITICAL_FREQ:
        return "Critical"

    return base


def build_alert_message(row: pd.Series) -> str:
    """Generate a human-readable alert string for a single packet row."""
    label    = row.get("predicted_label", "Normal")
    src      = row.get("src_ip",         "Unknown")
    dst      = row.get("dst_ip",         "Unknown")
    proto    = row.get("protocol",       "Unknown")
    severity = row.get("severity",       "—")
    ts       = row.get("timestamp",      datetime.now().strftime("%H:%M:%S"))

    templates = {
        "DDoS":       f"[{ts}] 🔴 DDoS ATTACK detected from {src} → {dst} via {proto}. Severity: {severity}",
        "PortScan":   f"[{ts}] 🟠 PORT SCAN activity from {src} targeting {dst}. Severity: {severity}",
        "Suspicious": f"[{ts}] 🟡 SUSPICIOUS traffic from {src} → {dst} ({proto}). Severity: {severity}",
        "Normal":     f"[{ts}] 🟢 Normal traffic: {src} → {dst}",
    }
    return templates.get(label, f"[{ts}] Unknown traffic type from {src}")


def enrich_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Add severity and alert_message columns to an already-predicted DataFrame.
    Expects columns: predicted_label, src_ip, dst_ip, protocol, traffic_freq, timestamp.
    """
    df = df.copy()
    df["severity"]      = df.apply(assign_severity, axis=1)
    df["alert_message"] = df.apply(build_alert_message, axis=1)
    return df


def get_threat_summary(df: pd.DataFrame) -> dict:
    """
    Return a summary dict used by the KPI metric cards.
    Keys: total_packets, total_threats, ddos_count, portscan_count,
          suspicious_count, high_severity_count, critical_count
    """
    threats = df[df["predicted_label"] != "Normal"]
    return {
        "total_packets":      len(df),
        "total_threats":      len(threats),
        "ddos_count":         int((df["predicted_label"] == "DDoS").sum()),
        "portscan_count":     int((df["predicted_label"] == "PortScan").sum()),
        "suspicious_count":   int((df["predicted_label"] == "Suspicious").sum()),
        "high_severity_count": int(df["severity"].isin(["High", "Critical"]).sum()),
        "critical_count":     int((df["severity"] == "Critical").sum()),
    }


def get_suspicious_ips(df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
    """
    Return top-N source IPs that appear in threat traffic, sorted by count.
    """
    threat_df = df[df["predicted_label"] != "Normal"].copy()
    if threat_df.empty:
        return pd.DataFrame(columns=["src_ip", "threat_type", "count", "severity"])

    grouped = (
        threat_df.groupby(["src_ip", "predicted_label", "severity"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
        .head(top_n)
    )
    grouped.columns = ["src_ip", "threat_type", "severity", "count"]
    return grouped

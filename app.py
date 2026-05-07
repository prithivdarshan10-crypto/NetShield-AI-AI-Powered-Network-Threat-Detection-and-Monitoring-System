"""
app.py
======
NetShield AI – Main Streamlit Application
Launch with:  streamlit run app.py
"""

import os
import time
import joblib
import numpy as np
import pandas as pd
import streamlit as st
from datetime import datetime

# ── Local modules ─────────────────────────────────────────────────────────────
from packet_capture import get_packets
from train_model import (
    encode_features,
    get_feature_columns,
    train_and_save_model,
    MODEL_PATH,
    ENCODER_PATH,
)
from alerts import enrich_dataframe, get_threat_summary, get_suspicious_ips
import dashboard as charts

# ─── Page Config ──────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="NetShield AI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─── Global CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

/* ── Root palette ── */
:root {
  --bg:        #0D1117;
  --surface:   #161B22;
  --border:    #21262D;
  --accent:    #00E5FF;
  --green:     #39D353;
  --red:       #F85149;
  --orange:    #FF9800;
  --yellow:    #FFC107;
  --text:      #C9D1D9;
  --text-dim:  #8B949E;
  --mono:      'Share Tech Mono', monospace;
  --sans:      'Rajdhani', sans-serif;
}

html, body, [data-testid="stAppViewContainer"] {
  background-color: var(--bg) !important;
  color: var(--text);
  font-family: var(--sans);
}

/* ── Sidebar ── */
[data-testid="stSidebar"] {
  background: var(--surface) !important;
  border-right: 1px solid var(--border);
}
[data-testid="stSidebar"] * { color: var(--text) !important; }

/* ── Metric cards ── */
[data-testid="stMetric"] {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px 16px;
}
[data-testid="stMetricLabel"] { color: var(--text-dim) !important; font-family: var(--mono); font-size: 11px !important; }
[data-testid="stMetricValue"] { color: var(--accent) !important; font-family: var(--mono); font-size: 28px !important; }
[data-testid="stMetricDelta"] { font-family: var(--mono) !important; font-size: 11px !important; }

/* ── Plotly chart containers ── */
.stPlotlyChart { border: 1px solid var(--border); border-radius: 8px; padding: 4px; background: var(--surface); }

/* ── Alert boxes ── */
.alert-box {
  background: #161B22;
  border-left: 3px solid var(--red);
  border-radius: 4px;
  padding: 8px 12px;
  margin: 4px 0;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--text);
}
.alert-box.normal  { border-color: var(--green); }
.alert-box.medium  { border-color: var(--orange); }
.alert-box.high    { border-color: var(--red); }
.alert-box.critical{ border-color: #9C27B0; }

/* ── Header ── */
.netshield-header {
  text-align: center;
  padding: 20px 0 10px;
  border-bottom: 1px solid var(--border);
  margin-bottom: 24px;
}
.netshield-title {
  font-family: var(--mono);
  font-size: 2.4rem;
  color: var(--accent);
  letter-spacing: 4px;
  text-shadow: 0 0 20px rgba(0,229,255,0.4);
}
.netshield-sub {
  font-family: var(--sans);
  font-size: 1rem;
  color: var(--text-dim);
  letter-spacing: 2px;
}

/* ── Status pill ── */
.status-pill {
  display: inline-block;
  padding: 2px 10px;
  border-radius: 20px;
  font-family: var(--mono);
  font-size: 11px;
}
.status-live   { background: #1B3A2D; color: var(--green); border: 1px solid var(--green); }
.status-demo   { background: #3A3A1B; color: var(--yellow); border: 1px solid var(--yellow); }

/* ── Section headings ── */
.section-heading {
  font-family: var(--mono);
  color: var(--accent);
  font-size: 0.85rem;
  letter-spacing: 2px;
  text-transform: uppercase;
  margin: 16px 0 8px;
  padding-bottom: 4px;
  border-bottom: 1px solid var(--border);
}

/* ── DataFrame ── */
.stDataFrame { background: var(--surface) !important; border: 1px solid var(--border) !important; border-radius: 8px; }
[data-testid="stDataFrame"] * { color: var(--text) !important; }

/* ── Buttons ── */
.stButton > button {
  background: transparent;
  border: 1px solid var(--accent);
  color: var(--accent);
  font-family: var(--mono);
  letter-spacing: 1px;
  border-radius: 4px;
  transition: all 0.2s;
}
.stButton > button:hover {
  background: rgba(0,229,255,0.1);
  box-shadow: 0 0 12px rgba(0,229,255,0.3);
}

/* ── Selectbox / slider ── */
.stSelectbox select, .stSlider * { accent-color: var(--accent); }

/* ── Hide default Streamlit chrome ── */
#MainMenu, footer, header { visibility: hidden; }
</style>
""", unsafe_allow_html=True)


# ─── Helper: Load or Train Model ─────────────────────────────────────────────

@st.cache_resource(show_spinner=False)
def load_model():
    """Load model from disk, training first if not found."""
    if not os.path.exists(MODEL_PATH) or not os.path.exists(ENCODER_PATH):
        train_and_save_model()
    model = joblib.load(MODEL_PATH)
    le    = joblib.load(ENCODER_PATH)
    return model, le


def predict_labels(df: pd.DataFrame, model, le) -> pd.DataFrame:
    """
    Run the ML model on packet features and attach predicted_label column.
    """
    df = encode_features(df)
    feature_cols = get_feature_columns()
    X = df[feature_cols].values
    preds = model.predict(X)
    df["predicted_label"] = le.inverse_transform(preds)
    return df


# ─── Session State Init ───────────────────────────────────────────────────────

if "packet_history" not in st.session_state:
    st.session_state.packet_history = pd.DataFrame()
if "monitoring" not in st.session_state:
    st.session_state.monitoring = False
if "alert_log" not in st.session_state:
    st.session_state.alert_log = []
if "scan_count" not in st.session_state:
    st.session_state.scan_count = 0


# ─── Sidebar ─────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("### 🛡️  NetShield AI")
    st.markdown('<div class="section-heading">CONTROL PANEL</div>', unsafe_allow_html=True)

    packets_per_cycle = st.slider("Packets per scan", 10, 100, 30, step=10)
    refresh_interval  = st.slider("Refresh interval (s)", 1, 10, 3)
    max_history       = st.slider("Max history (rows)", 100, 2000, 500, step=100)
    use_live_capture  = st.checkbox("🔴 Try live capture (needs root)", value=False)

    st.markdown('<div class="section-heading">ACTIONS</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("▶ Start"):
            st.session_state.monitoring = True
    with col2:
        if st.button("⏹ Stop"):
            st.session_state.monitoring = False

    if st.button("🗑 Clear History"):
        st.session_state.packet_history = pd.DataFrame()
        st.session_state.alert_log = []
        st.session_state.scan_count = 0

    st.markdown('<div class="section-heading">STATUS</div>', unsafe_allow_html=True)
    if st.session_state.monitoring:
        st.markdown('<span class="status-pill status-live">● MONITORING ACTIVE</span>',
                    unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-pill status-demo">○ STANDBY</span>',
                    unsafe_allow_html=True)

    st.markdown(f"<small style='color:var(--text-dim)'>Scans completed: {st.session_state.scan_count}</small>",
                unsafe_allow_html=True)
    st.markdown("<br><small style='color:var(--text-dim)'>Demo mode active if live capture unavailable.</small>",
                unsafe_allow_html=True)


# ─── Header ──────────────────────────────────────────────────────────────────

st.markdown("""
<div class="netshield-header">
  <div class="netshield-title">🛡 NETSHIELD AI</div>
  <div class="netshield-sub">AI-Powered Network Threat Detection &amp; Monitoring System</div>
</div>
""", unsafe_allow_html=True)


# ─── Load model ───────────────────────────────────────────────────────────────

with st.spinner("⚡ Initialising AI engine..."):
    model, le = load_model()


# ─── Main Monitoring Loop ─────────────────────────────────────────────────────

placeholder = st.empty()   # entire dashboard lives here for clean refresh

def render_dashboard(df_history: pd.DataFrame):
    """Render the full dashboard inside the placeholder."""

    with placeholder.container():

        # ── Scan & predict new batch ──────────────────────────────────────────
        new_packets = get_packets(n=packets_per_cycle, prefer_live=use_live_capture)
        new_packets = predict_labels(new_packets, model, le)
        new_packets = enrich_dataframe(new_packets)

        # Append to rolling history
        df_history = pd.concat([df_history, new_packets], ignore_index=True)
        if len(df_history) > max_history:
            df_history = df_history.tail(max_history).reset_index(drop=True)

        st.session_state.packet_history = df_history
        st.session_state.scan_count += 1

        # Append new alerts
        new_alerts = new_packets[new_packets["predicted_label"] != "Normal"]["alert_message"].tolist()
        st.session_state.alert_log = (new_alerts + st.session_state.alert_log)[:50]

        # ── KPI Cards ─────────────────────────────────────────────────────────
        summary = get_threat_summary(df_history)
        threat_ratio = summary["total_threats"] / max(summary["total_packets"], 1)

        st.markdown('<div class="section-heading">KEY METRICS</div>', unsafe_allow_html=True)
        k1, k2, k3, k4, k5, k6 = st.columns(6)
        k1.metric("Total Packets",   summary["total_packets"])
        k2.metric("Threats Detected", summary["total_threats"],
                  delta=f"+{len(new_packets[new_packets['predicted_label'] != 'Normal'])}")
        k3.metric("DDoS",            summary["ddos_count"])
        k4.metric("Port Scans",      summary["portscan_count"])
        k5.metric("Suspicious",      summary["suspicious_count"])
        k6.metric("High/Critical",   summary["high_severity_count"])

        # ── Row 1: Gauge + Timeline ───────────────────────────────────────────
        st.markdown('<div class="section-heading">NETWORK OVERVIEW</div>', unsafe_allow_html=True)
        g_col, t_col = st.columns([1, 3])
        with g_col:
            st.plotly_chart(charts.threat_severity_gauge(threat_ratio),
                            use_container_width=True, key="gauge")
        with t_col:
            st.plotly_chart(charts.live_traffic_chart(df_history),
                            use_container_width=True, key="timeline")

        # ── Row 2: Protocol + Threat Bar ─────────────────────────────────────
        p_col, b_col = st.columns(2)
        with p_col:
            st.plotly_chart(charts.protocol_distribution_chart(df_history),
                            use_container_width=True, key="proto")
        with b_col:
            st.plotly_chart(charts.threat_classification_chart(df_history),
                            use_container_width=True, key="threat_bar")

        # ── Row 3: Histogram + Scatter ───────────────────────────────────────
        h_col, s_col = st.columns(2)
        with h_col:
            st.plotly_chart(charts.packet_length_histogram(df_history),
                            use_container_width=True, key="histogram")
        with s_col:
            st.plotly_chart(charts.traffic_frequency_scatter(df_history),
                            use_container_width=True, key="scatter")

        # ── Top Attackers + Suspicious IP Table ─────────────────────────────
        st.markdown('<div class="section-heading">THREAT INTELLIGENCE</div>', unsafe_allow_html=True)
        att_col, tbl_col = st.columns([1.5, 1])

        suspicious_ips = get_suspicious_ips(df_history)
        with att_col:
            st.plotly_chart(charts.top_attackers_chart(suspicious_ips),
                            use_container_width=True, key="attackers")
        with tbl_col:
            st.markdown("**🚨 Suspicious IP Table**")
            if suspicious_ips.empty:
                st.info("No threats detected yet.")
            else:
                st.dataframe(
                    suspicious_ips[["src_ip", "threat_type", "severity", "count"]],
                    use_container_width=True,
                    height=280,
                )

        # ── Alert Log ────────────────────────────────────────────────────────
        st.markdown('<div class="section-heading">ALERT LOG</div>', unsafe_allow_html=True)
        if not st.session_state.alert_log:
            st.success("✅  No active threats in alert log.")
        else:
            for msg in st.session_state.alert_log[:15]:
                sev_class = "normal"
                if "DDoS" in msg or "Critical" in msg:
                    sev_class = "high"
                elif "PORT SCAN" in msg or "Medium" in msg:
                    sev_class = "medium"
                elif "SUSPICIOUS" in msg:
                    sev_class = "medium"
                st.markdown(f'<div class="alert-box {sev_class}">{msg}</div>',
                            unsafe_allow_html=True)

        # ── Raw Packet Table ─────────────────────────────────────────────────
        with st.expander("📋  Raw Packet Log (last 100 records)", expanded=False):
            display_cols = ["timestamp", "src_ip", "dst_ip", "protocol",
                            "packet_length", "traffic_freq", "predicted_label", "severity"]
            st.dataframe(df_history[display_cols].tail(100), use_container_width=True)

        # ── Download Report ───────────────────────────────────────────────────
        st.markdown('<div class="section-heading">EXPORT</div>', unsafe_allow_html=True)
        dl_col, _ = st.columns([1, 3])
        with dl_col:
            csv_data = df_history.to_csv(index=False).encode("utf-8")
            st.download_button(
                label="⬇ Download Threat Report (CSV)",
                data=csv_data,
                file_name=f"netshield_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv",
            )

        # ── Footer ────────────────────────────────────────────────────────────
        st.markdown(
            "<hr style='border-color:var(--border)'>"
            "<p style='text-align:center;color:var(--text-dim);font-family:var(--mono);font-size:11px'>"
            "NetShield AI  ·  Powered by Random Forest &amp; Scikit-learn  ·  "
            f"Last updated: {datetime.now().strftime('%H:%M:%S')}"
            "</p>",
            unsafe_allow_html=True,
        )

    return df_history


# ─── Entry Point ─────────────────────────────────────────────────────────────

if st.session_state.monitoring:
    df = render_dashboard(st.session_state.packet_history)
    time.sleep(refresh_interval)
    st.rerun()
else:
    # Show static dashboard with existing history (or empty state)
    if not st.session_state.packet_history.empty:
        render_dashboard(st.session_state.packet_history)
    else:
        # First-load: render one batch even while stopped so the UI isn't blank
        render_dashboard(pd.DataFrame())

    st.info("▶ Press **Start** in the sidebar to begin real-time monitoring.")

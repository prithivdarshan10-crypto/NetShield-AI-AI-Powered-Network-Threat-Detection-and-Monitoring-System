"""
dashboard.py
============
NetShield AI – Plotly Chart Builder
All chart-generating functions used by app.py.
Each function returns a Plotly Figure object.
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from alerts import SEVERITY_COLORS

# ─── Design Tokens ───────────────────────────────────────────────────────────

BG_COLOR      = "#0D1117"    # near-black background
PAPER_COLOR   = "#161B22"    # card background
GRID_COLOR    = "#21262D"    # subtle grid lines
TEXT_COLOR    = "#C9D1D9"    # primary text
ACCENT_CYAN   = "#00E5FF"
ACCENT_GREEN  = "#39D353"
ACCENT_RED    = "#F85149"
ACCENT_ORANGE = "#FF9800"

LABEL_COLORS = {
    "Normal":     ACCENT_GREEN,
    "DDoS":       ACCENT_RED,
    "PortScan":   ACCENT_ORANGE,
    "Suspicious": "#FFC107",
}

_BASE_LAYOUT = dict(
    paper_bgcolor=PAPER_COLOR,
    plot_bgcolor=BG_COLOR,
    font=dict(family="'Share Tech Mono', monospace", color=TEXT_COLOR, size=12),
    margin=dict(l=40, r=20, t=40, b=40),
    xaxis=dict(gridcolor=GRID_COLOR, showgrid=True, zeroline=False),
    yaxis=dict(gridcolor=GRID_COLOR, showgrid=True, zeroline=False),
)


def _apply_base(fig: go.Figure, title: str = "") -> go.Figure:
    """Apply the shared dark-theme layout to any figure."""
    layout = dict(_BASE_LAYOUT)
    layout["title"] = dict(text=title, font=dict(color=ACCENT_CYAN, size=14))
    fig.update_layout(**layout)
    return fig


# ─── 1. Live Traffic Timeline ────────────────────────────────────────────────

def live_traffic_chart(df: pd.DataFrame) -> go.Figure:
    """
    Line chart: packet count per timestamp, coloured by threat label.
    Shows traffic volume over the current monitoring window.
    """
    if df.empty:
        return go.Figure()

    # Count packets per (timestamp, label) pair
    counts = (
        df.groupby(["timestamp", "predicted_label"])
        .size()
        .reset_index(name="count")
    )

    fig = go.Figure()
    for label, color in LABEL_COLORS.items():
        sub = counts[counts["predicted_label"] == label]
        if sub.empty:
            continue
        fig.add_trace(go.Scatter(
            x=sub["timestamp"],
            y=sub["count"],
            mode="lines+markers",
            name=label,
            line=dict(color=color, width=2),
            marker=dict(size=5, color=color),
            fill="tozeroy",
            fillcolor=color.replace(")", ",0.08)").replace("rgb", "rgba") if "rgb" in color else color + "15",
        ))

    _apply_base(fig, "📡  Live Traffic Timeline")
    fig.update_layout(legend=dict(
        bgcolor=PAPER_COLOR, bordercolor=GRID_COLOR, borderwidth=1))
    return fig


# ─── 2. Protocol Distribution ────────────────────────────────────────────────

def protocol_distribution_chart(df: pd.DataFrame) -> go.Figure:
    """Donut chart showing relative proportion of TCP / UDP / ICMP traffic."""
    if df.empty:
        return go.Figure()

    counts = df["protocol"].value_counts().reset_index()
    counts.columns = ["protocol", "count"]

    fig = go.Figure(go.Pie(
        labels=counts["protocol"],
        values=counts["count"],
        hole=0.55,
        marker=dict(colors=[ACCENT_CYAN, ACCENT_GREEN, ACCENT_ORANGE, "#9C27B0"]),
        textfont=dict(color=TEXT_COLOR, size=12),
    ))

    _apply_base(fig, "🔌  Protocol Distribution")
    fig.update_layout(showlegend=True,
                      legend=dict(bgcolor=PAPER_COLOR, bordercolor=GRID_COLOR))
    return fig


# ─── 3. Threat Classification Bar ────────────────────────────────────────────

def threat_classification_chart(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar chart of threat label counts."""
    if df.empty:
        return go.Figure()

    counts = df["predicted_label"].value_counts().reset_index()
    counts.columns = ["label", "count"]
    counts = counts.sort_values("count", ascending=True)

    colors = [LABEL_COLORS.get(l, ACCENT_CYAN) for l in counts["label"]]

    fig = go.Figure(go.Bar(
        x=counts["count"],
        y=counts["label"],
        orientation="h",
        marker=dict(color=colors, line=dict(color=GRID_COLOR, width=1)),
        text=counts["count"],
        textposition="outside",
        textfont=dict(color=TEXT_COLOR),
    ))

    _apply_base(fig, "⚠️  Threat Classification")
    fig.update_layout(
        xaxis_title="Packet Count",
        yaxis_title="",
        bargap=0.3,
    )
    return fig


# ─── 4. Packet Length Distribution ───────────────────────────────────────────

def packet_length_histogram(df: pd.DataFrame) -> go.Figure:
    """Histogram of packet sizes coloured by threat label."""
    if df.empty:
        return go.Figure()

    fig = go.Figure()
    for label, color in LABEL_COLORS.items():
        sub = df[df["predicted_label"] == label]
        if sub.empty:
            continue
        fig.add_trace(go.Histogram(
            x=sub["packet_length"],
            name=label,
            marker_color=color,
            opacity=0.75,
            nbinsx=20,
        ))

    _apply_base(fig, "📦  Packet Length Distribution")
    fig.update_layout(
        barmode="overlay",
        xaxis_title="Packet Length (bytes)",
        yaxis_title="Count",
        legend=dict(bgcolor=PAPER_COLOR, bordercolor=GRID_COLOR),
    )
    return fig


# ─── 5. Traffic Frequency Scatter ────────────────────────────────────────────

def traffic_frequency_scatter(df: pd.DataFrame) -> go.Figure:
    """
    Scatter plot: packet_length vs traffic_freq, coloured by label.
    Good for visually separating DDoS (high freq, large size) clusters.
    """
    if df.empty:
        return go.Figure()

    fig = go.Figure()
    for label, color in LABEL_COLORS.items():
        sub = df[df["predicted_label"] == label]
        if sub.empty:
            continue
        fig.add_trace(go.Scatter(
            x=sub["packet_length"],
            y=sub["traffic_freq"],
            mode="markers",
            name=label,
            marker=dict(color=color, size=8, opacity=0.8,
                        line=dict(color=GRID_COLOR, width=0.5)),
        ))

    _apply_base(fig, "🔬  Packet Length vs Traffic Frequency")
    fig.update_layout(
        xaxis_title="Packet Length (bytes)",
        yaxis_title="Traffic Frequency",
        legend=dict(bgcolor=PAPER_COLOR, bordercolor=GRID_COLOR),
    )
    return fig


# ─── 6. Severity Gauge ───────────────────────────────────────────────────────

def threat_severity_gauge(threat_ratio: float) -> go.Figure:
    """
    Gauge chart showing current overall threat level (0–100%).
    Green → Yellow → Orange → Red as threat ratio rises.
    """
    pct = round(threat_ratio * 100, 1)

    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta",
        value=pct,
        number=dict(suffix="%", font=dict(color=ACCENT_CYAN, size=28)),
        delta=dict(reference=20, increasing=dict(color=ACCENT_RED),
                   decreasing=dict(color=ACCENT_GREEN)),
        gauge=dict(
            axis=dict(range=[0, 100], tickwidth=1, tickcolor=TEXT_COLOR,
                      tickfont=dict(color=TEXT_COLOR)),
            bar=dict(color=ACCENT_CYAN),
            bgcolor=BG_COLOR,
            borderwidth=2,
            bordercolor=GRID_COLOR,
            steps=[
                dict(range=[0,  25], color="#1B3A2D"),
                dict(range=[25, 50], color="#3A3A1B"),
                dict(range=[50, 75], color="#3A2B1B"),
                dict(range=[75, 100], color="#3A1B1B"),
            ],
            threshold=dict(
                line=dict(color=ACCENT_RED, width=3),
                thickness=0.75,
                value=75,
            ),
        ),
        title=dict(text="THREAT LEVEL", font=dict(color=ACCENT_CYAN, size=14)),
    ))

    fig.update_layout(
        paper_bgcolor=PAPER_COLOR,
        font=dict(family="'Share Tech Mono', monospace", color=TEXT_COLOR),
        margin=dict(l=20, r=20, t=40, b=20),
        height=220,
    )
    return fig


# ─── 7. Top Attacker IPs Bar ─────────────────────────────────────────────────

def top_attackers_chart(suspicious_ips_df: pd.DataFrame) -> go.Figure:
    """Bar chart of the top attacking source IPs by packet count."""
    if suspicious_ips_df.empty:
        return go.Figure()

    df = suspicious_ips_df.sort_values("count", ascending=False).head(8)
    colors = [LABEL_COLORS.get(t, ACCENT_ORANGE) for t in df["threat_type"]]

    fig = go.Figure(go.Bar(
        x=df["src_ip"],
        y=df["count"],
        marker=dict(color=colors, line=dict(color=GRID_COLOR, width=1)),
        text=df["threat_type"],
        textposition="outside",
        textfont=dict(color=TEXT_COLOR, size=10),
    ))

    _apply_base(fig, "🎯  Top Attacking IPs")
    fig.update_layout(
        xaxis_title="Source IP",
        yaxis_title="Packet Count",
        xaxis_tickangle=-35,
    )
    return fig

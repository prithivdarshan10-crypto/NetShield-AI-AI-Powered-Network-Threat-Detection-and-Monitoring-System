"""
packet_capture.py
=================
NetShield AI – Packet Capture & Demo Traffic Generator
Attempts live capture via Scapy; falls back to realistic demo data
when root privileges or a network interface are unavailable.
"""

import random
import time
from datetime import datetime
import pandas as pd
import numpy as np

# ─── Attempt to import Scapy ────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ─── Demo Traffic Templates ──────────────────────────────────────────────────

# Realistic private-range IP pools
NORMAL_SRC_IPS   = [f"192.168.1.{i}" for i in range(10, 30)]
NORMAL_DST_IPS   = [f"10.0.0.{i}"    for i in range(1, 20)]
DDOS_SRC_IPS     = [f"10.0.{random.randint(1,254)}.{random.randint(1,254)}" for _ in range(50)]
SCAN_SRC_IPS     = [f"172.16.{random.randint(0,5)}.{random.randint(1,10)}"  for _ in range(10)]
SUSP_SRC_IPS     = [f"10.10.{random.randint(1,20)}.{random.randint(1,50)}"  for _ in range(20)]

PROTOCOLS = ["TCP", "UDP", "ICMP"]

# Traffic profile weightings  (Normal is most common in healthy networks)
TRAFFIC_PROFILE_WEIGHTS = [0.65, 0.15, 0.12, 0.08]   # Normal, DDoS, PortScan, Suspicious
TRAFFIC_PROFILES = ["Normal", "DDoS", "PortScan", "Suspicious"]


def _generate_normal_packet() -> dict:
    return {
        "timestamp":      datetime.now().strftime("%H:%M:%S"),
        "src_ip":         random.choice(NORMAL_SRC_IPS),
        "dst_ip":         random.choice(NORMAL_DST_IPS),
        "protocol":       random.choice(PROTOCOLS),
        "packet_length":  random.randint(40, 512),
        "traffic_freq":   random.randint(1, 10),
    }


def _generate_ddos_packet() -> dict:
    return {
        "timestamp":      datetime.now().strftime("%H:%M:%S"),
        "src_ip":         random.choice(DDOS_SRC_IPS),
        "dst_ip":         "192.168.1.1",          # single victim IP
        "protocol":       random.choice(["TCP", "UDP", "ICMP"]),
        "packet_length":  random.randint(1400, 1500),
        "traffic_freq":   random.randint(500, 1500),
    }


def _generate_portscan_packet() -> dict:
    victim = f"192.168.1.{random.randint(1, 30)}"
    return {
        "timestamp":      datetime.now().strftime("%H:%M:%S"),
        "src_ip":         random.choice(SCAN_SRC_IPS),
        "dst_ip":         victim,
        "protocol":       "TCP",
        "packet_length":  random.randint(40, 60),
        "traffic_freq":   random.randint(140, 250),
    }


def _generate_suspicious_packet() -> dict:
    return {
        "timestamp":      datetime.now().strftime("%H:%M:%S"),
        "src_ip":         random.choice(SUSP_SRC_IPS),
        "dst_ip":         f"192.168.1.{random.randint(20, 50)}",
        "protocol":       random.choice(PROTOCOLS),
        "packet_length":  random.randint(200, 1100),
        "traffic_freq":   random.randint(45, 145),
    }


_GENERATORS = {
    "Normal":     _generate_normal_packet,
    "DDoS":       _generate_ddos_packet,
    "PortScan":   _generate_portscan_packet,
    "Suspicious": _generate_suspicious_packet,
}


def generate_demo_packets(n: int = 20) -> list[dict]:
    """
    Produce `n` synthetic packets weighted by realistic traffic profiles.
    Returns a list of dicts ready to be loaded into a DataFrame.
    """
    packets = []
    for _ in range(n):
        profile = random.choices(TRAFFIC_PROFILES, weights=TRAFFIC_PROFILE_WEIGHTS, k=1)[0]
        packet = _GENERATORS[profile]()
        packets.append(packet)
    return packets


# ─── Scapy Live Capture (requires root) ──────────────────────────────────────

def _parse_scapy_packet(pkt) -> dict | None:
    """Extract relevant fields from a raw Scapy packet."""
    if not pkt.haslayer(IP):
        return None

    proto = "OTHER"
    if pkt.haslayer(TCP):
        proto = "TCP"
    elif pkt.haslayer(UDP):
        proto = "UDP"
    elif pkt.haslayer(ICMP):
        proto = "ICMP"

    return {
        "timestamp":     datetime.now().strftime("%H:%M:%S"),
        "src_ip":        pkt[IP].src,
        "dst_ip":        pkt[IP].dst,
        "protocol":      proto,
        "packet_length": len(pkt),
        "traffic_freq":  1,         # incremented externally if needed
    }


def capture_live_packets(count: int = 20, timeout: int = 5) -> list[dict]:
    """
    Capture live packets using Scapy (requires root).
    Returns empty list if capture fails; caller falls back to demo data.
    """
    if not SCAPY_AVAILABLE:
        return []

    captured = []
    try:
        pkts = sniff(count=count, timeout=timeout, store=True)
        for pkt in pkts:
            parsed = _parse_scapy_packet(pkt)
            if parsed:
                captured.append(parsed)
    except Exception:
        # Common failure: permission denied, no interface, etc.
        pass

    return captured


def get_packets(n: int = 20, prefer_live: bool = False) -> pd.DataFrame:
    """
    Public API used by the dashboard:
      - Tries live capture if prefer_live=True and Scapy is available.
      - Falls back to demo traffic generation automatically.
    Returns a DataFrame with standard columns.
    """
    packets = []

    if prefer_live:
        packets = capture_live_packets(count=n)

    if not packets:
        packets = generate_demo_packets(n=n)

    df = pd.DataFrame(packets)
    return df

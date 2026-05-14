import numpy as np

# CICIDS2017 feature names (77 features used by rf_nids.pkl)
CICIDS_FEATURES = [
    "Destination Port", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Total Length of Fwd Packets",
    "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length", "Packet Length Mean",
    "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]

def generate_network_flow():
    """Generate a randomized but realistic-looking network flow."""
    flow = {}
    for f in CICIDS_FEATURES:
        if "Port" in f:
            flow[f] = int(np.random.randint(1, 65535))
        elif "Packets" in f:
            flow[f] = int(np.random.randint(1, 1000))
        elif "Bytes" in f:
            flow[f] = int(np.random.randint(100, 100000))
        else:
            flow[f] = float(np.random.rand() * 1000)
    return flow

def generate_ddos_flow():
    """Generate a DDoS-like flow."""
    flow = generate_network_flow()
    flow.update({
        "Destination Port": 80,
        "Flow Duration": int(np.random.randint(100000, 200000)),
        "Total Fwd Packets": int(np.random.randint(1000, 2000)),
        "Total Backward Packets": int(np.random.randint(10, 100)),
        "SYN Flag Count": int(np.random.randint(1000, 2000)),
        "ACK Flag Count": int(np.random.randint(10, 100)),
        "Flow Bytes/s": float(np.random.uniform(500, 1000)),
        "Flow Packets/s": float(np.random.uniform(10, 20)),
    })
    return flow

def generate_benign_flow():
    """Generate a benign HTTPS flow."""
    flow = generate_network_flow()
    flow.update({
        "Destination Port": 443,
        "Flow Duration": int(np.random.randint(30000, 80000)),
        "Total Fwd Packets": int(np.random.randint(5, 20)),
        "Total Backward Packets": int(np.random.randint(4, 15)),
        "SYN Flag Count": 1,
        "ACK Flag Count": int(np.random.randint(8, 20)),
        "Flow Bytes/s": float(np.random.uniform(200, 500)),
        "Flow Packets/s": float(np.random.uniform(0.2, 0.8)),
    })
    return flow

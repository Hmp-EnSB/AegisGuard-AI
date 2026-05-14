import numpy as np
from api.schemas.nids_schema import CICIDS_FEATURES

def generate_network_flow():
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
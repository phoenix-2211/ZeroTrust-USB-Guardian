# =========================================
# FILE ENTROPY UTILITY
# =========================================

import math
import os


def calculate_entropy(file_path: str, max_bytes: int = 1024 * 1024) -> float:
    """
    Calculate Shannon entropy of a file.
    Reads up to max_bytes (default: 1MB) for safety & performance.

    Returns:
        float: entropy value (0.0 – ~8.0)
    """

    if not os.path.exists(file_path):
        return 0.0

    try:
        with open(file_path, "rb") as f:
            data = f.read(max_bytes)
    except Exception:
        return 0.0

    if not data:
        return 0.0

    freq = {}
    length = len(data)

    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1

    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


# =========================================
# END OF ENTROPY UTILITY
# =========================================

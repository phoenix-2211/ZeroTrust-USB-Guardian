# =========================================
# USB SCANNER  —  IMPROVED
# =========================================
# Changes vs original:
#   • MAX_FILES cap (5000) to prevent huge USB freeze
#   • MAX_ENTROPY_FILE_SIZE: skip entropy on huge files
#   • Silently skips permission-denied paths
#   • Returns (features, scanned_files) always
# =========================================

import os
from core.utils_entropy import calculate_entropy

MAX_FILES            = 5_000   # hard cap — prevents runaway on large drives
MAX_ENTROPY_FILE_KB  = 512     # only calc entropy on files ≤ 512 KB


def scan_usb(drive_path: str):
    features = {
        "total_files":            0,
        "exe_count":              0,
        "script_count":           0,
        "hidden_files":           0,
        "suspicious_extensions":  0,
        "avg_entropy":            0.0,
    }
    scanned_files  = []
    entropy_values = []

    for root, dirs, files in os.walk(drive_path):
        # Skip permission-denied subdirs silently
        dirs[:] = [d for d in dirs if _can_access(os.path.join(root, d))]

        for file in files:
            if features["total_files"] >= MAX_FILES:
                break

            features["total_files"] += 1
            file_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()

            if ext in (".exe", ".dll"):
                features["exe_count"] += 1

            if ext in (".js", ".vbs", ".ps1", ".bat", ".cmd"):
                features["script_count"] += 1

            if file.startswith("."):
                features["hidden_files"] += 1

            if ext in (".scr", ".pif", ".com"):
                features["suspicious_extensions"] += 1

            # Entropy only on small-ish files
            try:
                size_kb = os.path.getsize(file_path) / 1024
                if size_kb <= MAX_ENTROPY_FILE_KB:
                    e = calculate_entropy(file_path)
                    entropy_values.append(e)
            except Exception:
                pass

            scanned_files.append({"file": file_path, "extension": ext})

        if features["total_files"] >= MAX_FILES:
            break

    if entropy_values:
        features["avg_entropy"] = round(
            sum(entropy_values) / len(entropy_values), 4
        )

    return features, scanned_files


def _can_access(path: str) -> bool:
    try:
        os.scandir(path)
        return True
    except PermissionError:
        return False

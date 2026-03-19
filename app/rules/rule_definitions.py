# =========================================
# RULE DEFINITIONS – PHASE 2.4.2
# =========================================

RULES = {
    "AUTORUN_PRESENT": {"score": 30},
    "AUTORUN_SPOOFING": {"score": 20},
    "AUTORUN_EXECUTABLE": {"score": 25},

    "SCRIPT_IN_ROOT": {"score": 20},
    "EXE_IN_ROOT": {"score": 15},

    "MULTIPLE_EXECUTABLES": {"score": 15},
    "SUSPICIOUS_FILENAME": {"score": 10},

    "DOUBLE_EXTENSION_EXEC": {"score": 15},

    # Phase 2.4.2
    "PACKED_EXECUTABLE": {"score": 30},
    "OBFUSCATED_SCRIPT": {"score": 25},

    "SCRIPT_EXE_COMBO": {"score": 20}
}

# ---------- extensions ----------
SCRIPT_EXTENSIONS = (".ps1", ".bat", ".cmd", ".vbs", ".js")
EXECUTABLE_EXTENSIONS = (".exe", ".dll")

# ---------- disguise ----------
DISGUISE_EXTENSIONS = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx",
    ".jpg", ".jpeg", ".png", ".txt", ".rtf"
)

# ---------- names ----------
SUSPICIOUS_NAMES = (
    "setup.exe", "install.exe", "update.exe",
    "patch.exe", "crack.exe", "keygen.exe"
)

# ---------- thresholds ----------
EXEC_ENTROPY_THRESHOLD = 7.5     # packed binaries
SCRIPT_ENTROPY_THRESHOLD = 4.5   # obfuscated scripts
MIN_EXEC_SIZE_KB = 50            # avoid tiny false positives
MAX_SCRIPT_LINE_LEN = 500        # base64 / encoded blobs

# ---------- patterns ----------
DOUBLE_EXT_PATTERN = (
    r"^[\w,\s-]+\.(?:pdf|docx|xlsx|jpg|png|txt|rtf)\.(exe|dll)$"
)

# =========================================
# END OF RULE DEFINITIONS
# =========================================

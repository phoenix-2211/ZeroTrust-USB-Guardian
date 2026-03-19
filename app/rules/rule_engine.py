# =========================================
# RULE ENGINE – PHASE 2.4.2
# =========================================

import os
import re

# Import predefined rule configs (scores, rule names, patterns, extensions, etc.)
from rules.rule_definitions import *

# Import entropy calculation utility (used to detect packed / obfuscated files)
from core.utils_entropy import calculate_entropy


def apply_rules(usb_path, scanned_files):
    """
    Apply security rules on scanned USB files.

    usb_path -> root path of USB drive
    scanned_files -> list of file metadata dictionaries
    Example:
    {
        "file": full_path,
        "extension": ext
    }
    """

    # Store which rules triggered
    rule_hits = []

    # Final cumulative rule score
    total_score = 0

    # Track number of executables and scripts (used later for combo rules)
    exe_count = 0
    script_count = 0

    # Loop through each scanned file entry
    for entry in scanned_files:
        file_path = entry.get("file")

        # Skip invalid or non-existing files
        if not file_path or not os.path.exists(file_path):
            continue

        # Get filename only (lowercase for safe comparison)
        name = os.path.basename(file_path).lower()

        # Relative path inside USB (helps detect root-level placement)
        rel = os.path.relpath(file_path, usb_path)

        # --------------------------------------------------
        # AUTORUN RELATED RULES
        # --------------------------------------------------

        # Direct autorun file present (common malware auto execution method)
        if name == "autorun.inf":
            add(rule_hits, "AUTORUN_PRESENT", file_path)
            total_score += RULES["AUTORUN_PRESENT"]["score"]

        # Fake autorun trick (autorun.inf.exe etc)
        if name.startswith("autorun.inf.") and not name.endswith(".inf"):
            add(rule_hits, "AUTORUN_SPOOFING", file_path)
            total_score += RULES["AUTORUN_SPOOFING"]["score"]

        # Autorun executable attempt
        if name.startswith("autorun") and name.endswith(".exe"):
            add(rule_hits, "AUTORUN_EXECUTABLE", file_path)
            total_score += RULES["AUTORUN_EXECUTABLE"]["score"]

        # --------------------------------------------------
        # SCRIPT RULES (PowerShell, VBS, BAT etc)
        # --------------------------------------------------

        if name.endswith(SCRIPT_EXTENSIONS):
            script_count += 1

            # Script placed in USB root = suspicious
            if os.path.dirname(rel) == ".":
                add(rule_hits, "SCRIPT_IN_ROOT", file_path)
                total_score += RULES["SCRIPT_IN_ROOT"]["score"]

            # Check if script is obfuscated
            if is_obfuscated_script(file_path):
                add(rule_hits, "OBFUSCATED_SCRIPT", file_path)
                total_score += RULES["OBFUSCATED_SCRIPT"]["score"]

        # --------------------------------------------------
        # EXECUTABLE RULES
        # --------------------------------------------------

        if name.endswith(EXECUTABLE_EXTENSIONS):
            exe_count += 1

            # Executable in USB root (common drop location)
            if os.path.dirname(rel) == ".":
                add(rule_hits, "EXE_IN_ROOT", file_path)
                total_score += RULES["EXE_IN_ROOT"]["score"]

            # Known suspicious file naming patterns
            if name in SUSPICIOUS_NAMES:
                add(rule_hits, "SUSPICIOUS_FILENAME", file_path)
                total_score += RULES["SUSPICIOUS_FILENAME"]["score"]

            # Double extension trick detection (file.jpg.exe)
            if is_disguised_exec(name):
                add(rule_hits, "DOUBLE_EXTENSION_EXEC", file_path)
                total_score += RULES["DOUBLE_EXTENSION_EXEC"]["score"]

            # Packed executable detection (entropy based)
            if is_packed_exec(file_path):
                add(rule_hits, "PACKED_EXECUTABLE", file_path)
                total_score += RULES["PACKED_EXECUTABLE"]["score"]

    # --------------------------------------------------
    # COMBO RULES (Behavior Correlation)
    # --------------------------------------------------

    # Too many executables → suspicious payload distribution
    if exe_count > 3:
        add(rule_hits, "MULTIPLE_EXECUTABLES", "MULTIPLE_FILES")
        total_score += RULES["MULTIPLE_EXECUTABLES"]["score"]

    # Script + executable combo → typical malware chain
    if exe_count > 0 and script_count > 0:
        add(rule_hits, "SCRIPT_EXE_COMBO", "USB_ROOT")
        total_score += RULES["SCRIPT_EXE_COMBO"]["score"]

    # Return final rule risk score + triggered rules
    return total_score, rule_hits


# =====================================================
# HELPER FUNCTIONS
# =====================================================

def add(hits, rule, file_path):
    """
    Add triggered rule info into hit list.
    """
    hits.append({
        "file": file_path,
        "rule": rule,
        "score": RULES[rule]["score"]
    })


def is_disguised_exec(name):
    """
    Detect double extension attacks like:
    invoice.pdf.exe
    photo.jpg.exe
    """
    return re.match(DOUBLE_EXT_PATTERN, name) is not None


def is_packed_exec(path):
    """
    Detect packed / encrypted executables using entropy + size check.
    """
    try:
        size_kb = os.path.getsize(path) / 1024

        # Ignore very small files
        if size_kb < MIN_EXEC_SIZE_KB:
            return False

        entropy = calculate_entropy(path)

        # High entropy → likely packed / encrypted
        return entropy >= EXEC_ENTROPY_THRESHOLD
    except Exception:
        return False


def is_obfuscated_script(path):
    """
    Detect script obfuscation using:
    - Entropy
    - Abnormally long lines
    """
    try:
        with open(path, "r", errors="ignore") as f:
            data = f.read(4096)

        # Empty script not suspicious
        if not data.strip():
            return False

        # Entropy check
        entropy = calculate_entropy(path)
        if entropy >= SCRIPT_ENTROPY_THRESHOLD:
            return True

        # Very long script lines → possible obfuscation
        for line in data.splitlines():
            if len(line) > MAX_SCRIPT_LINE_LEN:
                return True

        return False
    except Exception:
        return False


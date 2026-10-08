"""
NetSentinel — Configuration
Detection thresholds and server limits, kept out of the Flask app so the
detector, API and tests all share a single source of truth.
Everything is local. No external APIs.
"""

# ============================================================
# DETECTION THRESHOLDS — Editable defaults
# ============================================================

DETECTION_CONFIG = {
    "packets_per_source": 50,
    "unique_destinations": 10,
    "unique_ports": 10,
    "icmp_threshold": 30,
    "dns_threshold": 30,
    "repeated_communication": 40,
    "syn_threshold": 30,
    "traffic_spike_multiplier": 5,
    "time_window": 30,
}

# Only these keys may be changed at runtime via POST /api/reload
ALLOWED_CONFIG_KEYS = set(DETECTION_CONFIG)

# Live packet buffer: bounded so memory cannot grow forever
PACKET_BUFFER_SIZE = 50_000


def validate_config_update(data):
    """
    Validate a configuration update payload.
    Returns (cleaned_dict, error_message). Unknown keys are ignored;
    known keys must be numbers >= 1.
    """
    if not isinstance(data, dict):
        return None, "Invalid payload: expected a JSON object"

    cleaned = {}
    for key, value in data.items():
        if key not in ALLOWED_CONFIG_KEYS:
            continue  # ignore unknown keys silently

        # bool is a subclass of int — reject it explicitly
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return None, f"Invalid value for {key}: must be a number"

        if value < 1:
            return None, f"{key} must be a positive number (>= 1)"

        cleaned[key] = value

    return cleaned, None

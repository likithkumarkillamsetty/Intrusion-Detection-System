"""
signatures.py
Contains predefined attack signatures, thresholds, and rules.
"""

# Hardcoded lists of known malicious IPs (for demonstration)
BLACKLISTED_IPS = {
    "192.168.1.100", 
    "10.0.0.50",
    "203.0.113.5"
}

# Known Suspicious Ports (e.g., Telnet, SMB, RDP)
SUSPICIOUS_PORTS = [23, 21, 22, 445, 3389, 443, 80]

# Rule thresholds for anomaly detection
RULES = {
    # SYN flood: Max SYN packets from a single source within the time window
    "syn_flood_threshold": 50,  
    # Port scan: Max distinct destination ports accessed by a single source within the time window
    "port_scan_threshold": 15,  
    # Time window in seconds for the above rules
    "time_window": 10
}

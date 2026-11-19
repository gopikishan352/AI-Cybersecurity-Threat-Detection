"""
Cybersecurity and NSL-KDD Constants, Attack Mappings, and SOC Intelligence Definitions.
"""

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

FEATURE_COLUMNS = COLUMNS[:-2]  # First 41 columns are input features

CATEGORICAL_COLUMNS = ["protocol_type", "service", "flag"]

# Full NSL-KDD attack mapping to 5 standard classes
ATTACK_MAP = {
    # Normal
    "normal": "Normal",
    
    # Denial of Service (DoS)
    "apache2": "DoS",
    "back": "DoS",
    "land": "DoS",
    "neptune": "DoS",
    "mailbomb": "DoS",
    "pod": "DoS",
    "processtable": "DoS",
    "smurf": "DoS",
    "teardrop": "DoS",
    "udpstorm": "DoS",
    
    # Surveillance / Probe
    "ipsweep": "Probe",
    "mscan": "Probe",
    "nmap": "Probe",
    "portsweep": "Probe",
    "saint": "Probe",
    "satan": "Probe",
    
    # Remote to Local (R2L)
    "ftp_write": "R2L",
    "guess_passwd": "R2L",
    "httptunnel": "R2L",
    "imap": "R2L",
    "multihop": "R2L",
    "named": "R2L",
    "phf": "R2L",
    "sendmail": "R2L",
    "snmpgetattack": "R2L",
    "snmpguess": "R2L",
    "spy": "R2L",
    "warezclient": "R2L",
    "warezmaster": "R2L",
    "xlock": "R2L",
    "xsnoop": "R2L",
    "worm": "R2L",
    
    # User to Root (U2R)
    "buffer_overflow": "U2R",
    "loadmodule": "U2R",
    "perl": "U2R",
    "ps": "U2R",
    "rootkit": "U2R",
    "sqlattack": "U2R",
    "xterm": "U2R"
}

THREAT_CATEGORIES = ["Normal", "DoS", "Probe", "R2L", "U2R"]

RISK_LEVELS = {
    "Normal": "LOW",
    "Probe": "MEDIUM",
    "DoS": "HIGH",
    "R2L": "CRITICAL",
    "U2R": "CRITICAL"
}

RISK_COLORS = {
    "LOW": "#22c55e",
    "MEDIUM": "#f59e0b",
    "HIGH": "#f97316",
    "CRITICAL": "#ef4444"
}

THREAT_COLORS = {
    "Normal": "#22c55e",
    "DoS": "#f97316",
    "Probe": "#3b82f6",
    "R2L": "#a855f7",
    "U2R": "#ef4444"
}

# Baseline SOC rule-based explanations and defensive playbooks
THREAT_INTELLIGENCE = {
    "Normal": {
        "description": "Traffic patterns conform to expected baseline communication protocols without anomalous flags or packet volume spikes.",
        "impact": "None. Normal legitimate network activity.",
        "action": "Maintain standard telemetry monitoring and baseline profiling."
    },
    "DoS": {
        "description": "Denial of Service attack detected. Characterized by abnormal flood patterns, sync-drop states, or resource-exhaustion traffic aiming to degrade service availability.",
        "impact": "Service degradation, network latency, resource exhaustion on targeted endpoints.",
        "action": "Enforce rate limiting, drop connections from source CIDR blocks, activate anti-DDoS scrubbing, and inspect edge router filters."
    },
    "Probe": {
        "description": "Surveillance or Reconnaissance probe detected. Network scanning, ICMP sweeps, or port discovery attempts mapping active services and system architecture.",
        "impact": "Information disclosure of open ports and operating system fingerprints preceding targeted exploitation.",
        "action": "Block offending source IP at border firewall, enable honeypot lures, review ingress filtering rules, and alert SOC tier-1 analysts."
    },
    "R2L": {
        "description": "Remote-to-Local unauthorized access attempt detected. Exploits authentication weaknesses or configuration flaws to establish local access from an external origin.",
        "impact": "Unauthorized system access, credential compromise, initial foothold establishment.",
        "action": "Immediately revoke compromised session tokens, enforce MFA, lock targeted accounts, inspect auth logs, and isolate affected services."
    },
    "U2R": {
        "description": "User-to-Root privilege escalation attempt detected. Local non-privileged user attempting execution of unauthorized root/administrator shell or kernel buffer exploit.",
        "impact": "Full endpoint takeover, ring-0/root access, unauthorized kernel module execution, data tampering.",
        "action": "Initiate immediate endpoint containment, terminate suspect PID processes, preserve volatile memory for forensics, and patch local vulnerabilities."
    }
}

# Presets for quick UI testing (exact 41 NSL-KDD features)
PRESET_SAMPLES = {
    "normal": {
        "name": "Normal Web Browsing (HTTP)",
        "features": [0, "tcp", "http", "SF", 215, 45076, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
        "expected": "Normal"
    },
    "dos": {
        "name": "DoS SYN Flood (Neptune)",
        "features": [0, "tcp", "private", "S0", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 123, 6, 1.0, 1.0, 0.0, 0.0, 0.05, 0.07, 0.0, 255, 6, 0.02, 0.07, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0],
        "expected": "DoS"
    },
    "probe": {
        "name": "Reconnaissance Port Sweep (Portsweep)",
        "features": [0, "tcp", "private", "SH", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 255, 1, 0.0, 0.74, 0.0, 0.0, 0.0, 0.0, 0.98, 0.85],
        "expected": "Probe"
    },
    "r2l": {
        "name": "R2L Password Guessing (Guess_Passwd)",
        "features": [0, "tcp", "telnet", "SF", 126, 179, 0, 0, 0, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 255, 1, 0.0, 0.02, 0.01, 0.0, 0.0, 0.0, 0.0, 0.0],
        "expected": "R2L"
    }
}
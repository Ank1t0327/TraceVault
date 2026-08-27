from dataclasses import dataclass
from typing import List, Dict

@dataclass
class CorrelationNode:
    title: str          # e.g., 'SSH Brute Force', 'Successful Login', 'Suspicious File Download'
    source: str         # e.g., 'auth.log', 'browser', 'filesystem', 'proc'
    timestamp: str      # e.g., '10:02:14'
    description: str   # Brief description

# Risk Weights for findings
RISK_WEIGHTS = {
    "FAILED_AUTH_SERIES": 15,
    "SUCCESSFUL_LOGIN_AFTER_BRUTE": 25,
    "SUSPICIOUS_DOWNLOAD": 20,
    "EXECUTABLE_CREATED": 20,
    "MALICIOUS_PROCESS": 25,
    "PERSISTENCE_ADDED": 15
}

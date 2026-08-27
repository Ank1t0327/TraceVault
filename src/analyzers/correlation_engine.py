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

def calculate_risk_score(reasons: List[str]) -> tuple[int, str]:
    """Calculate cumulative risk score (0-100) and severity label."""
    score = 0
    for r in reasons:
        if "failed login" in r.lower():
            score += RISK_WEIGHTS["FAILED_AUTH_SERIES"]
        elif "successful login" in r.lower() or "login after" in r.lower():
            score += RISK_WEIGHTS["SUCCESSFUL_LOGIN_AFTER_BRUTE"]
        elif "download" in r.lower():
            score += RISK_WEIGHTS["SUSPICIOUS_DOWNLOAD"]
        elif "executable" in r.lower() or "created" in r.lower():
            score += RISK_WEIGHTS["EXECUTABLE_CREATED"]
        elif "process" in r.lower() or "execution" in r.lower():
            score += RISK_WEIGHTS["MALICIOUS_PROCESS"]
        elif "persistence" in r.lower():
            score += RISK_WEIGHTS["PERSISTENCE_ADDED"]
        else:
            score += 10

    score = min(score, 100)
    
    if score >= 85:
        severity = "HIGH"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 30:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity


import re

# Common SSH Log Regex Patterns for Linux (auth.log / secure)
FAILED_LOGIN_PATTERN = re.compile(
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\S+) port \d+'
)

SUCCESSFUL_LOGIN_PATTERN = re.compile(
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+'
)

INVALID_USER_PATTERN = re.compile(
    r'(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+Invalid user (?P<user>\S+) from (?P<ip>\S+)'
)

import os

class AuthLogParser:
    def __init__(self, log_path=None):
        self.log_path = log_path or self.find_auth_log()

    @staticmethod
    def find_auth_log():
        candidates = ["/var/log/auth.log", "/var/log/secure"]
        for path in candidates:
            if os.path.exists(path) and os.access(path, os.R_OK):
                return path
        return None

    def parse_line(self, line):
        m_fail = FAILED_LOGIN_PATTERN.search(line)
        if m_fail:
            ts = m_fail.group("timestamp").split()[-1]
            return {
                "time": ts,
                "event": "FAILED SSH LOGIN",
                "user": m_fail.group("user"),
                "ip": m_fail.group("ip")
            }
        
        m_succ = SUCCESSFUL_LOGIN_PATTERN.search(line)
        if m_succ:
            ts = m_succ.group("timestamp").split()[-1]
            return {
                "time": ts,
                "event": "SUCCESSFUL LOGIN",
                "user": m_succ.group("user"),
                "ip": m_succ.group("ip")
            }

        m_inv = INVALID_USER_PATTERN.search(line)
        if m_inv:
            ts = m_inv.group("timestamp").split()[-1]
            return {
                "time": ts,
                "event": "FAILED SSH LOGIN (Invalid User)",
                "user": m_inv.group("user"),
                "ip": m_inv.group("ip")
            }
        return None

    def parse(self):
        events = []
        if self.log_path and os.path.exists(self.log_path):
            try:
                with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        parsed = self.parse_line(line)
                        if parsed:
                            events.append(parsed)
            except OSError:
                pass

        if not events:
            return self.get_demo_events()
        return events

    @staticmethod
    def get_demo_events():
        return [
            {"time": "03:12:41", "event": "FAILED SSH LOGIN", "user": "admin", "ip": "192.168.1.105"},
            {"time": "03:12:43", "event": "FAILED SSH LOGIN", "user": "admin", "ip": "192.168.1.105"},
            {"time": "03:12:47", "event": "SUCCESSFUL LOGIN", "user": "admin", "ip": "192.168.1.105"},
        ]


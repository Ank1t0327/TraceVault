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

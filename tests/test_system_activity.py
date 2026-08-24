import os
import tempfile
import pytest
from src.parsers.auth_log import AuthLogParser
from src.parsers.user_activity import parse_shell_history, parse_user_accounts
from src.parsers.system_info import parse_cron_jobs, parse_running_processes

def test_auth_log_parser():
    sample_log = (
        "Aug 14 03:12:41 ubuntu sshd[1234]: Failed password for admin from 192.168.1.105 port 54321 ssh2\n"
        "Aug 14 03:12:43 ubuntu sshd[1234]: Failed password for admin from 192.168.1.105 port 54322 ssh2\n"
        "Aug 14 03:12:47 ubuntu sshd[1234]: Accepted password for admin from 192.168.1.105 port 54323 ssh2\n"
    )
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(sample_log)
        temp_path = f.name

    try:
        parser = AuthLogParser(log_path=temp_path)
        events = parser.parse()
        assert len(events) == 3
        assert events[0]["event"] == "FAILED SSH LOGIN"
        assert events[2]["event"] == "SUCCESSFUL LOGIN"
        assert events[0]["user"] == "admin"
        assert events[0]["ip"] == "192.168.1.105"
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_user_accounts_parser():
    sample_passwd = (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "admin:x:1000:1000:admin:/home/admin:/bin/bash\n"
    )
    with tempfile.NamedTemporaryFile("w+", delete=False) as f:
        f.write(sample_passwd)
        temp_path = f.name

    try:
        users = parse_user_accounts(passwd_file=temp_path)
        assert len(users) == 3
        interactive = [u["username"] for u in users if u["is_interactive"]]
        assert "root" in interactive
        assert "admin" in interactive
        assert "daemon" not in interactive
    finally:
        if os.path.exists(temp_path):
            os.remove(temp_path)

def test_process_and_cron_call():
    # Smoke test function calls
    procs = parse_running_processes()
    crons = parse_cron_jobs()
    assert isinstance(procs, list)
    assert isinstance(crons, list)

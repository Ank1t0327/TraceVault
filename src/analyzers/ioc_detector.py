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



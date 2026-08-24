import os

def parse_cron_jobs():
    """Inspect Linux system and user cron jobs."""
    cron_jobs = []
    cron_files = ["/etc/crontab"]
    cron_dirs = ["/etc/cron.d", "/var/spool/cron/crontabs"]

    for d in cron_dirs:
        if os.path.exists(d) and os.path.isdir(d):
            try:
                for f in os.listdir(d):
                    cron_files.append(os.path.join(d, f))
            except OSError:
                pass

    for file_path in cron_files:
        if os.path.exists(file_path) and os.access(file_path, os.R_OK):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#") and not "=" in line.split()[0]:
                            cron_jobs.append({
                                "source": file_path,
                                "entry": line
                            })
            except OSError:
                pass
    return cron_jobs

def parse_running_processes():
    """Enumerate running processes from Linux /proc filesystem."""
    processes = []
    proc_dir = "/proc"
    if not os.path.exists(proc_dir):
        return processes

    for entry in os.listdir(proc_dir):
        if entry.isdigit():
            pid = int(entry)
            cmdline_path = os.path.join(proc_dir, entry, "cmdline")
            if os.path.exists(cmdline_path) and os.access(cmdline_path, os.R_OK):
                try:
                    with open(cmdline_path, "rb") as f:
                        content = f.read().replace(b'\x00', b' ').decode('utf-8', errors='ignore').strip()
                        if content:
                            processes.append({
                                "pid": pid,
                                "cmdline": content
                            })
                except OSError:
                    pass
    return processes


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

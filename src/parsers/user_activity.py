import os

def parse_shell_history(history_file_path=None):
    """Parse shell history files (.bash_history, .zsh_history)."""
    if not history_file_path:
        home = os.path.expanduser("~")
        for candidate in [".bash_history", ".zsh_history"]:
            path = os.path.join(home, candidate)
            if os.path.exists(path) and os.access(path, os.R_OK):
                history_file_path = path
                break

    commands = []
    if history_file_path and os.path.exists(history_file_path):
        try:
            with open(history_file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    cmd = line.strip()
                    # Filter zsh timestamp formats e.g. : 1600000000:0;command
                    if cmd.startswith(": ") and ";" in cmd:
                        cmd = cmd.split(";", 1)[1]
                    if cmd:
                        commands.append(cmd)
        except OSError:
            pass
    return commands

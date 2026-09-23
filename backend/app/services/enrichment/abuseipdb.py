from pathlib import Path

BLOCKLIST_FILES = [
    Path("/opt/aegis/blocklists/et-compromised.txt"),
    Path("/opt/aegis/blocklists/feodo.txt"),
    Path("/opt/aegis/blocklists/ci-badguys.txt"),
]

def is_abusive_ip(ip: str) -> bool:
    for bl in BLOCKLIST_FILES:
        if not bl.exists():
            continue
        try:
            if ip.strip() in bl.read_text(encoding="utf-8", errors="ignore").splitlines():
                return True
        except Exception:
            continue
    return False

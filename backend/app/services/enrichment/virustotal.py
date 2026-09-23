import yara
from pathlib import Path

RULES_DIR = Path("/opt/aegis/yara-rules")

def scan_file(file_path: str) -> dict:
    if not RULES_DIR.exists():
        return {"source": "yara_local", "matches": [], "status": "rules_not_found"}

    try:
        if RULES_DIR.is_dir():
            rule_files = {f"rule_{i}": str(p) for i, p in enumerate(RULES_DIR.rglob("*.yar*"))}
            if not rule_files:
                return {"source": "yara_local", "matches": [], "status": "rules_not_found"}
            rules = yara.compile(filepaths=rule_files)
        else:
            rules = yara.compile(str(RULES_DIR))

        matches = rules.match(file_path)

        return {
            "source": "yara_local",
            "file": file_path,
            "matches": [m.rule for m in matches],
            "malicious": len(matches) > 0
        }
    except Exception as e:
        return {
            "source": "yara_local",
            "file": file_path,
            "matches": [],
            "malicious": False,
            "error": str(e)
        }

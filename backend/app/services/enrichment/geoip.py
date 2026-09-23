import csv
import ipaddress
import os
from pathlib import Path

# Check container path or local data path
_DEFAULT_PATH = Path("/opt/aegis/geoip/dbip-city-lite.csv")
_LOCAL_FALLBACK = Path(__file__).resolve().parent.parent.parent / "data" / "dbip-city-lite.csv"

DBIP_CSV = _DEFAULT_PATH if _DEFAULT_PATH.exists() else _LOCAL_FALLBACK

def lookup_ip(ip: str) -> dict:
    csv_file = DBIP_CSV if DBIP_CSV.exists() else _DEFAULT_PATH
    if not csv_file.exists():
        return {"ip": ip, "country": "unknown", "source": "dbip_lite_local"}

    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "country": "unknown", "source": "dbip_lite_local"}

    try:
        with open(csv_file, newline="", encoding="utf-8", errors="ignore") as f:
            for row in csv.reader(f):
                try:
                    if ipaddress.ip_address(row[0]) <= target <= ipaddress.ip_address(row[1]):
                        return {
                            "ip": ip,
                            "country": row[2] if len(row) > 2 else "unknown",
                            "region": row[3] if len(row) > 3 else "",
                            "city": row[4] if len(row) > 4 else "",
                            "source": "dbip_lite_local"
                        }
                except Exception:
                    continue
    except Exception:
        pass

    return {"ip": ip, "country": "unknown", "source": "dbip_lite_local"}

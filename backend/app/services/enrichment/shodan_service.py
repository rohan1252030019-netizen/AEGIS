import subprocess
import xml.etree.ElementTree as ET

def scan_host(ip: str) -> dict:
    try:
        result = subprocess.run(
            ["nmap", "-sV", "-Pn", "--open", "-oX", "-", ip],
            capture_output=True, text=True, timeout=30
        )
        root = ET.fromstring(result.stdout)
        ports = []

        for port in root.findall(".//port"):
            service = port.find("service")
            ports.append({
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": service.get("name") if service is not None else "unknown"
            })

        return {"ip": ip, "source": "nmap_local", "ports": ports}

    except Exception as e:
        return {"ip": ip, "source": "nmap_local", "error": str(e), "ports": []}

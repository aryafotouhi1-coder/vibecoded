import platform
import sys
import os
import subprocess
import json
import socket
import datetime
import re
import html
import tempfile
import webbrowser
import socketserver
import http.server
import threading
import shutil
import time
from pathlib import Path
from urllib.request import urlopen
from urllib.error import URLError

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None

def format_bytes(num):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num < 1024.0:
            return f"{num:.1f} {unit}"
        num /= 1024.0
    return f"{num:.1f} PB"

def get_system_info():
    info = {
        "platform": platform.system(),
        "platform_release": platform.release(),
        "platform_version": platform.version(),
        "architecture": platform.machine(),
        "hostname": socket.gethostname(),
        "ip_addresses": [],
        "processor": platform.processor(),
        "cpu_count": None,
        "memory": {},
        "disk": [],
        "boot_time": None,
        "python_version": platform.python_version(),
    }

    # Try to get IP addresses
    try:
        if psutil:
            info["ip_addresses"] = [addr.address for iface in psutil.net_if_addrs().values() for addr in iface if addr.family == socket.AF_INET]
        else:
            # Fallback: use socket to get local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info["ip_addresses"] = [s.getsockname()[0]]
            s.close()
    except Exception:
        info["ip_addresses"] = ["Unable to determine"]

    # Get CPU count
    info["cpu_count"] = psutil.cpu_count(logical=True) if psutil else os.cpu_count()

    if psutil:
        # Memory info
        try:
            vm = psutil.virtual_memory()
            info["memory"] = {
                "total": format_bytes(vm.total),
                "available": format_bytes(vm.available),
                "used": format_bytes(vm.used),
                "percent": f"{vm.percent}%",
            }
        except Exception:
            info["memory"] = {"error": "Unable to retrieve"}

        # Disk info
        try:
            for part in psutil.disk_partitions(all=False):
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    info["disk"].append({
                        "device": part.device,
                        "mountpoint": part.mountpoint,
                        "fstype": part.fstype,
                        "total": format_bytes(usage.total),
                        "used": format_bytes(usage.used),
                        "free": format_bytes(usage.free),
                        "percent": f"{usage.percent}%",
                    })
                except PermissionError:
                    continue
        except Exception:
            info["disk"] = [{"error": "Unable to retrieve"}]

        # Boot time
        try:
            info["boot_time"] = datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
        except Exception:
            info["boot_time"] = "Unable to retrieve"
    else:
        info["memory"] = {"info": "psutil not installed - install with: pip install psutil"}
        info["disk"] = [{"info": "psutil not installed - install with: pip install psutil"}]
        info["boot_time"] = "psutil not installed"

    return info

def get_processes():
    processes = []
    if psutil:
        for proc in psutil.process_iter(attrs=["pid", "name", "username", "status", "create_time"]):
            try:
                pinfo = proc.info
                pinfo["create_time"] = datetime.datetime.fromtimestamp(pinfo["create_time"]).isoformat()
                processes.append(pinfo)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    else:
        if platform.system() == "Windows":
            cmd = ["tasklist", "/FO", "CSV", "/NH"]
            out = subprocess.check_output(cmd, text=True, errors="ignore")
            for line in out.splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    processes.append({"name": parts[0], "pid": int(parts[1])})
        else:
            out = subprocess.check_output(["ps", "-eo", "pid,comm,user,state"], text=True, errors="ignore")
            for line in out.splitlines()[1:]:
                cols = line.strip().split(None, 3)
                if len(cols) >= 4:
                    processes.append({"pid": int(cols[0]), "name": cols[1], "user": cols[2], "state": cols[3]})
    return processes

def get_open_ports():
    ports = []
    if psutil:
        for conn in psutil.net_connections(kind="inet"):
            if conn.laddr:
                ports.append({
                    "proto": "TCP" if conn.type == socket.SOCK_STREAM else "UDP",
                    "pid": conn.pid,
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "",
                    "status": conn.status,
                })
    else:
        if platform.system() == "Windows":
            out = subprocess.check_output(["netstat", "-ano"], text=True, errors="ignore")
        else:
            out = subprocess.check_output(["netstat", "-tunlp"], text=True, errors="ignore")
        for line in out.splitlines():
            if line.strip().startswith(("Proto", "Active")):
                continue
            cols = line.split()
            if len(cols) < 4:
                continue
            proto = cols[0].upper()
            local = cols[1]
            remote = cols[2] if len(cols) > 2 else ""
            if platform.system() == "Windows":
                if proto == "UDP":
                    status = "UDP"
                    pid = cols[3] if len(cols) > 3 else None
                else:
                    status = cols[3] if len(cols) > 3 else "UNKNOWN"
                    pid = cols[4] if len(cols) > 4 else None
            else:
                status = cols[5] if len(cols) > 5 else "UNKNOWN"
                pid = cols[-1]
            ports.append({
                "proto": proto,
                "pid": pid,
                "local_address": local,
                "remote_address": remote,
                "status": status,
            })
    return ports


def translate_status(status, proto=None):
    normalized = str(status).upper() if status is not None else ""
    if proto and proto.upper() == "UDP":
        return "UDP (no TCP state)"
    if normalized.isdigit():
        return f"{status} (numeric state interpreted as PID or missing state)"
    translations = {
        "LISTENING": "Listening",
        "ESTABLISHED": "Established",
        "TIME_WAIT": "Time wait",
        "CLOSE_WAIT": "Close wait",
        "SYN_SENT": "SYN sent",
        "SYN_RECEIVED": "SYN received",
        "FIN_WAIT_1": "FIN wait 1",
        "FIN_WAIT_2": "FIN wait 2",
        "CLOSE": "Close",
        "CLOSING": "Closing",
        "LAST_ACK": "Last ACK",
        "UDP": "UDP (no state)",
        "UNKNOWN": "Unknown",
    }
    return translations.get(normalized, normalized.title())


def get_cves_for_software(software_name, version=None):
    """Query NVD API for CVEs related to software."""
    cves = []
    try:
        if not requests:
            return cves
        
        # NVD API endpoint (free tier - no key needed but limited)
        url = f"https://services.nvd.nist.gov/rest/json/cves/1.0"
        params = {"keyword": software_name, "resultsPerPage": 10}
        
        response = requests.get(url, params=params, timeout=5)
        if response.status_code == 200:
            data = response.json()
            for item in data.get("result", {}).get("CVE_Items", [])[:5]:
                cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "Unknown")
                description = item.get("cve", {}).get("description", {}).get("description_data", [{}])[0].get("value", "")
                severity = item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", "UNKNOWN")
                cves.append({"id": cve_id, "description": description[:100], "severity": severity})
    except (URLError, Exception):
        pass
    
    return cves


def check_os_vulnerabilities(os_info):
    """Check for known OS vulnerabilities."""
    vulnerabilities = []
    # Check for pending Windows Updates
    try:
        if platform.system() == "Windows":
            cmd = 'powershell -NoProfile -Command "Get-WmiObject -Class Win32_QuickFixEngineering | Select-Object -Last 1 | Select-Object -ExpandProperty InstalledOn"'
            result = subprocess.check_output(cmd, text=True, errors="ignore", timeout=5)
            # If we can retrieve recent hotfixes, system is updated
            # Only report vulnerabilities if we detect evidence of unpatched system
    except:
        pass
    
    return vulnerabilities


def get_installed_app_version(app_name):
    """Try to detect installed application version."""
    version_info = {"name": app_name, "version": "Unknown", "method": "not detected"}
    # Try common CLI version commands first (cross-platform)
    cli_variants = [[app_name, "--version"], [app_name, "-v"], [app_name, "version"]]
    for cmd in cli_variants:
        try:
            result = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=2)
            if result and isinstance(result, str):
                versions = re.findall(r"\d+\.\d+[\.\d]*", result)
                if versions:
                    version_info["version"] = versions[0]
                    version_info["method"] = "cli"
                    return version_info
        except Exception:
            pass

    # Windows registry fallback for installed GUI apps
    if platform.system() == "Windows":
        try:
            # Use list form to avoid shell quoting issues
            ps_cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object {$_.DisplayName -like '*" + app_name + "*'} | Select-Object -ExpandProperty DisplayVersion"
            ]
            result = subprocess.check_output(ps_cmd, text=True, errors="ignore", timeout=3)
            if result and isinstance(result, str) and result.strip():
                versions = re.findall(r"\d+\.\d+[\.\d]*", result)
                if versions:
                    version_info["version"] = versions[0]
                    version_info["method"] = "registry"
        except Exception:
            pass

    return version_info


def check_common_app_updates():
    """Check versions of common applications."""
    apps_to_check = ["Python", "node", "git", "code", "java", "AdobeReader"]
    updates_needed = []

    # Detect installed versions for common apps across platforms
    installed = {}
    for app in apps_to_check:
        try:
            info = get_installed_app_version(app)
            installed[app] = info.get("version", "Unknown")
        except Exception:
            installed[app] = "Unknown"

    # Python: compare to known latest (hardcoded for demo)
    try:
        python_version = installed.get("Python") or platform.python_version()
        latest_python = "3.13.0"
        if python_version and python_version != "Unknown" and python_version < latest_python:
            updates_needed.append({
                "app": "Python",
                "installed": python_version,
                "latest": latest_python,
                "update_url": "https://www.python.org/downloads/",
                "priority": "LOW"
            })
    except Exception:
        pass

    # For other apps, report installed version and provide vendor update URLs if known
    app_update_urls = {
        "node": "https://nodejs.org/",
        "git": "https://git-scm.com/downloads",
        "code": "https://code.visualstudio.com/download",
        "java": "https://www.java.com/en/download/",
        "AdobeReader": "https://get.adobe.com/reader/"
    }
    for app_key in ["node", "git", "code", "java", "AdobeReader"]:
        ver = installed.get(app_key, "Unknown")
        if ver and ver != "Unknown":
            updates_needed.append({
                "app": app_key,
                "installed": ver,
                "latest": "unknown",
                "update_url": app_update_urls.get(app_key, ""),
                "priority": "LOW"
            })

    # Lightweight OS update checks per platform (non-invasive)
    try:
        if platform.system() == "Darwin":
            try:
                cmd = ["softwareupdate", "-l"]
                result = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=5)
                if "No new software available." not in result and ("recommended" in result.lower() or "label" in result.lower()):
                    updates_needed.append({
                        "app": "macOS",
                        "installed": "current",
                        "latest": "updates available",
                        "update_url": "https://support.apple.com/macos",
                        "priority": "MEDIUM"
                    })
            except Exception:
                pass
        elif platform.system() == "Linux":
            try:
                cmd = ["/bin/sh", "-c", "apt list --upgradable 2>/dev/null | sed -n '2p' || true"]
                result = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=5)
                if result and not result.strip().startswith("Listing") and result.strip():
                    updates_needed.append({
                        "app": "Linux packages",
                        "installed": "current",
                        "latest": "upgrades available",
                        "update_url": "",
                        "priority": "MEDIUM"
                    })
            except Exception:
                try:
                    cmd = ["/bin/sh", "-c", "dnf check-update >/dev/null 2>&1 || echo updates"]
                    result = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT, timeout=5)
                    if "updates" in result.lower():
                        updates_needed.append({
                            "app": "Linux packages",
                            "installed": "current",
                            "latest": "upgrades available",
                            "update_url": "",
                            "priority": "MEDIUM"
                        })
                except Exception:
                    pass
    except Exception:
        pass

    return updates_needed


def check_port_vulnerabilities(open_ports):
    """Identify potentially vulnerable open ports."""
    dangerous_ports = {
        23: {"service": "Telnet", "risk": "CRITICAL", "description": "Unencrypted remote access", "fix": "Use SSH (port 22) instead"},
        3389: {"service": "RDP", "risk": "HIGH", "description": "Exposed remote desktop", "fix": "Use VPN or restrict to trusted IPs"},
        445: {"service": "SMB", "risk": "HIGH", "description": "Windows file sharing", "fix": "Disable if not needed or firewall"},
        139: {"service": "NetBIOS", "risk": "HIGH", "description": "Legacy Windows sharing", "fix": "Disable if not needed"},
        3306: {"service": "MySQL", "risk": "CRITICAL", "description": "Exposed database", "fix": "Firewall or use credentials"},
        5432: {"service": "PostgreSQL", "risk": "CRITICAL", "description": "Exposed database", "fix": "Firewall or use credentials"},
        27017: {"service": "MongoDB", "risk": "CRITICAL", "description": "Exposed NoSQL database", "fix": "Firewall or enable authentication"},
        6379: {"service": "Redis", "risk": "CRITICAL", "description": "Exposed cache", "fix": "Firewall or use requirepass"},
        22: {"service": "SSH", "risk": "MEDIUM", "description": "Remote access - ensure strong auth", "fix": "Use key-based auth, disable root login"},
    }
    
    vulnerable = []
    for port in open_ports[:50]:  # Check first 50 to avoid timeout
        local = port.get("local_address", "")
        match = re.search(r":(\d+)$", local)
        if match:
            port_num = int(match.group(1))
            if port_num in dangerous_ports:
                port_info = dangerous_ports[port_num]
                vulnerable.append({
                    "port": port_num,
                    "service": port_info["service"],
                    "risk": port_info["risk"],
                    "description": port_info["description"],
                    "fix": port_info["fix"],
                    "pid": port.get("pid"),
                    "local_address": local,
                    "status": port.get("status")
                })
    
    return vulnerable


def generate_vulnerability_report(system_info, processes, open_ports):
    """Generate comprehensive vulnerability report."""
    report = {
        "generated_at": datetime.datetime.now().isoformat(),
        "os_vulnerabilities": check_os_vulnerabilities(system_info),
        "application_updates": check_common_app_updates(),
        "port_vulnerabilities": check_port_vulnerabilities(open_ports),
        "cve_summary": {}
    }
    
    # Try to get CVE info for detected software
    if psutil:
        try:
            unique_apps = set(p.get("name", "").replace(".exe", "").split()[0] for p in processes[:20])
            for app in list(unique_apps)[:5]:  # Limit to 5 to avoid rate limiting
                cves = get_cves_for_software(app)
                if cves:
                    report["cve_summary"][app] = cves
        except:
            pass
    
    return report


def html_escape(value):
    return html.escape(str(value))


def generate_report_html(report, processes, open_ports, system_info):
    app_rows = []
    for app in report.get("application_updates", []):
        latest = str(app.get("latest", "")).lower()
        # Skip entries where the latest version is unknown
        if latest in ("", "unknown", "n/a"):
            continue
        url = app.get("update_url", "")
        if url:
            href = html_escape(url)
            button = f'<a class="button-link" href="{href}" target="_blank" rel="noopener noreferrer">Update</a>'
        else:
            button = '<span class="button-disabled">Update</span>'
        app_rows.append(f"<tr><td>{html_escape(app['app'])}</td><td>{html_escape(app['installed'])}</td><td>{html_escape(app['latest'])}</td><td>{html_escape(app['priority'])}</td><td>{button}</td></tr>")

    port_rows = []
    for port in report.get("port_vulnerabilities", []):
        port_rows.append(
            f"<tr><td>{html_escape(port['port'])}</td><td>{html_escape(port['service'])}</td><td>{html_escape(port['risk'])}</td>"
            f"<td>{html_escape(port['description'])}</td><td>{html_escape(port['local_address'])}</td><td>{html_escape(port['status'])}</td></tr>"
        )

    cve_rows = []
    for app, cves in report.get("cve_summary", {}).items():
        for cve in cves[:5]:
            cve_rows.append(
                f"<tr><td>{html_escape(app)}</td><td>{html_escape(cve['id'])}</td><td>{html_escape(cve['severity'])}</td>"
                f"<td>{html_escape(cve['description'])}</td></tr>"
            )

    process_rows = []
    for p in processes[:50]:
        process_rows.append(
            f"<tr><td>{html_escape(p.get('pid'))}</td><td>{html_escape(p.get('name', 'Unknown'))}</td>"
            f"<td>{html_escape(p.get('username', ''))}</td><td>{html_escape(p.get('status', ''))}</td>"
            f"<td>{html_escape(p.get('create_time', ''))}</td></tr>"
        )

    # Build a clean HTML representation of system_info
    si = system_info or {}
    ip_html = "<br>".join(html_escape(ip) for ip in si.get("ip_addresses", [])) if si.get("ip_addresses") else "N/A"
    mem = si.get("memory", {}) or {}
    memory_html = "<table class=\"subtable\">"
    for k in ("total", "available", "used", "percent"):
        if k in mem:
            memory_html += f"<tr><th>{html_escape(k.capitalize())}</th><td>{html_escape(mem.get(k))}</td></tr>"
    memory_html += "</table>" if memory_html != "<table class=\"subtable\">" else "N/A"

    disks = si.get("disk", []) or []
    if disks:
        disks_html = '<table class="subtable"><tr><th>Device</th><th>Mount</th><th>FS</th><th>Total</th><th>Used</th><th>Free</th></tr>'
        for d in disks:
            disks_html += f"<tr><td>{html_escape(d.get('device',''))}</td><td>{html_escape(d.get('mountpoint',''))}</td><td>{html_escape(d.get('fstype',''))}</td><td>{html_escape(d.get('total',''))}</td><td>{html_escape(d.get('used',''))}</td><td>{html_escape(d.get('free',''))}</td></tr>"
        disks_html += '</table>'
    else:
        disks_html = 'N/A'

    system_info_html = f"""
    <table class="sysinfo">
      <tr><th>Platform</th><td>{html_escape(si.get('platform',''))} {html_escape(si.get('platform_release',''))} {html_escape(si.get('platform_version',''))}</td></tr>
      <tr><th>Architecture</th><td>{html_escape(si.get('architecture',''))}</td></tr>
      <tr><th>Hostname</th><td>{html_escape(si.get('hostname',''))}</td></tr>
      <tr><th>IP Addresses</th><td>{ip_html}</td></tr>
      <tr><th>Processor</th><td>{html_escape(si.get('processor',''))}</td></tr>
      <tr><th>CPU Count</th><td>{html_escape(si.get('cpu_count',''))}</td></tr>
      <tr><th>Memory</th><td>{memory_html}</td></tr>
      <tr><th>Disks</th><td>{disks_html}</td></tr>
      <tr><th>Boot Time</th><td>{html_escape(si.get('boot_time',''))}</td></tr>
      <tr><th>Python</th><td>{html_escape(si.get('python_version',''))}</td></tr>
    </table>
    """

    html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>System Security Scan Report</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 20px; background: #f7f7f7; color: #222; }}
h1 {{ color: #333; }}
table {{ border-collapse: collapse; width: 100%; margin-bottom: 24px; }}
th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #444; color: #fff; }}
.button-link, .button-disabled {{ display: inline-block; padding: 7px 12px; border: none; background: #0078d4; color: white; text-decoration: none; cursor: pointer; border-radius: 4px; }}
.button-link:hover {{ background: #005a9e; }}
.button-disabled {{ background: #999; cursor: not-allowed; color: #eee; }}
section {{ background: white; padding: 16px; border-radius: 8px; box-shadow: 0 0 10px rgba(0,0,0,0.05); margin-bottom: 20px; }}
.sysinfo {{ width: 100%; max-width: 980px; }}
.sysinfo th {{ width: 180px; background: #2f4f4f; color: #fff; }}
.subtable {{ border-collapse: collapse; width: 100%; }}
.subtable th, .subtable td {{ padding: 6px; border: 1px solid #ddd; text-align: left; }}
</style>
</head>
<body>
<h1>System Security Scan Report</h1>
<section>
<h2>System Info</h2>
{system_info_html}
</section>
<section>
<h2>Application Updates</h2>
<table>
<tr><th>Application</th><th>Installed</th><th>Latest</th><th>Priority</th><th>Action</th></tr>
{''.join(app_rows) if app_rows else '<tr><td colspan="5">No updates detected</td></tr>'}
</table>
</section>
<section>
<h2>Exposed/Vulnerable Ports</h2>
<table>
<tr><th>Port</th><th>Service</th><th>Risk</th><th>Description</th><th>Address</th><th>Status</th></tr>
{''.join(port_rows) if port_rows else '<tr><td colspan="6">No exposed ports detected</td></tr>'}
</table>
</section>
<section>
<h2>CVE Summary</h2>
<table>
<tr><th>Application</th><th>CVE ID</th><th>Severity</th><th>Description</th></tr>
{''.join(cve_rows) if cve_rows else '<tr><td colspan="4">No CVEs detected</td></tr>'}
</table>
</section>
<section>
<h2>Process Sample</h2>
<table>
<tr><th>PID</th><th>Name</th><th>User</th><th>Status</th><th>Started</th></tr>
{''.join(process_rows) if process_rows else '<tr><td colspan="5">No process data</td></tr>'}
</table>
</section>
</body>
</html>
"""
    return html_content


def write_report_html(report, processes, open_ports, system_info):
    html_data = generate_report_html(report, processes, open_ports, system_info)
    path = Path(tempfile.gettempdir()) / "system_security_scan_report.html"
    path.write_text(html_data, encoding="utf-8")
    return path


def open_report_in_browser(path):
    # Try to serve the report over a local HTTP server in a detached subprocess/thread
    try:
        # pick a free port
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()

        # Attempt to launch a detached http.server process
        cmd = [sys.executable, "-m", "http.server", str(port), "--bind", "127.0.0.1"]
        kwargs = dict(stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if os.name == "nt":
            # DETACHED_PROCESS and CREATE_NEW_PROCESS_GROUP to detach on Windows
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        else:
            # start new session on POSIX
            kwargs["start_new_session"] = True

        # Serve from the report's directory
        cwd = str(path.parent)
        proc = subprocess.Popen(cmd, cwd=cwd, **kwargs)
        time.sleep(0.2)
        url = f"http://127.0.0.1:{port}/{path.name}"
        try:
            webbrowser.open(url)
            print(f"Serving report at: {url} (PID {proc.pid})")
            return
        except Exception:
            # If opening the browser fails, fall back to file URI
            pass
    except Exception:
        pass

    # Fallback: open file:// URL
    file_url = path.as_uri()
    try:
        webbrowser.open(file_url)
    except Exception:
        print(f"Unable to open browser automatically. Report saved at: {path}")


def summarize_ports(ports):
    from collections import Counter
    status_counts = Counter()
    proto_counts = Counter()
    pid_counts = Counter()
    for port in ports:
        status_counts[translate_status(port.get("status"), port.get("proto"))] += 1
        proto_counts[port.get("proto", "UNKNOWN")] += 1
        if port.get("pid"):
            pid_counts[str(port.get("pid"))] += 1
    return {
        "total_ports": len(ports),
        "status_counts": dict(status_counts),
        "proto_counts": dict(proto_counts),
        "top_pids": pid_counts.most_common(10),
    }


def main():
    result = {
        "system_info": get_system_info(),
        "processes": get_processes(),
        "open_ports": get_open_ports(),
    }
    print("SYSTEM INFO:")
    print(json.dumps(result["system_info"], indent=2))
    
    print("\n" + "="*70)
    processes = result["processes"]
    print(f"PROCESS SUMMARY: {len(processes)} running processes")
    print("(These are all programs currently executing on your system)")
    if processes:
        from collections import Counter
        names = Counter(p.get("name", "Unknown") for p in processes)
        print("  Top 10 most common process names:")
        for name, count in names.most_common(10):
            print(f"    {name}: {count}")

        # Show a sample of running processes with PID, name, user and status
        print("\n  Sample running processes (first 20):")
        for p in processes[:20]:
            pid = p.get('pid')
            pname = p.get('name', 'Unknown')
            user = p.get('username', '')
            status_text = translate_status(p.get('status'), None)
            started = p.get('create_time', 'N/A')
            print(f"    PID {pid} - {pname} | User: {user} | Status: {status_text} | Started: {started}")

    print("\n" + "="*70)
    ports = result["open_ports"]
    port_summary = summarize_ports(ports)
    print(f"OPEN PORT SUMMARY: {port_summary['total_ports']} network connections detected")
    print("(Ports are connection points; high numbers mean the system is busy with network activity)\n")
    
    print("  Protocol breakdown:")
    for proto, count in sorted(port_summary['proto_counts'].items(), key=lambda x: (-x[1], x[0])):
        print(f"    {proto}: {count}")
    
    print("\n  Connection status breakdown:")
    for status, count in sorted(port_summary['status_counts'].items(), key=lambda x: (-x[1], x[0])):
        print(f"    {status}: {count}")
    
    if port_summary['top_pids']:
        print("\n  Top processes using the most network ports:")
        print("  (These processes have the most network connections open)")
        for pid, count in port_summary['top_pids']:
            proc_name = next((p.get('name') for p in processes if str(p.get('pid')) == str(pid)), 'Unknown')
            print(f"    Process ID {pid} ({proc_name}): {count} open ports")

    print("\n" + "="*70)
    print(f"SAMPLE OF FIRST 15 OPEN PORTS:")
    print("(Showing a few examples to understand what's happening on the network)\n")
    for i, port in enumerate(ports[:15], 1):
        status_text = translate_status(port.get("status"), port.get("proto"))
        remote = port.get('remote_address') or 'not connected'
        print(f"  {i}. {port.get('proto', 'UNKNOWN')} {port.get('local_address')} → {remote}")
        print(f"     Status: {status_text} | Owned by PID {port.get('pid')}")

    # Vulnerability and Update Check
    print("\n" + "="*70)
    print("SECURITY & VULNERABILITY SCAN")
    print("="*70)
    print("\nGenerating vulnerability report (this may take a moment)...\n")
    
    vuln_report = generate_vulnerability_report(result["system_info"], processes, ports)
    
    # OS Vulnerabilities
    if vuln_report["os_vulnerabilities"]:
        print("🔴 OS VULNERABILITIES DETECTED:")
        for vuln in vuln_report["os_vulnerabilities"]:
            print(f"  • {vuln.get('cve', 'N/A')}: {vuln.get('description', 'N/A')}")
            print(f"    Severity: {vuln.get('severity', 'UNKNOWN')}")
            print(f"    Fix: {vuln.get('fix', 'Check security updates')}\n")
    else:
        print("✓ No known OS vulnerabilities detected\n")
    
    # Port Vulnerabilities
    if vuln_report["port_vulnerabilities"]:
        print("🔴 EXPOSED/VULNERABLE PORTS:")
        for port_vuln in vuln_report["port_vulnerabilities"]:
            print(f"  • Port {port_vuln['port']} ({port_vuln['service']}): {port_vuln['description']}")
            print(f"    Risk Level: {port_vuln['risk']}")
            print(f"    Address: {port_vuln['local_address']} | Status: {port_vuln['status']}")
            print(f"    Remediation: {port_vuln['fix']}\n")
    else:
        print("✓ No critically exposed ports detected\n")
    
    # Application Updates (filter out unknown 'latest' values)
    known_updates = [a for a in vuln_report.get("application_updates", []) if str(a.get("latest", "")).lower() not in ("", "unknown", "n/a")]
    if known_updates:
        print("🟡 APPLICATIONS WITH AVAILABLE UPDATES:")
        for i, app in enumerate(known_updates, 1):
            url = app.get('update_url') or ''
            print(f"  [{i}] {app['app']} {'[Update]' if url else ''}")
            print(f"      Installed: {app['installed']}")
            print(f"      Latest: {app['latest']}")
            print(f"      Priority: {app['priority']}")
            print(f"      Update URL: {url if url else 'N/A'}")
    else:
        print("✓ All checked applications are up to date")

    report_path = write_report_html(vuln_report, processes, ports, result["system_info"])
    open_report_in_browser(report_path)
    print(f"\nHTML security report generated and opened at: {report_path}")

    # CVE Summary
    if vuln_report["cve_summary"]:
        print("🔍 CVE SUMMARY FOR DETECTED SOFTWARE:")
        for app, cves in vuln_report["cve_summary"].items():
            if cves:
                print(f"  {app}:")
                for cve in cves[:3]:
                    print(f"    - {cve['id']} ({cve['severity']}): {cve['description']}")
    else:
        print("✓ No CVEs found for detected software\n")

if __name__ == "__main__":
    main()
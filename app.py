from flask import Flask, render_template, request
import requests
from datetime import datetime, timedelta
from functools import lru_cache
import json

app = Flask(__name__)

OSV_API = "https://api.osv.dev/v1/query"
PYPI_API = "https://pypi.org/pypi/{package}/json"

# Popular packages to display on dashboard
POPULAR_PACKAGES = [
    "flask", "django", "requests", "numpy", "pandas", 
    "sqlalchemy", "celery", "pytest", "beautifulsoup4", "pillow"
]

def fetch_osv(package, ecosystem="PyPI", version=None):
    payload = {"package": {"name": package, "ecosystem": ecosystem}}
    if version:
        payload["version"] = version
    r = requests.post(OSV_API, json=payload, timeout=10)
    r.raise_for_status()
    return r.json().get("vulns", [])

def fetch_pypi_meta(package):
    r = requests.get(PYPI_API.format(package=package), timeout=10)
    if r.status_code != 200:
        return None
    data = r.json()
    info = data.get("info", {})
    releases = data.get("releases", {})
    latest_release_date = None
    if releases:
        for ver, files in releases.items():
            for f in files:
                upload_time = f.get("upload_time_iso_8601")
                if upload_time:
                    dt = datetime.fromisoformat(upload_time.replace("Z","+00:00"))
                    if not latest_release_date or dt > latest_release_date:
                        latest_release_date = dt
    return {
        "name": info.get("name"),
        "version": info.get("version"),
        "license": info.get("license") or info.get("classifiers"),
        "summary": info.get("summary"),
        "home_page": info.get("home_page"),
        "project_url": info.get("project_url"),
        "latest_release_date": latest_release_date
    }

def cvss_severity(v):
    sev = "UNKNOWN"
    for s in v.get("severity", []):
        if s.get("type") == "CVSS_V3":
            score = float(s.get("score", 0))
            if score >= 9.0: sev = "CRITICAL"
            elif score >= 7.0: sev = "HIGH"
            elif score >= 4.0: sev = "MEDIUM"
            else: sev = "LOW"
    return sev

def compute_verdict(meta, vulns):
    reasons = []
    verdict = "Safe"

    disallowed = {"GPL", "AGPL", "LGPL"}
    lic_text = str(meta.get("license", "")).upper()
    if any(l in lic_text for l in disallowed):
        verdict = "Unsafe"
        reasons.append("License not permitted by firm policy")

    has_critical = any(cvss_severity(v) == "CRITICAL" for v in vulns)
    has_high = any(cvss_severity(v) == "HIGH" for v in vulns)
    if has_critical:
        verdict = "Unsafe"
        reasons.append("Critical vulnerability present")
    elif has_high and verdict != "Unsafe":
        verdict = "Needs review"
        reasons.append("High-severity vulnerability present")

    last_release = meta.get("latest_release_date")
    if last_release and datetime.utcnow() - last_release > timedelta(days=540):
        if verdict == "Safe":
            verdict = "Needs review"
        reasons.append("Stale maintenance (no recent releases)")

    if not meta.get("name"):
        verdict = "Needs review"
        reasons.append("Package metadata incomplete")

    return verdict, reasons

@lru_cache(maxsize=100)
def get_package_info(package):
    """Fetch package info with caching"""
    try:
        meta = fetch_pypi_meta(package)
        vulns = fetch_osv(package, "PyPI")
        verdict, reasons = compute_verdict(meta or {}, vulns)
        
        vuln_counts = {
            "CRITICAL": sum(1 for v in vulns if cvss_severity(v) == "CRITICAL"),
            "HIGH": sum(1 for v in vulns if cvss_severity(v) == "HIGH"),
            "MEDIUM": sum(1 for v in vulns if cvss_severity(v) == "MEDIUM"),
            "LOW": sum(1 for v in vulns if cvss_severity(v) == "LOW"),
        }
        
        return {
            "name": package,
            "version": meta.get("version") if meta else "N/A",
            "license": meta.get("license") if meta else "Unknown",
            "vulnerabilities": vuln_counts,
            "verdict": verdict,
            "last_updated": str(meta.get("latest_release_date")) if meta and meta.get("latest_release_date") else "Unknown"
        }
    except:
        return {
            "name": package,
            "version": "N/A",
            "license": "Unknown",
            "vulnerabilities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "verdict": "Error",
            "last_updated": "Unknown"
        }

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/search", methods=["POST"])
def search():
    package = request.form.get("package")
    ecosystem = request.form.get("ecosystem") or "PyPI"
    version = request.form.get("version") or None

    meta = fetch_pypi_meta(package) if ecosystem == "PyPI" else {"name": package}
    vulns = fetch_osv(package, ecosystem, version)

    verdict, reasons = compute_verdict(meta or {}, vulns)

    return render_template("results.html",
                           package=package,
                           ecosystem=ecosystem,
                           version=version,
                           meta=meta,
                           vulns=vulns,
                           verdict=verdict,
                           reasons=reasons)

@app.route("/dashboard")
def dashboard():
    packages = [get_package_info(pkg) for pkg in POPULAR_PACKAGES]
    return render_template("dashboard.html", packages=packages)

@app.route("/api/packages")
def api_packages():
    packages = [get_package_info(pkg) for pkg in POPULAR_PACKAGES]
    return json.dumps(packages)

if __name__ == "__main__":
    app.run(debug=True)

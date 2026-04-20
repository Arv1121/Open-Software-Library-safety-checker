from flask import Flask, render_template, request
import requests
from datetime import datetime, timedelta
import json
import logging

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)

OSV_API = "https://api.osv.dev/v1/query"
PYPI_API = "https://pypi.org/pypi/{package}/json"
DEPS_DEV_API = "https://api.deps.dev/v3/systems/pypi/packages/{package}"
GITHUB_API = "https://api.github.com/repos/{owner}/{repo}"
LIBRARIES_IO_API = "https://libraries.io/api/pypi/{package}"

POPULAR_PACKAGES = [
    "flask", "django", "requests", "numpy", "pandas", 
    "sqlalchemy", "celery", "pytest", "beautifulsoup4", "pillow"
]

def fetch_osv(package, ecosystem="PyPI", version=None):
    try:
        payload = {"package": {"name": package, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version
        r = requests.post(OSV_API, json=payload, timeout=10)
        r.raise_for_status()
        return r.json().get("vulns", [])
    except Exception as e:
        logging.error(f"OSV fetch error: {e}")
        return []

def fetch_pypi_meta(package):
    try:
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
            "license": info.get("license") or "Unknown",
            "summary": info.get("summary"),
            "home_page": info.get("home_page"),
            "project_url": info.get("project_url"),
            "latest_release_date": latest_release_date,
            "author": info.get("author"),
            "downloads": data.get("stats", {}).get("last_month", 0) if data.get("stats") else 0
        }
    except Exception as e:
        logging.error(f"PyPI fetch error: {e}")
        return None

def fetch_deps_dev_data(package):
    """Fetch SBOM and dependency info from deps.dev"""
    try:
        r = requests.get(DEPS_DEV_API.format(package=package), timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "dependencies": len(data.get("version", {}).get("dependencies", [])),
                "dependents": data.get("version", {}).get("dependents", 0)
            }
        return {"dependencies": 0, "dependents": 0}
    except Exception as e:
        logging.error(f"Deps.dev fetch error: {e}")
        return {"dependencies": 0, "dependents": 0}

def fetch_github_data(repo_url):
    """Fetch GitHub repo stats"""
    try:
        if not repo_url or "github.com" not in repo_url:
            return None
        
        # Parse owner/repo from URL
        parts = repo_url.rstrip("/").split("/")
        owner, repo = parts[-2], parts[-1].replace(".git", "")
        
        r = requests.get(GITHUB_API.format(owner=owner, repo=repo), timeout=10)
        if r.status_code == 200:
            data = r.json()
            return {
                "stars": data.get("stargazers_count", 0),
                "forks": data.get("forks_count", 0),
                "watchers": data.get("watchers_count", 0),
                "open_issues": data.get("open_issues_count", 0),
                "last_push": data.get("pushed_at"),
                "contributors_url": data.get("contributors_url")
            }
        return None
    except Exception as e:
        logging.error(f"GitHub fetch error: {e}")
        return None

def cvss_severity(v):
    """Extract severity from vulnerability data"""
    sev = "UNKNOWN"
    
    # Check severity array first
    for s in v.get("severity", []):
        if s.get("type") == "CVSS_V3":
            try:
                score = float(s.get("score", 0))
                if score >= 9.0: 
                    sev = "CRITICAL"
                elif score >= 7.0: 
                    sev = "HIGH"
                elif score >= 4.0: 
                    sev = "MEDIUM"
                else: 
                    sev = "LOW"
                break
            except (ValueError, TypeError):
                continue
    
    # Fallback: try to extract from CVSS string in affected field
    if sev == "UNKNOWN":
        affected = v.get("affected", [])
        for item in affected:
            cvss_str = item.get("ecosystem_specific", {}).get("severity")
            if cvss_str and isinstance(cvss_str, str):
                # Parse "CVSS:3.1/AV:N/AC:L/..." format
                try:
                    # Extract numeric score if present
                    if "CVSS:" in cvss_str:
                        parts = cvss_str.split("/")
                        if parts:
                            # Try to find score in first part
                            score_part = parts[0].split(":")[-1]
                            score = float(score_part)
                            if score >= 9.0: sev = "CRITICAL"
                            elif score >= 7.0: sev = "HIGH"
                            elif score >= 4.0: sev = "MEDIUM"
                            else: sev = "LOW"
                            break
                except (ValueError, IndexError, AttributeError):
                    continue
    
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
    if last_release:
        if last_release.tzinfo is None:
            now = datetime.utcnow()
        else:
            now = datetime.now(last_release.tzinfo)
        
        if now - last_release > timedelta(days=540):
            if verdict == "Safe":
                verdict = "Needs review"
            reasons.append("Stale maintenance (no recent releases)")

    if not meta.get("name"):
        verdict = "Needs review"
        reasons.append("Package metadata incomplete")

    return verdict, reasons

def get_package_info(package):
    """Fetch comprehensive package info"""
    try:
        meta = fetch_pypi_meta(package)
        vulns = fetch_osv(package, "PyPI")
        deps_data = fetch_deps_dev_data(package)
        github_data = fetch_github_data(meta.get("home_page") if meta else None)
        
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
            "summary": meta.get("summary") if meta else "N/A",
            "author": meta.get("author") if meta else "Unknown",
            "vulnerabilities": vuln_counts,
            "verdict": verdict,
            "reasons": reasons,
            "last_updated": str(meta.get("latest_release_date")) if meta and meta.get("latest_release_date") else "Unknown",
            "downloads_last_month": meta.get("downloads", 0) if meta else 0,
            "dependencies": deps_data.get("dependencies", 0),
            "dependents": deps_data.get("dependents", 0),
            "github": github_data or {}
        }
    except Exception as e:
        logging.error(f"Package info error: {e}")
        return {
            "name": package,
            "version": "N/A",
            "license": "Unknown",
            "summary": "Error fetching data",
            "author": "Unknown",
            "vulnerabilities": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "verdict": "Error",
            "reasons": [str(e)],
            "last_updated": "Unknown",
            "downloads_last_month": 0,
            "dependencies": 0,
            "dependents": 0,
            "github": {}
        }

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/search", methods=["POST"])
def search():
    package = request.form.get("package")
    ecosystem = request.form.get("ecosystem") or "PyPI"
    version = request.form.get("version") or None

    try:
        meta = fetch_pypi_meta(package) if ecosystem == "PyPI" else {"name": package}
        vulns = fetch_osv(package, ecosystem, version)
        deps_data = fetch_deps_dev_data(package)
        github_data = fetch_github_data(meta.get("home_page") if meta else None)

        verdict, reasons = compute_verdict(meta or {}, vulns)

        return render_template("results.html",
                               package=package,
                               ecosystem=ecosystem,
                               version=version,
                               meta=meta,
                               vulns=vulns,
                               verdict=verdict,
                               reasons=reasons,
                               deps_data=deps_data,
                               github_data=github_data)
    except Exception as e:
        logging.error(f"Search error: {e}")
        return render_template("results.html",
                               package=package,
                               ecosystem=ecosystem,
                               version=version,
                               meta=None,
                               vulns=[],
                               verdict="Error",
                               reasons=[str(e)],
                               deps_data={},
                               github_data=None)

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

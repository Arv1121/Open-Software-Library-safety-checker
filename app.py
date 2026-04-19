from functools import lru_cache
import json

# Popular packages to display on dashboard
POPULAR_PACKAGES = [
    "flask", "django", "requests", "numpy", "pandas", 
    "sqlalchemy", "celery", "pytest", "beautifulsoup4", "pillow"
]

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

@app.route("/dashboard")
def dashboard():
    packages = [get_package_info(pkg) for pkg in POPULAR_PACKAGES]
    return render_template("dashboard.html", packages=packages)

@app.route("/api/packages")
def api_packages():
    packages = [get_package_info(pkg) for pkg in POPULAR_PACKAGES]
    return json.dumps(packages)

from flask import Flask, render_template, request, jsonify, Response, make_response
from flask_cors import CORS
import requests
from datetime import datetime, timedelta
import json
import logging
from functools import wraps
import hashlib
from collections import defaultdict
import time

app = Flask(__name__, static_folder='static', static_url_path='/static')
app.secret_key = 'your-secret-key-change-this'
CORS(app)
logging.basicConfig(level=logging.INFO)

# Enhanced stats with timestamps
STATS = {
    "unique_visitors": set(),
    "total_searches": 0,
    "searches_by_package": {},
    "visitor_ips": [],
    "search_history": [],          # [{package, ecosystem, timestamp}]
    "trending_window": [],         # recent searches for trending calc
}

OSV_API = "https://api.osv.dev/v1/query"
PYPI_API = "https://pypi.org/pypi/{package}/json"
DEPS_DEV_API = "https://api.deps.dev/v3/systems/pypi/packages/{package}"
GITHUB_API = "https://api.github.com/repos/{owner}/{repo}"

POPULAR_PACKAGES = [
    "flask", "django", "requests", "numpy", "pandas",
    "sqlalchemy", "celery", "pytest", "beautifulsoup4", "pillow"
]

# Extended list for autocomplete suggestions
KNOWN_PACKAGES = [
    "flask", "django", "requests", "numpy", "pandas", "sqlalchemy", "celery",
    "pytest", "beautifulsoup4", "pillow", "fastapi", "uvicorn", "pydantic",
    "aiohttp", "httpx", "boto3", "botocore", "cryptography", "paramiko",
    "pyopenssl", "twisted", "tornado", "gunicorn", "werkzeug", "jinja2",
    "click", "rich", "typer", "loguru", "structlog", "sentry-sdk",
    "redis", "pymongo", "psycopg2", "pymysql", "alembic", "peewee",
    "marshmallow", "cerberus", "voluptuous", "attrs", "dataclasses-json",
    "arrow", "pendulum", "python-dateutil", "pytz", "babel",
    "scipy", "matplotlib", "seaborn", "plotly", "bokeh", "altair",
    "scikit-learn", "tensorflow", "torch", "keras", "xgboost", "lightgbm",
    "opencv-python", "imageio", "wand", "cairosvg",
    "lxml", "html5lib", "cssselect", "pyquery", "mechanize",
    "parameterized", "hypothesis", "faker", "factory-boy", "responses",
    "black", "flake8", "mypy", "pylint", "bandit", "safety",
    "setuptools", "wheel", "pip", "virtualenv", "pipenv", "poetry",
    "tqdm", "colorama", "tabulate", "prettytable", "termcolor",
    "pyyaml", "toml", "python-dotenv", "configparser", "dynaconf",
    "stripe", "twilio", "sendgrid", "mailchimp3", "slack-sdk",
    "google-cloud-storage", "google-auth", "azure-storage-blob",
    "ansible", "fabric", "invoke", "doit", "prefect", "airflow",
    "scrapy", "selenium", "playwright", "pyppeteer",
    "jwt", "passlib", "bcrypt", "itsdangerous", "authlib",
]

def track_visitor(f):
    """Decorator to track unique visitors"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        visitor_id = hashlib.md5(f"{ip}{user_agent}".encode()).hexdigest()

        STATS["unique_visitors"].add(visitor_id)
        STATS["visitor_ips"].append({
            "ip": ip,
            "timestamp": datetime.utcnow().isoformat(),
            "path": request.path
        })

        return f(*args, **kwargs)
    return decorated_function


def record_search(package, ecosystem):
    """Record a search for history and trending."""
    now = datetime.utcnow()
    entry = {"package": package, "ecosystem": ecosystem, "timestamp": now.isoformat()}
    STATS["search_history"].append(entry)
    STATS["trending_window"].append(entry)
    # Keep only last 500 entries in each list
    STATS["search_history"] = STATS["search_history"][-500:]
    STATS["trending_window"] = STATS["trending_window"][-200:]


def get_trending_packages(limit=5):
    """Return top packages searched in the last 24 hours."""
    cutoff = datetime.utcnow() - timedelta(hours=24)
    counts = {}
    for entry in STATS["trending_window"]:
        try:
            ts = datetime.fromisoformat(entry["timestamp"])
        except (ValueError, KeyError):
            continue
        if ts >= cutoff:
            pkg = entry["package"]
            counts[pkg] = counts.get(pkg, 0) + 1
    sorted_pkgs = sorted(counts.items(), key=lambda x: x[1], reverse=True)
    return [{"package": p, "count": c} for p, c in sorted_pkgs[:limit]]

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
    try:
        if not repo_url or "github.com" not in repo_url:
            return None
        
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
    
    if sev == "UNKNOWN":
        affected = v.get("affected", [])
        for item in affected:
            cvss_str = item.get("ecosystem_specific", {}).get("severity")
            if cvss_str and isinstance(cvss_str, str):
                try:
                    if "CVSS:" in cvss_str:
                        parts = cvss_str.split("/")
                        if parts:
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

# Register cvss_severity as a Jinja2 template filter so templates can use
# {{ vuln | cvss_severity }} in addition to calling it as a function.
app.jinja_env.filters['cvss_severity'] = cvss_severity

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
@track_visitor
def index():
    stats = {
        "unique_visitors": len(STATS["unique_visitors"]),
        "total_searches": STATS["total_searches"]
    }
    trending = get_trending_packages(5)
    return render_template("index.html", stats=stats, trending=trending,
                           popular_packages=POPULAR_PACKAGES)


@app.route("/search", methods=["POST"])
@track_visitor
def search():
    package = request.form.get("package", "").strip()
    ecosystem = request.form.get("ecosystem") or "PyPI"
    version = request.form.get("version") or None

    # Track search with timestamp
    STATS["total_searches"] += 1
    STATS["searches_by_package"][package] = STATS["searches_by_package"].get(package, 0) + 1
    record_search(package, ecosystem)

    try:
        meta = fetch_pypi_meta(package) if ecosystem == "PyPI" else {"name": package}
        vulns = fetch_osv(package, ecosystem, version)
        deps_data = fetch_deps_dev_data(package)
        github_data = fetch_github_data(meta.get("home_page") if meta else None)

        verdict, reasons = compute_verdict(meta or {}, vulns)

        stats = {
            "unique_visitors": len(STATS["unique_visitors"]),
            "total_searches": STATS["total_searches"],
            "package_searches": STATS["searches_by_package"].get(package, 0)
        }

        return render_template("results.html",
                               package=package,
                               ecosystem=ecosystem,
                               version=version,
                               meta=meta,
                               vulns=vulns,
                               verdict=verdict,
                               reasons=reasons,
                               deps_data=deps_data,
                               github_data=github_data,
                               stats=stats,
                               cvss_severity=cvss_severity)
    except Exception as e:
        logging.error(f"Search error: {e}")
        stats = {
            "unique_visitors": len(STATS["unique_visitors"]),
            "total_searches": STATS["total_searches"],
            "package_searches": STATS["searches_by_package"].get(package, 0)
        }
        return render_template("results.html",
                               package=package,
                               ecosystem=ecosystem,
                               version=version,
                               meta=None,
                               vulns=[],
                               verdict="Error",
                               reasons=[str(e)],
                               deps_data={},
                               github_data=None,
                               stats=stats,
                               cvss_severity=cvss_severity)


@app.route("/dashboard")
@track_visitor
def dashboard():
    packages = [get_package_info(pkg) for pkg in POPULAR_PACKAGES]
    stats = {
        "unique_visitors": len(STATS["unique_visitors"]),
        "total_searches": STATS["total_searches"]
    }
    trending = get_trending_packages(5)
    return render_template("dashboard.html", packages=packages, stats=stats, trending=trending)


@app.route("/compare")
@track_visitor
def compare():
    pkgs = request.args.getlist("pkg")
    pkgs = [p.strip() for p in pkgs if p.strip()][:3]
    results = [get_package_info(p) for p in pkgs] if pkgs else []
    stats = {
        "unique_visitors": len(STATS["unique_visitors"]),
        "total_searches": STATS["total_searches"]
    }
    return render_template("comparison.html", results=results, pkgs=pkgs, stats=stats)


# ── API endpoints ──────────────────────────────────────────────────────────────

@app.route("/api/packages")
def api_packages():
    packages = [get_package_info(pkg) for pkg in POPULAR_PACKAGES]
    return jsonify(packages)


@app.route("/api/stats")
def api_stats():
    return jsonify({
        "unique_visitors": len(STATS["unique_visitors"]),
        "total_searches": STATS["total_searches"],
        "top_packages": sorted(STATS["searches_by_package"].items(), key=lambda x: x[1], reverse=True)[:10]
    })


@app.route("/api/autocomplete")
def api_autocomplete():
    """Return package name suggestions matching the query prefix."""
    q = request.args.get("q", "").strip().lower()
    if len(q) < 1:
        return jsonify([])
    # Combine known list with previously searched packages
    candidates = set(KNOWN_PACKAGES) | set(STATS["searches_by_package"].keys())
    matches = sorted(
        [p for p in candidates if q in p.lower()],
        key=lambda p: (not p.lower().startswith(q), p)
    )[:10]
    return jsonify(matches)


@app.route("/api/trending")
def api_trending():
    """Return trending packages (most searched in last 24 h)."""
    return jsonify(get_trending_packages(10))


@app.route("/api/history")
def api_history():
    """Return the last 20 search history entries."""
    return jsonify(list(reversed(STATS["search_history"][-20:])))


@app.route("/api/compare")
def api_compare():
    """Return JSON comparison data for up to 3 packages."""
    pkgs = request.args.getlist("pkg")
    pkgs = [p.strip() for p in pkgs if p.strip()][:3]
    results = [get_package_info(p) for p in pkgs]
    return jsonify(results)


@app.route("/api/export/json/<package>")
def api_export_json(package):
    """Export package report as JSON download."""
    data = get_package_info(package)
    data["exported_at"] = datetime.utcnow().isoformat()
    payload = json.dumps(data, indent=2, default=str)
    return Response(
        payload,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment; filename={package}-report.json"}
    )


@app.route("/terms")
@track_visitor
def terms():
    return render_template("terms.html", now=datetime.utcnow())


# ── SEO routes ─────────────────────────────────────────────────────────────────

BASE_URL = "https://ibrary-safety-checker-production-1526.up.railway.app"

@app.route("/googleef147e2249f09263.html")
def google_verification():
    """Serve Google Search Console HTML verification file."""
    content = "google-site-verification: googleef147e2249f09263.html"
    response = make_response(content)
    response.headers["Content-Type"] = "text/html; charset=utf-8"
    return response


@app.route("/robots.txt")
def robots_txt():
    content = f"""User-agent: *
Allow: /
Disallow: /api/
Crawl-delay: 2

Sitemap: {BASE_URL}/sitemap.xml
Sitemap: {BASE_URL}/sitemap-packages.xml
"""
    response = make_response(content)
    response.headers["Content-Type"] = "text/plain; charset=utf-8"
    response.headers["Cache-Control"] = "public, max-age=86400"
    return response


@app.route("/sitemap.xml")
def sitemap_xml():
    now = datetime.utcnow().strftime("%Y-%m-%d")
    pages = [
        {"loc": f"{BASE_URL}/",          "priority": "1.0", "changefreq": "daily",   "lastmod": now},
        {"loc": f"{BASE_URL}/dashboard", "priority": "0.9", "changefreq": "hourly",  "lastmod": now},
        {"loc": f"{BASE_URL}/compare",   "priority": "0.7", "changefreq": "weekly",  "lastmod": now},
        {"loc": f"{BASE_URL}/terms",     "priority": "0.3", "changefreq": "monthly", "lastmod": now},
    ]
    xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    for page in pages:
        xml_parts.append(
            f"  <url>\n"
            f"    <loc>{page['loc']}</loc>\n"
            f"    <lastmod>{page['lastmod']}</lastmod>\n"
            f"    <changefreq>{page['changefreq']}</changefreq>\n"
            f"    <priority>{page['priority']}</priority>\n"
            f"  </url>"
        )
    xml_parts.append("</urlset>")
    response = make_response("\n".join(xml_parts))
    response.headers["Content-Type"] = "application/xml; charset=utf-8"
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


@app.route("/sitemap-packages.xml")
def sitemap_packages_xml():
    now = datetime.utcnow().strftime("%Y-%m-%d")
    xml_parts = ['<?xml version="1.0" encoding="UTF-8"?>',
                 '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">']
    # Static search result pages for all known popular packages
    for pkg in POPULAR_PACKAGES:
        xml_parts.append(
            f"  <url>\n"
            f"    <loc>{BASE_URL}/search?package={pkg}&amp;ecosystem=PyPI</loc>\n"
            f"    <lastmod>{now}</lastmod>\n"
            f"    <changefreq>weekly</changefreq>\n"
            f"    <priority>0.6</priority>\n"
            f"  </url>"
        )
    xml_parts.append("</urlset>")
    response = make_response("\n".join(xml_parts))
    response.headers["Content-Type"] = "application/xml; charset=utf-8"
    response.headers["Cache-Control"] = "public, max-age=3600"
    return response


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)

@app.after_request
def add_security_headers(response):
    # Prevent Clickjacking
    response.headers["X-Frame-Options"] = "DENY"

    # Prevent MIME type sniffing
    response.headers["X-Content-Type-Options"] = "nosniff"

    # Enforce HTTPS (HSTS) - only if Railway serves HTTPS
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    # Content Security Policy – includes all CDNs used by templates
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://code.jquery.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://raw.githubusercontent.com https://img.shields.io; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'"
    )
    return response

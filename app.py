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
NPM_API = "https://registry.npmjs.org/{package}"
CARGO_API = "https://crates.io/api/v1/crates/{package}"
NUGET_API = "https://api.nuget.org/v3/registration5/{package}/index.json"
MAVEN_SEARCH_API = "https://search.maven.org/solrsearch/select"
DEPS_DEV_API = "https://api.deps.dev/v3/systems/pypi/packages/{package}"
GITHUB_API = "https://api.github.com/repos/{owner}/{repo}"

# ── Ecosystem definitions ──────────────────────────────────────────────────────

SUPPORTED_ECOSYSTEMS = [
    {"id": "PyPI",     "label": "PyPI (Python)",       "icon": "🐍"},
    {"id": "npm",      "label": "npm (JavaScript)",     "icon": "📦"},
    {"id": "Maven",    "label": "Maven (Java)",         "icon": "☕"},
    {"id": "Go",       "label": "Go",                   "icon": "🐹"},
    {"id": "crates.io","label": "Cargo (Rust)",         "icon": "🦀"},
    {"id": "NuGet",    "label": "NuGet (.NET/C#)",      "icon": "🔷"},
    {"id": "RubyGems", "label": "RubyGems (Ruby)",      "icon": "💎"},
    {"id": "Packagist","label": "Composer (PHP)",       "icon": "🐘"},
]

# ── AI/ML packages ─────────────────────────────────────────────────────────────

AI_ML_PACKAGES = [
    # Deep Learning frameworks
    "tensorflow", "torch", "jax", "keras", "mxnet", "paddle", "mindspore",
    "flax", "haiku", "trax", "fastai", "lightning", "pytorch-lightning",
    # ML libraries
    "scikit-learn", "xgboost", "lightgbm", "catboost", "optuna", "hyperopt",
    "shap", "lime", "eli5", "mlflow", "wandb", "neptune-client",
    # NLP
    "transformers", "spacy", "nltk", "gensim", "sentence-transformers",
    "tokenizers", "datasets", "evaluate", "accelerate", "peft", "trl",
    "langchain", "openai", "anthropic", "cohere", "tiktoken",
    # Computer Vision
    "opencv-python", "pillow", "imageio", "albumentations", "torchvision",
    "timm", "detectron2", "ultralytics", "supervision", "kornia",
    # Data Processing
    "pandas", "numpy", "polars", "dask", "vaex", "modin", "cudf",
    "pyarrow", "h5py", "zarr", "xarray",
    # Visualization
    "matplotlib", "seaborn", "plotly", "bokeh", "altair", "holoviews",
    "panel", "streamlit", "gradio", "dash",
    # AutoML
    "autogluon", "tpot", "h2o", "auto-sklearn", "flaml", "pycaret",
    # Reinforcement Learning
    "gym", "gymnasium", "stable-baselines3", "ray", "rllib",
    "tianshou", "d3rlpy",
    # Graph Neural Networks
    "torch-geometric", "dgl", "spektral", "stellargraph",
    # Time Series
    "prophet", "statsmodels", "pmdarima", "sktime", "darts", "neuralprophet",
    # Experiment tracking / MLOps
    "mlflow", "dvc", "bentoml", "seldon", "feast", "great-expectations",
    # Scientific computing
    "scipy", "sympy", "numba", "cupy", "jaxlib",
]

# ── Ecosystem-grouped packages ─────────────────────────────────────────────────

ECOSYSTEM_PACKAGES = {
    "PyPI": [
        # Web frameworks
        "flask", "django", "fastapi", "tornado", "aiohttp", "starlette",
        "bottle", "falcon", "sanic", "quart", "litestar",
        # HTTP clients
        "requests", "httpx", "urllib3", "aiohttp", "httpcore",
        # Databases
        "sqlalchemy", "alembic", "pymongo", "redis", "psycopg2", "pymysql",
        "motor", "tortoise-orm", "databases", "peewee", "piccolo",
        # Auth / Security
        "cryptography", "paramiko", "pyopenssl", "bcrypt", "passlib",
        "itsdangerous", "authlib", "pyjwt", "python-jose",
        # Task queues
        "celery", "rq", "dramatiq", "huey", "apscheduler",
        # Testing
        "pytest", "hypothesis", "faker", "factory-boy", "responses",
        "coverage", "tox", "nox", "ward",
        # Serialization
        "pydantic", "marshmallow", "attrs", "cattrs", "msgpack",
        "orjson", "ujson", "simplejson",
        # CLI
        "click", "typer", "rich", "textual", "prompt-toolkit",
        "colorama", "tabulate", "tqdm",
        # Config / Env
        "pyyaml", "toml", "python-dotenv", "dynaconf", "hydra-core",
        # Cloud / DevOps
        "boto3", "google-cloud-storage", "azure-storage-blob",
        "ansible", "fabric", "invoke", "prefect", "airflow",
        # Scraping
        "beautifulsoup4", "scrapy", "selenium", "playwright", "lxml",
        # Utilities
        "arrow", "pendulum", "python-dateutil", "pytz", "babel",
        "pillow", "imageio", "wand", "cairosvg",
        "loguru", "structlog", "sentry-sdk",
        "setuptools", "wheel", "pip", "virtualenv", "poetry",
        "black", "flake8", "mypy", "pylint", "bandit",
        "stripe", "twilio", "sendgrid", "slack-sdk",
    ] + AI_ML_PACKAGES,

    "npm": [
        # Frontend frameworks
        "react", "vue", "angular", "svelte", "solid-js", "preact",
        "next", "nuxt", "gatsby", "remix", "astro",
        # State management
        "redux", "mobx", "zustand", "jotai", "recoil", "pinia",
        # UI component libraries
        "antd", "@mui/material", "chakra-ui", "mantine", "shadcn-ui",
        "tailwindcss", "bootstrap", "bulma",
        # Build tools
        "webpack", "vite", "rollup", "esbuild", "parcel", "turbopack",
        "babel", "swc", "typescript",
        # Testing
        "jest", "vitest", "mocha", "chai", "cypress", "playwright",
        "testing-library", "@testing-library/react",
        # HTTP / API
        "axios", "node-fetch", "got", "superagent", "ky",
        "express", "fastify", "koa", "hapi", "nestjs",
        # Database / ORM
        "mongoose", "sequelize", "prisma", "typeorm", "drizzle-orm",
        "pg", "mysql2", "sqlite3", "redis", "ioredis",
        # Auth
        "passport", "jsonwebtoken", "bcrypt", "argon2", "next-auth",
        # Utilities
        "lodash", "ramda", "date-fns", "dayjs", "moment",
        "uuid", "nanoid", "dotenv", "zod", "yup", "joi",
        "chalk", "ora", "inquirer", "commander", "yargs",
        # Bundler plugins / tooling
        "eslint", "prettier", "husky", "lint-staged", "commitlint",
        # Node.js
        "express", "socket.io", "ws", "bull", "agenda", "node-cron",
        "multer", "sharp", "jimp", "pdf-lib",
        # AI/ML (JS)
        "@tensorflow/tfjs", "onnxruntime-node", "brain.js",
        "natural", "compromise", "ml5",
    ],

    "Maven": [
        # Spring ecosystem
        "org.springframework.boot:spring-boot-starter-web",
        "org.springframework.boot:spring-boot-starter-data-jpa",
        "org.springframework.boot:spring-boot-starter-security",
        "org.springframework.boot:spring-boot-starter-test",
        "org.springframework.cloud:spring-cloud-starter-netflix-eureka-client",
        "org.springframework.kafka:spring-kafka",
        # Persistence
        "org.hibernate:hibernate-core",
        "com.baeldung:persistence-modules",
        "org.mybatis:mybatis",
        "com.zaxxer:HikariCP",
        # Logging
        "org.slf4j:slf4j-api",
        "ch.qos.logback:logback-classic",
        "org.apache.logging.log4j:log4j-core",
        # Testing
        "junit:junit",
        "org.junit.jupiter:junit-jupiter",
        "org.mockito:mockito-core",
        "org.assertj:assertj-core",
        "io.rest-assured:rest-assured",
        # HTTP clients
        "org.apache.httpcomponents:httpclient",
        "com.squareup.okhttp3:okhttp",
        # JSON
        "com.fasterxml.jackson.core:jackson-databind",
        "com.google.code.gson:gson",
        # Build / utilities
        "org.projectlombok:lombok",
        "org.mapstruct:mapstruct",
        "com.google.guava:guava",
        "org.apache.commons:commons-lang3",
        "commons-io:commons-io",
        # Messaging
        "org.apache.kafka:kafka-clients",
        "com.rabbitmq:amqp-client",
        # Cloud
        "com.amazonaws:aws-java-sdk-s3",
        "com.google.cloud:google-cloud-storage",
    ],

    "Go": [
        # Web frameworks
        "github.com/gin-gonic/gin",
        "github.com/gofiber/fiber",
        "github.com/labstack/echo",
        "github.com/gorilla/mux",
        "github.com/go-chi/chi",
        "github.com/beego/beego",
        # Database
        "gorm.io/gorm",
        "github.com/jmoiron/sqlx",
        "go.mongodb.org/mongo-driver",
        "github.com/go-redis/redis",
        "github.com/lib/pq",
        # Auth / Security
        "github.com/golang-jwt/jwt",
        "golang.org/x/crypto",
        # HTTP clients
        "github.com/go-resty/resty",
        "github.com/hashicorp/go-retryablehttp",
        # Testing
        "github.com/stretchr/testify",
        "github.com/onsi/ginkgo",
        "github.com/onsi/gomega",
        # CLI
        "github.com/spf13/cobra",
        "github.com/spf13/viper",
        "github.com/urfave/cli",
        # Logging
        "go.uber.org/zap",
        "github.com/sirupsen/logrus",
        "github.com/rs/zerolog",
        # Utilities
        "github.com/google/uuid",
        "github.com/pkg/errors",
        "github.com/mitchellh/mapstructure",
        # gRPC / Protobuf
        "google.golang.org/grpc",
        "google.golang.org/protobuf",
        # Cloud
        "cloud.google.com/go/storage",
        "github.com/aws/aws-sdk-go-v2",
    ],

    "crates.io": [
        # Web frameworks
        "actix-web", "axum", "warp", "rocket", "tide", "poem",
        # Async runtime
        "tokio", "async-std", "smol",
        # HTTP clients
        "reqwest", "hyper", "ureq",
        # Serialization
        "serde", "serde_json", "serde_yaml", "bincode", "toml",
        # Database
        "sqlx", "diesel", "sea-orm", "rusqlite", "mongodb",
        "redis", "deadpool-postgres",
        # CLI
        "clap", "structopt", "argh", "indicatif", "console",
        # Error handling
        "anyhow", "thiserror", "color-eyre",
        # Logging / tracing
        "tracing", "log", "env_logger", "tracing-subscriber",
        # Crypto
        "ring", "rustls", "openssl", "sha2", "aes",
        # Utilities
        "uuid", "chrono", "rand", "regex", "lazy_static",
        "once_cell", "rayon", "crossbeam", "parking_lot",
        # Testing
        "mockall", "proptest", "criterion",
        # WebAssembly
        "wasm-bindgen", "js-sys", "web-sys",
        # ML (Rust)
        "candle-core", "burn", "linfa", "smartcore",
    ],

    "NuGet": [
        # ASP.NET Core
        "Microsoft.AspNetCore.App",
        "Microsoft.AspNetCore.Authentication.JwtBearer",
        "Microsoft.AspNetCore.Identity.EntityFrameworkCore",
        # Entity Framework
        "Microsoft.EntityFrameworkCore",
        "Microsoft.EntityFrameworkCore.SqlServer",
        "Microsoft.EntityFrameworkCore.Sqlite",
        "Npgsql.EntityFrameworkCore.PostgreSQL",
        # Testing
        "xunit", "NUnit", "MSTest.TestFramework",
        "Moq", "NSubstitute", "FluentAssertions",
        # Logging
        "Serilog", "Serilog.AspNetCore", "NLog",
        "Microsoft.Extensions.Logging",
        # HTTP
        "RestSharp", "Flurl.Http", "Refit",
        # Serialization
        "Newtonsoft.Json", "System.Text.Json",
        "MessagePack", "protobuf-net",
        # Utilities
        "AutoMapper", "MediatR", "FluentValidation",
        "Polly", "Hangfire", "Quartz.NET",
        # Cloud
        "AWSSDK.S3", "Azure.Storage.Blobs",
        "Google.Cloud.Storage.V1",
        # ML.NET
        "Microsoft.ML", "Microsoft.ML.FastTree",
        "Microsoft.ML.ImageAnalytics",
    ],

    "RubyGems": [
        # Web frameworks
        "rails", "sinatra", "hanami", "grape", "roda",
        # Database
        "activerecord", "sequel", "mongoid", "redis",
        "pg", "mysql2", "sqlite3",
        # Auth
        "devise", "doorkeeper", "jwt", "bcrypt",
        # Testing
        "rspec", "minitest", "capybara", "factory_bot",
        "faker", "vcr", "webmock",
        # HTTP clients
        "faraday", "httparty", "rest-client", "typhoeus",
        # Background jobs
        "sidekiq", "resque", "delayed_job", "good_job",
        # Utilities
        "nokogiri", "oj", "dry-rb", "zeitwerk",
        "pundit", "cancancan", "kaminari", "pagy",
        # Asset pipeline
        "sprockets", "webpacker", "propshaft",
        # Deployment
        "capistrano", "mina", "puma", "unicorn",
    ],

    "Packagist": [
        # Frameworks
        "laravel/framework", "symfony/symfony",
        "slim/slim", "cakephp/cakephp", "codeigniter4/framework",
        # ORM / Database
        "doctrine/orm", "doctrine/dbal",
        "illuminate/database", "cycle/orm",
        # Auth
        "firebase/php-jwt", "lcobucci/jwt",
        "league/oauth2-server", "spatie/laravel-permission",
        # HTTP
        "guzzlehttp/guzzle", "symfony/http-client",
        "nyholm/psr7", "laminas/laminas-diactoros",
        # Testing
        "phpunit/phpunit", "mockery/mockery",
        "fakerphp/faker", "pestphp/pest",
        # Utilities
        "nesbot/carbon", "ramsey/uuid",
        "league/flysystem", "league/csv",
        "monolog/monolog", "vlucas/phpdotenv",
        # Template engines
        "twig/twig", "smarty/smarty", "blade/blade",
        # Composer tools
        "composer/composer", "phpstan/phpstan",
        "squizlabs/php_codesniffer", "friendsofphp/php-cs-fixer",
    ],
}

# Flat popular packages list (used for dashboard and sitemap)
POPULAR_PACKAGES = [
    # Python
    "flask", "django", "requests", "numpy", "pandas",
    "sqlalchemy", "celery", "pytest", "beautifulsoup4", "pillow",
    # AI/ML
    "tensorflow", "torch", "scikit-learn", "transformers", "langchain",
    # npm
    "react", "express", "lodash", "axios", "next",
    # Java
    "org.springframework.boot:spring-boot-starter-web",
    # Rust
    "actix-web", "tokio", "serde",
    # Go
    "github.com/gin-gonic/gin",
]

# Extended list for autocomplete suggestions (2000+ packages)
KNOWN_PACKAGES = sorted(set(
    # PyPI
    ECOSYSTEM_PACKAGES["PyPI"] +
    # npm (plain names)
    ECOSYSTEM_PACKAGES["npm"] +
    # Rust
    ECOSYSTEM_PACKAGES["crates.io"] +
    # Ruby
    ECOSYSTEM_PACKAGES["RubyGems"] +
    # PHP
    ECOSYSTEM_PACKAGES["Packagist"] +
    # NuGet
    ECOSYSTEM_PACKAGES["NuGet"] +
    # Go (short names)
    [p.split("/")[-1] for p in ECOSYSTEM_PACKAGES["Go"]] +
    # Maven (artifact IDs)
    [p.split(":")[-1] for p in ECOSYSTEM_PACKAGES["Maven"]] +
    # AI/ML explicit
    AI_ML_PACKAGES
))

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

def fetch_npm_meta(package):
    """Fetch package metadata from the npm registry."""
    try:
        r = requests.get(NPM_API.format(package=package), timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        latest_ver = data.get("dist-tags", {}).get("latest", "")
        ver_data = data.get("versions", {}).get(latest_ver, {})
        time_data = data.get("time", {})
        latest_time = time_data.get(latest_ver)
        latest_release_date = None
        if latest_time:
            try:
                latest_release_date = datetime.fromisoformat(latest_time.replace("Z", "+00:00"))
            except ValueError:
                pass
        return {
            "name": data.get("name"),
            "version": latest_ver,
            "license": ver_data.get("license") or data.get("license") or "Unknown",
            "summary": data.get("description") or ver_data.get("description"),
            "home_page": data.get("homepage") or (ver_data.get("repository", {}) or {}).get("url"),
            "project_url": f"https://www.npmjs.com/package/{package}",
            "latest_release_date": latest_release_date,
            "author": (ver_data.get("author") or {}).get("name") if isinstance(ver_data.get("author"), dict) else ver_data.get("author"),
            "downloads": 0,
        }
    except Exception as e:
        logging.error(f"npm fetch error: {e}")
        return None


def fetch_cargo_meta(package):
    """Fetch package metadata from crates.io."""
    try:
        r = requests.get(CARGO_API.format(package=package), timeout=10,
                         headers={"User-Agent": "library-safety-checker/1.0"})
        if r.status_code != 200:
            return None
        data = r.json()
        crate = data.get("crate", {})
        newest_ver = crate.get("newest_version", "")
        updated_at = crate.get("updated_at")
        latest_release_date = None
        if updated_at:
            try:
                latest_release_date = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
            except ValueError:
                pass
        return {
            "name": crate.get("name"),
            "version": newest_ver,
            "license": (data.get("versions") or [{}])[0].get("license") or "Unknown",
            "summary": crate.get("description"),
            "home_page": crate.get("homepage") or crate.get("repository"),
            "project_url": f"https://crates.io/crates/{package}",
            "latest_release_date": latest_release_date,
            "author": None,
            "downloads": crate.get("downloads", 0),
        }
    except Exception as e:
        logging.error(f"Cargo fetch error: {e}")
        return None


def fetch_nuget_meta(package):
    """Fetch package metadata from NuGet."""
    try:
        r = requests.get(NUGET_API.format(package=package.lower()), timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        items = data.get("items", [])
        if not items:
            return None
        # Last page has the latest versions
        last_page = items[-1]
        page_items = last_page.get("items", [])
        if not page_items:
            return None
        latest = page_items[-1].get("catalogEntry", {})
        published = latest.get("published")
        latest_release_date = None
        if published:
            try:
                latest_release_date = datetime.fromisoformat(published.replace("Z", "+00:00"))
            except ValueError:
                pass
        return {
            "name": latest.get("id"),
            "version": latest.get("version"),
            "license": latest.get("licenseExpression") or "Unknown",
            "summary": latest.get("description"),
            "home_page": latest.get("projectUrl"),
            "project_url": f"https://www.nuget.org/packages/{package}",
            "latest_release_date": latest_release_date,
            "author": latest.get("authors"),
            "downloads": 0,
        }
    except Exception as e:
        logging.error(f"NuGet fetch error: {e}")
        return None


def fetch_maven_meta(package):
    """Fetch package metadata from Maven Central (groupId:artifactId format)."""
    try:
        if ":" in package:
            group_id, artifact_id = package.split(":", 1)
        else:
            group_id, artifact_id = "", package
        params = {
            "q": f"g:{group_id} AND a:{artifact_id}" if group_id else f"a:{artifact_id}",
            "rows": 1,
            "wt": "json",
        }
        r = requests.get(MAVEN_SEARCH_API, params=params, timeout=10)
        if r.status_code != 200:
            return None
        docs = r.json().get("response", {}).get("docs", [])
        if not docs:
            return None
        doc = docs[0]
        ts = doc.get("timestamp")
        latest_release_date = None
        if ts:
            try:
                latest_release_date = datetime.utcfromtimestamp(ts / 1000)
            except (ValueError, OSError):
                pass
        return {
            "name": f"{doc.get('g')}:{doc.get('a')}",
            "version": doc.get("latestVersion") or doc.get("v"),
            "license": "See POM",
            "summary": f"Maven artifact {doc.get('g')}:{doc.get('a')}",
            "home_page": f"https://mvnrepository.com/artifact/{doc.get('g')}/{doc.get('a')}",
            "project_url": f"https://search.maven.org/artifact/{doc.get('g')}/{doc.get('a')}",
            "latest_release_date": latest_release_date,
            "author": doc.get("g"),
            "downloads": 0,
        }
    except Exception as e:
        logging.error(f"Maven fetch error: {e}")
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

def _fetch_meta_for_ecosystem(package, ecosystem):
    """Dispatch metadata fetch to the correct registry based on ecosystem."""
    if ecosystem == "PyPI":
        return fetch_pypi_meta(package)
    elif ecosystem == "npm":
        return fetch_npm_meta(package)
    elif ecosystem == "crates.io":
        return fetch_cargo_meta(package)
    elif ecosystem == "NuGet":
        return fetch_nuget_meta(package)
    elif ecosystem == "Maven":
        return fetch_maven_meta(package)
    else:
        # Go, RubyGems, Packagist – return minimal stub; OSV still works
        return {"name": package, "version": "N/A", "license": "Unknown",
                "summary": None, "home_page": None, "latest_release_date": None,
                "author": None, "downloads": 0}


def get_package_info(package, ecosystem="PyPI"):
    """Fetch comprehensive package info for any supported ecosystem."""
    try:
        meta = _fetch_meta_for_ecosystem(package, ecosystem)
        vulns = fetch_osv(package, ecosystem)
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
            "ecosystem": ecosystem,
            "version": meta.get("version") if meta else "N/A",
            "license": meta.get("license") if meta else "Unknown",
            "summary": meta.get("summary") if meta else "N/A",
            "author": meta.get("author") if meta else "Unknown",
            "home_page": meta.get("home_page") if meta else None,
            "project_url": meta.get("project_url") if meta else None,
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
            "ecosystem": ecosystem,
            "version": "N/A",
            "license": "Unknown",
            "summary": "Error fetching data",
            "author": "Unknown",
            "home_page": None,
            "project_url": None,
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
                           popular_packages=POPULAR_PACKAGES,
                           ecosystems=SUPPORTED_ECOSYSTEMS,
                           ai_ml_packages=AI_ML_PACKAGES[:20])


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
        meta = _fetch_meta_for_ecosystem(package, ecosystem)
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
                               ecosystems=SUPPORTED_ECOSYSTEMS,
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
                               ecosystems=SUPPORTED_ECOSYSTEMS,
                               cvss_severity=cvss_severity)


@app.route("/dashboard")
@track_visitor
def dashboard():
    # Only fetch PyPI packages for the dashboard to keep it fast
    pypi_pkgs = [
        "flask", "django", "requests", "numpy", "pandas",
        "sqlalchemy", "celery", "pytest", "beautifulsoup4", "pillow",
        "tensorflow", "torch", "scikit-learn", "transformers", "fastapi",
    ]
    packages = [get_package_info(pkg, "PyPI") for pkg in pypi_pkgs]
    stats = {
        "unique_visitors": len(STATS["unique_visitors"]),
        "total_searches": STATS["total_searches"]
    }
    trending = get_trending_packages(5)
    return render_template("dashboard.html", packages=packages, stats=stats,
                           trending=trending, ecosystems=SUPPORTED_ECOSYSTEMS,
                           ecosystem_packages=ECOSYSTEM_PACKAGES,
                           ai_ml_packages=AI_ML_PACKAGES)


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
    packages = [get_package_info(pkg, "PyPI") for pkg in POPULAR_PACKAGES[:10]]
    return jsonify(packages)


@app.route("/api/ecosystems")
def api_ecosystems():
    """List all supported ecosystems with package counts."""
    result = []
    for eco in SUPPORTED_ECOSYSTEMS:
        pkgs = ECOSYSTEM_PACKAGES.get(eco["id"], [])
        result.append({
            "id": eco["id"],
            "label": eco["label"],
            "icon": eco["icon"],
            "package_count": len(pkgs),
            "sample_packages": pkgs[:5],
        })
    return jsonify(result)


@app.route("/api/packages/ecosystem/<ecosystem>")
def api_packages_by_ecosystem(ecosystem):
    """Return the known package list for a given ecosystem."""
    pkgs = ECOSYSTEM_PACKAGES.get(ecosystem)
    if pkgs is None:
        return jsonify({"error": f"Unknown ecosystem: {ecosystem}",
                        "supported": [e["id"] for e in SUPPORTED_ECOSYSTEMS]}), 404
    return jsonify({"ecosystem": ecosystem, "packages": pkgs, "count": len(pkgs)})


@app.route("/api/search/advanced")
def api_search_advanced():
    """Multi-ecosystem package search.

    Query params:
      q        – search term (required)
      ecosystem – comma-separated list of ecosystems to search (default: all)
      limit    – max results per ecosystem (default: 10)
    """
    q = request.args.get("q", "").strip().lower()
    if not q:
        return jsonify({"error": "q parameter is required"}), 400

    ecosystems_param = request.args.get("ecosystem", "")
    requested = [e.strip() for e in ecosystems_param.split(",") if e.strip()] \
        if ecosystems_param else [e["id"] for e in SUPPORTED_ECOSYSTEMS]
    limit = min(int(request.args.get("limit", 10)), 50)

    results = {}
    for eco in requested:
        pkgs = ECOSYSTEM_PACKAGES.get(eco, [])
        matches = [p for p in pkgs if q in p.lower()][:limit]
        if matches:
            results[eco] = matches

    # Also search previously searched packages
    searched = [p for p in STATS["searches_by_package"] if q in p.lower()][:limit]
    if searched:
        results["_recent"] = searched

    return jsonify({"query": q, "results": results,
                    "total": sum(len(v) for v in results.values())})


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

    # Emit one URL per package per ecosystem (capped to keep sitemap manageable)
    for eco_id, pkgs in ECOSYSTEM_PACKAGES.items():
        for pkg in pkgs[:100]:  # top 100 per ecosystem
            safe_pkg = pkg.replace("&", "%26").replace(":", "%3A")
            xml_parts.append(
                f"  <url>\n"
                f"    <loc>{BASE_URL}/search?package={safe_pkg}&amp;ecosystem={eco_id}</loc>\n"
                f"    <lastmod>{now}</lastmod>\n"
                f"    <changefreq>weekly</changefreq>\n"
                f"    <priority>0.6</priority>\n"
                f"  </url>"
            )

    # Also include AI/ML packages under PyPI
    for pkg in AI_ML_PACKAGES:
        safe_pkg = pkg.replace("&", "%26")
        xml_parts.append(
            f"  <url>\n"
            f"    <loc>{BASE_URL}/search?package={safe_pkg}&amp;ecosystem=PyPI</loc>\n"
            f"    <lastmod>{now}</lastmod>\n"
            f"    <changefreq>weekly</changefreq>\n"
            f"    <priority>0.7</priority>\n"
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

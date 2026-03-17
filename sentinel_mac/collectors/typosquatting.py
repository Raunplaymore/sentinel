"""Sentinel — Typosquatting Detector.

Checks package names from pip/npm install commands against a curated list
of popular packages using edit distance. Flags packages that look like
misspellings of well-known packages — a common attack vector when AI agents
hallucinate or mistype package names.

Package lists: top ~300 PyPI + top ~200 npm (as of 2026-03).
Update at each Sentinel version bump. See CLAUDE.md for instructions.
"""

import re
from typing import Optional


# ── Popular PyPI packages (top ~300, 2026-03) ────────────────────────────────
POPULAR_PYPI = {
    "boto3", "packaging", "urllib3", "setuptools", "certifi", "requests",
    "typing-extensions", "botocore", "idna", "charset-normalizer",
    "aiobotocore", "python-dateutil", "six", "cryptography", "cffi",
    "numpy", "pyyaml", "s3transfer", "pip", "pycparser", "pluggy",
    "pydantic", "pygments", "s3fs", "fsspec", "click", "protobuf",
    "pandas", "attrs", "pydantic-core", "pytest", "anyio", "markupsafe",
    "h11", "iniconfig", "platformdirs", "jmespath", "wheel",
    "annotated-types", "filelock", "jinja2", "importlib-metadata",
    "pathspec", "pyjwt", "rsa", "httpx", "zipp", "pytz", "httpcore",
    "pyasn1", "aiohttp", "python-dotenv", "rich", "multidict",
    "jsonschema", "google-auth", "tzdata", "yarl", "colorama", "tqdm",
    "grpcio", "tomli", "awscli", "virtualenv", "frozenlist",
    "googleapis-common-protos", "requests-oauthlib", "markdown-it-py",
    "aiosignal", "wrapt", "greenlet", "pillow", "pyasn1-modules",
    "sqlalchemy", "scipy", "pyarrow", "uvicorn", "starlette",
    "oauthlib", "psutil", "pyparsing", "fastapi", "cachetools",
    "opentelemetry-proto", "tenacity", "openpyxl", "regex",
    "sniffio", "websocket-client", "soupsieve", "beautifulsoup4",
    "distlib", "lxml", "opentelemetry-api", "shellingham",
    "more-itertools", "langchain", "hatchling", "requests-toolbelt",
    "exceptiongroup", "docutils", "proto-plus", "websockets",
    "pyopenssl", "google-cloud-storage", "werkzeug", "coverage",
    "flask", "pynacl", "sortedcontainers", "psycopg2-binary",
    "msgpack", "typer", "pydantic-settings", "decorator", "openai",
    "networkx", "poetry-core", "dnspython", "huggingface-hub",
    "python-multipart", "distro", "azure-core", "scikit-learn",
    "redis", "joblib", "msal", "bcrypt", "snowflake-connector-python",
    "matplotlib", "gitpython", "ruff", "google-cloud-core", "jiter",
    "async-timeout", "threadpoolctl", "itsdangerous", "tabulate",
    "types-requests", "textual", "alembic", "asn1crypto",
    "prompt-toolkit", "deprecated", "smmap", "kubernetes", "zstandard",
    "chardet", "gitdb", "orjson", "pytest-cov", "defusedxml",
    "prometheus-client", "blinker", "tzlocal", "rapidfuzz",
    "contourpy", "paramiko", "backoff", "google-api-python-client",
    "build", "pytest-asyncio", "dill", "docker", "cycler",
    "fastjsonschema", "email-validator", "cloudpickle", "mako",
    "marshmallow", "transformers", "nodeenv", "tokenizers", "babel",
    "sqlparse", "sympy", "mypy", "ipython", "aiofiles", "xmltodict",
    "uvloop", "black", "toml", "identify", "mpmath", "traitlets",
    "tornado", "parso", "cython", "jedi", "gunicorn", "sentry-sdk",
    "isort", "markdown", "tiktoken", "asgiref", "mcp",
    "nest-asyncio", "langchain-core", "pymongo", "pymysql",
    "watchdog", "termcolor", "typing-inspect", "authlib",
    "debugpy", "litellm",
}

# ── Popular npm packages (top ~200, 2026-03) ─────────────────────────────────
POPULAR_NPM = {
    "lodash", "react", "react-dom", "vue", "angular", "express",
    "next", "axios", "typescript", "webpack", "babel-core",
    "@babel/core", "@babel/preset-env", "jest", "mocha", "chai",
    "sinon", "eslint", "prettier", "moment", "dayjs", "underscore",
    "jquery", "d3", "three", "socket.io", "mongoose", "sequelize",
    "typeorm", "prisma", "graphql", "apollo-server", "redux",
    "zustand", "mobx", "rxjs", "ramda", "immutable", "immer",
    "zod", "yup", "joi", "dotenv", "commander", "inquirer", "chalk",
    "ora", "figures", "debug", "winston", "pino", "morgan",
    "body-parser", "cors", "helmet", "passport", "jsonwebtoken",
    "bcrypt", "bcryptjs", "nodemailer", "multer", "sharp",
    "uuid", "nanoid", "crypto-js", "forge", "node-fetch",
    "got", "superagent", "cheerio", "puppeteer", "playwright",
    "selenium-webdriver", "cypress", "vitest", "rollup", "vite",
    "esbuild", "parcel", "gulp", "grunt", "pm2", "nodemon",
    "concurrently", "cross-env", "dotenv-cli", "rimraf", "mkdirp",
    "glob", "fast-glob", "chokidar", "fs-extra", "path-browserify",
    "stream-browserify", "buffer", "events", "process",
    "readable-stream", "through2", "bl", "concat-stream",
    "tar", "archiver", "adm-zip", "yauzl", "yazl",
    "semver", "node-semver", "compare-versions",
    "lodash-es", "fp-ts", "io-ts", "effect",
    "objection", "bookshelf",
    "redis", "ioredis", "bull", "bullmq", "bee-queue",
    "aws-sdk", "@aws-sdk/client-s3", "firebase", "@google-cloud/storage",
    "stripe", "twilio", "sendgrid", "@sendgrid/mail",
    "jimp", "canvas", "fabric",
    "markdown-it", "marked", "showdown", "remark",
    "highlight.js", "prismjs", "shiki",
    "socket.io-client", "ws", "uws",
    "pg", "mysql2", "sqlite3", "mongodb",
    "class-transformer", "class-validator", "reflect-metadata",
    "tsyringe", "inversify", "awilix",
    "date-fns", "luxon", "timezone-support",
    "lodash.merge", "lodash.clonedeep", "lodash.get",
    "mime", "mime-types", "content-type",
    "qs", "querystring", "form-data",
    "async", "bluebird", "p-limit", "p-queue", "p-retry",
    "retry", "exponential-backoff",
    "compression", "serve-static", "finalhandler",
    "on-finished", "depd", "destroy", "inherits",
    "ansi-styles", "supports-color", "has-flag",
    "string-width", "strip-ansi", "wrap-ansi",
    "yargs", "minimist", "meow", "cac",
    "table", "cli-table3", "boxen",
    "open", "execa", "cross-spawn", "which",
    "conf", "cosmiconfig", "rc", "config",
    "jest-circus", "@jest/globals", "ts-jest",
    "@testing-library/react", "@testing-library/jest-dom",
    "nock", "msw", "supertest",
}

# ── Regex to extract package names ───────────────────────────────────────────
# pip install foo bar==1.0 baz>=2 → ["foo", "bar", "baz"]
_PIP_EXTRAS_RE = re.compile(r"[>=<!~\[].*")
_FLAGS_RE = re.compile(r"^-")  # shared for pip and npm flag tokens

# ── Module-level normalized caches (built once at import time) ────────────────
# Exact-match sets (normalized) for fast O(1) lookups
POPULAR_PYPI_NORMALIZED: frozenset[str] = frozenset(
    p.lower().replace("_", "-").replace(".", "-") for p in POPULAR_PYPI
)
POPULAR_NPM_NORMALIZED: frozenset[str] = frozenset(
    p.lower().replace("_", "-").replace(".", "-") for p in POPULAR_NPM
)
# Pre-normalized (norm, original) pairs for distance comparisons
_POPULAR_PYPI_NORM_PAIRS: list[tuple[str, str]] = [
    (p.lower().replace("_", "-").replace(".", "-"), p) for p in POPULAR_PYPI
]
_POPULAR_NPM_NORM_PAIRS: list[tuple[str, str]] = [
    (p.lower().replace("_", "-").replace(".", "-"), p) for p in POPULAR_NPM
]


def _normalize(name: str) -> str:
    """Normalize package name: lowercase, hyphens/underscores/dots interchangeable."""
    return name.lower().replace("_", "-").replace(".", "-")


def _levenshtein(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)

    # Optimization: skip if length difference alone exceeds threshold
    if abs(len(a) - len(b)) > 3:
        return abs(len(a) - len(b))

    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        curr = [i + 1]
        for j, cb in enumerate(b):
            curr.append(min(
                prev[j + 1] + 1,   # deletion
                curr[j] + 1,       # insertion
                prev[j] + (ca != cb),  # substitution
            ))
        prev = curr
    return prev[-1]


def extract_pip_packages(command: str) -> list[str]:
    """Extract package names from a pip install command string."""
    # Strip the "pip install" / "pip3 install" prefix
    match = re.search(r"pip3?\s+install\s+", command)
    if not match:
        return []

    rest = command[match.end():]
    packages = []
    for token in rest.split():
        # Skip flags like --upgrade, -q, etc.
        if _FLAGS_RE.match(token):
            continue
        # Strip version specifiers: foo>=1.0 → foo
        name = _PIP_EXTRAS_RE.sub("", token).strip()
        if name:
            packages.append(name)
    return packages


def extract_npm_packages(command: str) -> list[str]:
    """Extract package names from an npm/npx install command string."""
    match = re.search(r"npm\s+(?:install|i|add)\s+", command)
    if not match:
        return []

    rest = command[match.end():]
    packages = []
    for token in rest.split():
        if _FLAGS_RE.match(token):
            continue
        # Strip version: foo@1.0 → foo (but keep @scope/pkg intact)
        if "@" in token and not token.startswith("@"):
            token = token.split("@")[0]
        if token:
            packages.append(token)
    return packages


def check_typosquatting(
    package: str,
    ecosystem: str,  # "pip" or "npm"
) -> Optional[dict]:
    """Check if a package name looks like a typosquat of a popular package.

    Returns a dict with match info if suspicious, None if clean.
    """
    norm = _normalize(package)

    # Exact match — legit
    exact_set = POPULAR_PYPI_NORMALIZED if ecosystem == "pip" else POPULAR_NPM_NORMALIZED
    if norm in exact_set:
        return None

    norm_pairs = _POPULAR_PYPI_NORM_PAIRS if ecosystem == "pip" else _POPULAR_NPM_NORM_PAIRS
    best_match = None
    best_dist = 999

    for known_norm, known in norm_pairs:
        # Skip comparison if length difference is too large
        if abs(len(norm) - len(known_norm)) > 3:
            continue

        dist = _levenshtein(norm, known_norm)

        # Distance 1 on short names is very suspicious
        # Distance 2 only flag for longer names to reduce false positives
        threshold = 1 if len(norm) <= 8 else 2

        if dist <= threshold and dist < best_dist:
            best_dist = dist
            best_match = known

    if best_match is None:
        return None

    confidence = "high" if best_dist == 1 else "medium"
    return {
        "package": package,
        "ecosystem": ecosystem,
        "similar_to": best_match,
        "edit_distance": best_dist,
        "confidence": confidence,
    }

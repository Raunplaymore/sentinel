"""Sentinel — Typosquatting Detector.

Checks package names from pip/npm install commands against a curated list
of popular packages using edit distance. Flags packages that look like
misspellings of well-known packages — a common attack vector when AI agents
hallucinate or mistype package names.

Package lists: top ~300 PyPI (2026-04) + top ~200 npm (2026-03).
Update at each Sentinel version bump. See CLAUDE.md for instructions.
"""

import re
import shlex
from typing import Optional


# ── Popular PyPI packages (top ~300, 2026-04) ────────────────────────────────
POPULAR_PYPI = {
    "boto3", "packaging", "setuptools", "urllib3", "certifi",
    "typing-extensions", "requests", "charset-normalizer", "idna",
    "botocore", "aiobotocore", "python-dateutil", "cryptography", "six",
    "numpy", "cffi", "pyyaml", "grpcio-status", "pycparser", "pydantic",
    "pluggy", "s3transfer", "pygments", "click", "attrs", "protobuf",
    "pydantic-core", "anyio", "fsspec", "pandas", "pytest", "h11",
    "markupsafe", "iniconfig", "s3fs", "platformdirs", "annotated-types",
    "pip", "wheel", "jinja2", "jmespath", "importlib-metadata", "filelock",
    "pathspec", "pyjwt", "httpx", "typing-inspection", "python-dotenv",
    "httpcore", "pytz", "zipp", "rich", "pyasn1", "jsonschema", "yarl",
    "multidict", "aiohttp", "google-auth", "uvicorn", "markdown-it-py",
    "google-api-core", "tzdata", "tqdm", "tomli", "colorama",
    "googleapis-common-protos", "mdurl", "starlette", "virtualenv",
    "awscli", "pillow", "propcache", "frozenlist", "scipy", "rpds-py",
    "trove-classifiers", "fastapi", "rsa", "referencing", "wrapt",
    "pyasn1-modules", "aiosignal", "jsonschema-specifications", "greenlet",
    "grpcio", "sqlalchemy", "requests-oauthlib", "pyarrow", "pyparsing",
    "aiohappyeyeballs", "opentelemetry-api", "tenacity", "annotated-doc",
    "cachetools", "regex", "psutil", "opentelemetry-semantic-conventions",
    "hatchling", "oauthlib", "opentelemetry-sdk", "sniffio",
    "more-itertools", "soupsieve", "shellingham", "websockets",
    "exceptiongroup", "docutils", "beautifulsoup4", "tomlkit", "lxml",
    "typer", "distlib", "grpcio-tools", "et-xmlfile", "openpyxl",
    "requests-toolbelt", "google-genai", "mypy-extensions",
    "pydantic-settings", "networkx", "dnspython", "proto-plus",
    "websocket-client", "opentelemetry-proto", "coverage", "werkzeug",
    "python-multipart", "msgpack", "pyopenssl", "openai", "langchain",
    "google-cloud-storage", "distro", "flask", "psycopg2-binary", "pynacl",
    "tabulate", "wcwidth", "opentelemetry-exporter-otlp-proto-http",
    "keyring", "huggingface-hub", "smmap", "sortedcontainers",
    "scikit-learn", "decorator", "fonttools", "isodate", "watchfiles",
    "jaraco-classes", "matplotlib", "secretstorage", "joblib", "jeepney",
    "opentelemetry-exporter-otlp-proto-grpc", "ruff", "poetry-core",
    "jiter", "redis", "jaraco-context",
    "opentelemetry-exporter-otlp-proto-common", "kiwisolver",
    "google-cloud-aiplatform", "jaraco-functools", "gitpython",
    "azure-core", "azure-identity", "ptyprocess", "pexpect", "bcrypt",
    "email-validator", "itsdangerous", "threadpoolctl", "editables",
    "msal", "pytest-cov", "google-cloud-core", "python-discovery",
    "alembic", "mcp", "zstandard", "sse-starlette", "contourpy",
    "prompt-toolkit", "ruamel-yaml", "snowflake-connector-python",
    "defusedxml", "async-timeout", "opentelemetry-instrumentation",
    "types-requests", "orjson", "textual", "gitdb", "sympy", "deprecated",
    "pytest-asyncio", "docstring-parser", "blinker", "google-crc32c",
    "docker", "rapidfuzz", "google-resumable-media", "mpmath", "tzlocal",
    "chardet", "pyproject-hooks", "cycler", "jsonpointer", "asn1crypto",
    "build", "kubernetes", "mako", "google-api-python-client", "dill",
    "setuptools-scm", "prometheus-client", "backoff", "paramiko",
    "sentry-sdk", "uv", "hf-xet", "opentelemetry-exporter-otlp",
    "yandexcloud", "google-auth-oauthlib", "marshmallow", "uritemplate",
    "fastjsonschema", "google-cloud-bigquery", "mypy", "tokenizers",
    "uvloop", "google-auth-httplib2", "nodeenv", "httplib2", "sqlparse",
    "transformers", "toml", "ipython", "msal-extensions", "authlib",
    "babel", "black", "tiktoken", "azure-storage-blob", "xmltodict",
    "httptools", "jsonpatch", "httpx-sse", "tornado", "cython", "aiofiles",
    "pre-commit", "cloudpickle", "identify", "gunicorn",
    "google-cloud-secret-manager", "parso", "traitlets", "cfgv",
    "executing", "asgiref", "databricks-sdk", "opentelemetry-util-http",
    "jedi", "opentelemetry-instrumentation-requests", "asttokens",
    "importlib-resources", "pytest-xdist", "google-cloud-batch",
    "pydantic-ai-slim", "matplotlib-inline", "grpc-google-iam-v1", "py4j",
    "execnet", "python-json-logger", "langchain-core", "jsonschema-path",
    "markdown", "durationpy", "google-analytics-admin", "cachecontrol",
    "webencodings", "stack-data", "pure-eval", "nest-asyncio", "xxhash",
    "multiprocess", "typing-inspect", "isort", "litellm", "h2", "gcsfs",
    "hyperframe", "hpack", "dbt-core", "grpcio-health-checking",
    "pathable", "termcolor", "watchdog", "pymongo", "flatbuffers",
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

# DEFECT FIX (v0.8): package-name validators reject obvious noise that the
# old regex-only extractor would otherwise feed into the Levenshtein
# scorer (e.g. `(mypy`, `MCP,`, pure-digit tokens). PEP 503 allows pure
# digits but real packages never look like that.
#
# PEP 503: name = letter/digit, then [letter|digit|.|-|_]*. We cap at
# 214 chars (PyPI hard limit) and reject pure-digit tokens.
_PIP_NAME_RE = re.compile(r"^[A-Za-z0-9][-_.A-Za-z0-9]{0,213}$")

# npm registry rules (simplified): lowercase, digits, hyphens, underscores,
# dots; optional @scope/ prefix. npm rejects uppercase since 2017.
_NPM_NAME_RE = re.compile(
    r"^(?:@[a-z0-9][-_.a-z0-9]{0,213}/)?[a-z0-9][-_.a-z0-9]{0,213}$"
)


def _is_valid_pip_name(name: str) -> bool:
    """Loose PEP 503 check + reject obvious noise (numbers only, etc.)."""
    if not _PIP_NAME_RE.match(name):
        return False
    # Pure-digit "names" are PEP 503 valid technically but never real packages.
    if name.isdigit():
        return False
    return True


def _is_valid_npm_name(name: str) -> bool:
    """npm registry rules + reject pure-numeric noise."""
    if not _NPM_NAME_RE.match(name):
        return False
    if name.isdigit():
        return False
    return True


# Shell metachars that terminate a subcommand or redirect its I/O.
# Tokens after these inside the same subcommand are NOT package names
# (they are output paths, file descriptors, pipelines targets, etc.).
_SUBCOMMAND_SEPARATORS: frozenset[str] = frozenset({"&&", "||", ";", "&"})
_REDIRECT_TOKENS: frozenset[str] = frozenset(
    {">", ">>", "<", "<<", "<<<", "|", "2>", "2>>", "&>", "&>>"}
)


def _split_subcommands(command: str) -> list[list[str]]:
    """Split a shell command into independent subcommands.

    Tokenizes via :class:`shlex.shlex` with ``punctuation_chars=True`` so
    quoted strings stay intact (the original bug — `git commit -m
    "...pip install foo..."` looked like a real install) AND adjacent
    operators without surrounding whitespace are still recognized
    (``pip install foo&&pip install bar`` and ``pip install foo>out.txt``
    both tokenize correctly — the previous ``shlex.split`` glued the
    operator to a neighboring token, producing ``foo&&pip`` as a single
    token and missing the second subcommand).

    Splits on the unquoted shell separators ``&&``, ``||``, ``;``, and
    standalone ``&``. Tokens at or after a redirect operator
    (``>``, ``<``, ``|`` and friends) are dropped from the current
    subcommand — they can never be package names.

    Returns one token list per subcommand. Returns ``[]`` if the command
    is malformed (unclosed quote, etc.) — callers must treat that as
    "no extractable packages" rather than fall back to the raw string.
    """
    try:
        sh = shlex.shlex(command, posix=True, punctuation_chars=True)
        sh.whitespace_split = True
        tokens = list(sh)
    except ValueError:
        return []
    subs: list[list[str]] = []
    cur: list[str] = []
    in_redirect_tail = False
    for tok in tokens:
        if tok in _SUBCOMMAND_SEPARATORS:
            if cur:
                subs.append(cur)
                cur = []
            in_redirect_tail = False
            continue
        if tok in _REDIRECT_TOKENS:
            # Everything from here until the next subcommand separator
            # is redirect plumbing (file paths, FDs) — skip it.
            in_redirect_tail = True
            continue
        if in_redirect_tail:
            continue
        cur.append(tok)
    if cur:
        subs.append(cur)
    return subs

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
    """Extract package names from a ``pip install`` subcommand.

    DEFECT FIX (v0.8): the previous implementation regex-scanned the raw
    command for ``pip install`` and treated every following whitespace
    token as a package — including tokens that lived inside a quoted
    string (e.g. ``git commit -m "...pip install foo..."``). We now use
    :func:`shlex.split` to respect quotes and only recognize a
    subcommand whose first token is ``pip`` / ``pip3`` (or
    ``python(3) -m pip``). Each candidate token is validated against
    :func:`_is_valid_pip_name`, which rejects pure-digit and noise
    tokens that pollute the typosquatting score.

    Signature is preserved — external callers (``core._hook_check``,
    ``agent_log_parser._check_typosquatting``) keep working.
    """
    packages: list[str] = []
    for sub in _split_subcommands(command):
        # Need at least: ["pip", "install", <something>]
        if len(sub) < 3:
            continue
        leader = sub[0]
        if leader in ("pip", "pip3"):
            if sub[1] != "install":
                continue
            rest_start = 2
        elif (
            leader in ("python", "python3")
            and len(sub) >= 5
            and sub[1] == "-m"
            and sub[2] == "pip"
            and sub[3] == "install"
        ):
            rest_start = 4
        else:
            continue
        for token in sub[rest_start:]:
            if _FLAGS_RE.match(token):
                continue
            # Strip version specifiers + extras: foo>=1.0 → foo, foo[bar] → foo
            name = _PIP_EXTRAS_RE.sub("", token).strip()
            if name and _is_valid_pip_name(name):
                packages.append(name)
    return packages


def extract_npm_packages(command: str) -> list[str]:
    """Extract package names from an ``npm install`` / ``add`` subcommand.

    DEFECT FIX (v0.8): see :func:`extract_pip_packages`. Same shlex +
    subcommand-leader treatment, validated against npm's stricter
    naming rules (lowercase, optional ``@scope/`` prefix).
    """
    packages: list[str] = []
    for sub in _split_subcommands(command):
        if len(sub) < 3:
            continue
        if sub[0] != "npm":
            continue
        if sub[1] not in ("install", "i", "add"):
            continue
        for token in sub[2:]:
            if _FLAGS_RE.match(token):
                continue
            # Strip version: foo@1.0 → foo (but keep @scope/pkg intact)
            if "@" in token and not token.startswith("@"):
                token = token.split("@")[0]
            if token and _is_valid_npm_name(token):
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

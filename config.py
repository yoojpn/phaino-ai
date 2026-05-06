"""
vulnscan 設定ファイル
"""
import os

# デフォルトモデル
LLM_MODEL   = os.getenv("LLM_MODEL", "Qwen/Qwen3.6-27B")
LLM_API_KEY  = os.getenv("LLM_API_KEY", "token-vulnscan")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://localhost:8000/v1")

# ===========================
# CodeQL設定
# ===========================
CODEQL_PATH     = os.getenv("CODEQL_PATH", "codeql")
CODEQL_DB_DIR   = os.getenv("CODEQL_DB_DIR", "/tmp/codeql_dbs")
CODEQL_TIMEOUT  = 300

CODEQL_LANGUAGES = {
    "python":     "python",
    "javascript": "javascript",
    "typescript": "javascript",
    "java":       "java",
    "go":         "go",
    "ruby":       "ruby",
    "rust":       "rust",
}

# ===========================
# スキャン設定
# ===========================
LANGUAGE_PRIORITY = {
    "python": 1, "javascript": 1, "typescript": 1,
    "java": 2, "php": 2, "go": 2,
    "ruby": 3, "rust": 3, "c": 3, "cpp": 3,
}
MAX_FUNCTION_TOKENS = 2_000
BATCH_SIZE          = 200
MAX_REACT_STEPS     = 32
MAX_DOCKER_RETRY    = 5
MAX_PARALLEL_DOCKER = 6
MIN_EXPLOITABILITY  = "practical"

# ===========================
# Docker設定
# ===========================
DOCKER_TIMEOUT = 30
DOCKER_MEMORY  = "512m"

# ===========================
# レポート設定
# ===========================
REPORT_FORMAT = "hackerone"
OUTPUT_DIR    = "./reports"

# ===========================
# 除外設定
# ===========================
EXCLUDE_DIRS = {
    "node_modules", ".git", "__pycache__", ".pytest_cache",
    "vendor", "dist", "build", ".venv", "venv", "env",
    "target", "out", ".idea", ".vscode",
    "plugins", "bower_components", "third_party",
    "jquery", "bootstrap", "angular",
    # テスト系
    "test", "tests", "testing", "unittest", "testdata",
    "fixtures", "mocks", "mock", "spec", "specs",
    "benchmarks", "benchmark", "perf",
    # 言語バインディング・自動生成
    "csharp", "objc", "kotlin", "swift", "lua", "perl",
    "generated", "gen", "auto_generated", "pb",
    # ドキュメント・サンプル
    "docs", "doc", "examples", "example", "samples", "demo",
    "tutorial", "conformance",
}
EXCLUDE_FILE_PATTERNS = [
    r"\.min\.[jt]s$",
    r"-\d+\.\d+[\d\.]*\.js$",
    r"wysihtml", r"codemirror", r"tinymce",
    r"moment\.js$", r"lodash.*\.js$",
    r"underscore.*\.js$", r"backbone.*\.js$",
    r"ace\.js$", r"ckeditor", r"polyfill.*\.js$",
    r"clipboard", r"tinysort",
]

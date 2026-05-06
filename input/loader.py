"""
入力レイヤー - GitHub API / ZIP / サイトURL
"""

import os
import re
import shutil
import zipfile
import tempfile
import base64
import subprocess
import concurrent.futures
from pathlib import Path
from typing import List, Optional, Tuple
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from config import EXCLUDE_DIRS, EXCLUDE_FILE_PATTERNS

CODE_EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".ts": "typescript",
    ".jsx": "javascript", ".tsx": "typescript", ".java": "java",
    ".php": "php", ".go": "go", ".rs": "rust", ".rb": "ruby",
    ".c": "c", ".cpp": "cpp", ".cc": "cpp", ".h": "c", ".hpp": "cpp",
}


class CodeFile:
    def __init__(self, path: str, language: str, content: str):
        self.path     = path
        self.language = language
        self.content  = content
        self.size     = len(content)


class InputLoader:

    def __init__(self):
        self.github_token = os.getenv("GITHUB_TOKEN", "")

    def load(self, source: str) -> List[CodeFile]:
        if self._is_github_url(source):
            return self.load_github(source)
        elif os.path.isdir(source):
            return self.load_dir(source)
        elif source.endswith(".zip") or (os.path.isfile(source) and not source.startswith("http")):
            return self.load_zip(source)
        elif source.startswith("http"):
            return self.load_url(source)
        else:
            raise ValueError(f"不明な入力形式: {source}")

    # ===========================
    # GitHub
    # ===========================
    def load_github(self, url: str) -> List[CodeFile]:
        print(f"[*] GitHub取得: {url}")
        # サブディレクトリ指定: /tree/BRANCH/PATH or /blob/BRANCH/PATH
        subdir_match = re.search(
            r"github\.com/([^/]+/[^/]+)/(?:tree|blob)/([^/]+)/(.+)", url
        )
        if subdir_match:
            repo   = subdir_match.group(1)
            branch = subdir_match.group(2)
            subdir = subdir_match.group(3).rstrip("/")
            print(f"  サブディレクトリ指定: {subdir} (branch={branch})")
            files = self._load_github_api(repo, branch=branch, subdir=subdir)
            if files:
                return files
            return self._load_github_clone_sparse(repo, branch, subdir)
        match = re.search(r"github\.com/([^/]+/[^/]+?)(?:\.git)?(?:/|$)", url)
        if match:
            repo  = match.group(1)
            files = self._load_github_api(repo)
            if files:
                return files
        return self._load_github_clone(url)

    def _load_github_api(self, repo: str, branch: str = None, subdir: str = None) -> List[CodeFile]:
        headers = {"Accept": "application/vnd.github.v3+json"}
        if self.github_token:
            headers["Authorization"] = f"token {self.github_token}"

        # デフォルトブランチ取得
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{repo}",
                headers=headers, timeout=10,
            )
            resp.raise_for_status()
            default_branch = resp.json().get("default_branch", "main")
        except Exception:
            default_branch = "main"

        # ファイルツリー取得
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{repo}/git/trees/{branch or default_branch}?recursive=1",
                headers=headers, timeout=30,
            )
            resp.raise_for_status()
            tree = resp.json().get("tree", [])
        except Exception as e:
            print(f"  [-] GitHub API失敗: {e}")
            return []

        print(f"  ツリー取得: {len(tree)}件")

        # コードファイルを絞り込む
        targets = []
        for item in tree:
            if item.get("type") != "blob":
                continue
            path = item.get("path", "")
            if subdir and not path.startswith(subdir + "/") and path != subdir:
                continue
            ext  = Path(path).suffix.lower()
            lang = CODE_EXTENSIONS.get(ext)
            if not lang:
                continue
            parts = Path(path).parts
            if any(ex in parts for ex in EXCLUDE_DIRS):
                continue
            if any(re.search(p, Path(path).name, re.IGNORECASE) for p in EXCLUDE_FILE_PATTERNS):
                continue
            if item.get("size", 0) > 1_000_000:
                continue
            targets.append((path, lang, item.get("url", "")))

        print(f"  対象ファイル: {len(targets)}件 → コンテンツ取得中...")

        # 並列でコンテンツ取得（最大200件）
        def fetch_file(args: Tuple[str, str, str]) -> Optional[CodeFile]:
            path, lang, blob_url = args
            try:
                r = requests.get(blob_url, headers=headers, timeout=10)
                r.raise_for_status()
                blob_data = r.json()
                encoding  = blob_data.get("encoding", "")
                if encoding == "base64":
                    content = base64.b64decode(blob_data["content"]).decode("utf-8", errors="ignore")
                else:
                    content = blob_data.get("content", "")
                if not content.strip():
                    return None
                lines    = content.split("\n")
                max_line = max((len(l) for l in lines), default=0)
                if len(lines) < 10 and max_line > 500:
                    return None
                if max_line > 2000:
                    return None
                return CodeFile(path=path, language=lang, content=content)
            except Exception:
                return None

        files = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
            for result in ex.map(fetch_file, targets):
                if result:
                    files.append(result)

        print(f"[+] {len(files)}件のコードファイルを取得")
        return files


    def _load_github_clone_sparse(self, repo: str, branch: str, subdir: str):
        import tempfile, subprocess
        tmpdir = tempfile.mkdtemp(prefix="vulnscan_sparse_")
        try:
            clone_url = f"https://github.com/{repo}.git"
            subprocess.run(["git", "clone", "--depth=1", "--filter=blob:none",
                           "--sparse", clone_url, tmpdir],
                          check=True, capture_output=True)
            subprocess.run(["git", "sparse-checkout", "set", subdir],
                          check=True, capture_output=True, cwd=tmpdir)
            return self.load_dir(str(Path(tmpdir) / subdir))
        except Exception as e:
            print(f"  [-] sparse clone失敗: {e}")
            return []

    def _load_github_clone(self, url: str) -> List[CodeFile]:
        print(f"  [*] git clone フォールバック...")
        tmpdir = tempfile.mkdtemp(prefix="vulnscan_")
        try:
            result = subprocess.run(
                ["git", "clone", "--depth=1", "--single-branch", url, tmpdir],
                capture_output=True, text=True, timeout=300,
            )
            if result.returncode != 0:
                raise RuntimeError(f"git clone失敗: {result.stderr}")
            files = self._collect_files(tmpdir)
            print(f"[+] {len(files)}件のコードファイルを取得")
            return files
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ===========================
    # ZIP
    # ===========================
    def load_zip(self, zip_path: str) -> List[CodeFile]:
        print(f"[*] ZIP展開: {zip_path}")
        tmpdir = tempfile.mkdtemp(prefix="vulnscan_")
        try:
            with zipfile.ZipFile(zip_path, "r") as zf:
                zf.extractall(tmpdir)
            files = self._collect_files(tmpdir)
            print(f"[+] {len(files)}件のコードファイルを取得")
            return files
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    # ===========================
    # URL
    # ===========================
    def load_url(self, url: str) -> List[CodeFile]:
        print(f"[*] URL取得: {url}")
        files   = []
        visited = set()

        try:
            resp = requests.get(url, timeout=10)
            resp.raise_for_status()
            html = resp.text
            files.append(CodeFile(
                path=f"{url}/index.html",
                language="javascript",
                content=html,
            ))
            soup = BeautifulSoup(html, "html.parser")
            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"

            for script in soup.find_all("script"):
                src = script.get("src")
                if src:
                    if any(re.search(p, src, re.IGNORECASE) for p in EXCLUDE_FILE_PATTERNS):
                        continue
                    js_url = src if src.startswith("http") else base + src
                    if js_url not in visited:
                        visited.add(js_url)
                        try:
                            r = requests.get(js_url, timeout=10)
                            if r.status_code == 200:
                                files.append(CodeFile(
                                    path=js_url,
                                    language="javascript",
                                    content=r.text,
                                ))
                        except Exception:
                            pass
                elif script.string:
                    files.append(CodeFile(
                        path=f"{url}/inline_{len(files)}.js",
                        language="javascript",
                        content=script.string,
                    ))
        except Exception as e:
            print(f"[-] URL取得エラー: {e}")

        print(f"[+] {len(files)}件のファイルを取得")
        return files

    # ===========================
    # ユーティリティ
    # ===========================
    def _collect_files(self, root: str) -> List[CodeFile]:
        files     = []
        root_path = Path(root)
        for path in root_path.rglob("*"):
            if any(ex in path.parts for ex in EXCLUDE_DIRS):
                continue
            if not path.is_file():
                continue
            ext  = path.suffix.lower()
            lang = CODE_EXTENSIONS.get(ext)
            if not lang:
                continue
            if any(re.search(p, path.name, re.IGNORECASE) for p in EXCLUDE_FILE_PATTERNS):
                continue
            try:
                content  = path.read_text(encoding="utf-8", errors="ignore")
                if not content.strip():
                    continue
                lines    = content.split("\n")
                max_line = max((len(l) for l in lines), default=0)
                if len(lines) < 10 and max_line > 500:
                    continue
                if max_line > 2000:
                    continue
                files.append(CodeFile(
                    path=str(path.relative_to(root_path)),
                    language=lang,
                    content=content,
                ))
            except Exception:
                continue
        return files

    def _is_github_url(self, url: str) -> bool:
        return "github.com" in url or "gitlab.com" in url

    def load_dir(self, dir_path: str) -> List[CodeFile]:
        """ローカルディレクトリを直接読み込む"""
        files = []
        for p in Path(dir_path).rglob("*"):
            if not p.is_file():
                continue
            if any(ex in p.parts for ex in EXCLUDE_DIRS):
                continue
            ext = p.suffix.lower()
            if ext not in CODE_EXTENSIONS:
                continue
            try:
                content = p.read_text(encoding="utf-8", errors="ignore")
                files.append(CodeFile(str(p), CODE_EXTENSIONS[ext], content))
            except Exception:
                continue
        print(f"[+] {len(files)}ファイル読み込み: {dir_path}")
        return files

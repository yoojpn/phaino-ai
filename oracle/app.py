"""
phaino_ai - Oracle Free Tier Web Server
FastAPI + SQLiteジョブキュー + RunPod管理デーモン

起動:
  uvicorn oracle.app:app --host 0.0.0.0 --port 8080
"""

import asyncio
import logging
import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from oracle.db import JobDB
from oracle.runpod_manager import RunPodManager
from oracle.worker import ScanWorker

# ===========================
# ロギング
# ===========================
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("oracle.app")

# ===========================
# 定数
# ===========================
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "/tmp/vulnscan_uploads"))
REPORT_DIR = Path(os.getenv("REPORT_DIR", "/tmp/vulnscan_reports"))
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "200"))


# ===========================
# Lifespan（起動・停止）
# ===========================
@asynccontextmanager
async def lifespan(app: FastAPI):
    # 起動時
    db = JobDB()
    db.init()

    manager = RunPodManager()
    worker = ScanWorker(db=db, manager=manager, report_dir=REPORT_DIR)

    # バックグラウンドワーカー起動
    task = asyncio.create_task(worker.run_forever())

    app.state.db = db
    app.state.manager = manager
    app.state.worker = worker

    logger.info("Oracle Web Server 起動完了")

    yield

    # 停止時
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass

    logger.info("Oracle Web Server 停止")


# ===========================
# FastAPI アプリ
# ===========================
import base64
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class BasicAuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, username: str, password: str):
        super().__init__(app)
        self.credentials = base64.b64encode(f"{username}:{password}".encode()).decode()

    async def dispatch(self, request, call_next):
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Basic ") and auth[6:] == self.credentials:
            return await call_next(request)
        return Response(
            content="Unauthorized",
            status_code=401,
            headers={"WWW-Authenticate": "Basic realm=\"phaino-ai\""}
        )

app = FastAPI(
    title="phaino_ai",
    description="脆弱性検出特化AIパイプライン",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://phaino-ai.com", "https://phaino-ai.pages.dev"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 静的ファイル・テンプレート
_here = Path(__file__).parent
app.mount("/static", StaticFiles(directory=str(_here / "static")), name="static")
templates = Jinja2Templates(directory=str(_here / "templates"))


# ===========================
# ページ
# ===========================
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    db: JobDB = request.app.state.db
    jobs = db.list_jobs(limit=20)
    return templates.TemplateResponse(
        "index.html", {"request": request, "jobs": jobs}
    )


@app.get("/job/{job_id}", response_class=HTMLResponse)
async def job_detail(request: Request, job_id: str):
    db: JobDB = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return templates.TemplateResponse(
        "job.html", {"request": request, "job": job}
    )


# ===========================
# API エンドポイント
# ===========================

@app.post("/api/scan/multi")
async def scan_multi(
    request: Request,
    repo_urls: str = Form(""),          # 改行区切りのGitHub URL群
    site_urls: str = Form(""),          # 改行区切りのWeb URL群
    files: List[UploadFile] = File([]), # 複数ZIP
    min_exploitability: str = Form("practical"),
    no_docker: bool = Form(False),
    max_functions: int = Form(5000),
    no_react: bool = Form(False),
):
    """複数ターゲット（リポ/ZIP/Web）を1ジョブでスキャン"""
    targets = []

    for url in [u.strip() for u in repo_urls.splitlines() if u.strip()]:
        if not url.startswith("https://github.com/"):
            raise HTTPException(status_code=400, detail=f"GitHub URLが不正: {url}")
        targets.append({"type": "github", "value": url, "display": url})

    for url in [u.strip() for u in site_urls.splitlines() if u.strip()]:
        if not url.startswith(("http://", "https://")):
            raise HTTPException(status_code=400, detail=f"Web URLが不正: {url}")
        targets.append({"type": "web", "value": url, "display": url})

    for file in files:
        if not file.filename.endswith(".zip"):
            raise HTTPException(status_code=400, detail=f".zipのみ対応: {file.filename}")
        content = await file.read()
        if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail=f"{file.filename}が{MAX_UPLOAD_MB}MB超")
        save_path = UPLOAD_DIR / f"{uuid.uuid4()}.zip"
        save_path.write_bytes(content)
        targets.append({"type": "zip", "value": str(save_path), "display": file.filename})

    if not targets:
        raise HTTPException(status_code=400, detail="ターゲットを1つ以上指定してください")

    display = ", ".join(t["display"] for t in targets)
    db: JobDB = request.app.state.db
    job_id = _create_job(
        db=db,
        target=__import__("json").dumps(targets),
        target_type="multi",
        target_display=display,
        min_exploitability=min_exploitability,
        no_docker=no_docker,
        max_functions=max_functions,
        no_react=no_react,
    )
    return JSONResponse({"job_id": job_id, "status": "queued", "targets": len(targets)})

# ===========================

@app.post("/api/scan/github")
async def scan_github(
    request: Request,
    repo_url: str = Form(...),
    min_exploitability: str = Form("practical"),
    no_docker: bool = Form(False),
    max_functions: int = Form(5000),
    no_react: bool = Form(False),
):
    """GitHubリポジトリURLでスキャン"""
    if not repo_url.startswith("https://github.com/"):
        raise HTTPException(status_code=400, detail="GitHub URLを入力してください")

    db: JobDB = request.app.state.db
    job_id = _create_job(
        db=db,
        target=repo_url,
        target_type="github",
        min_exploitability=min_exploitability,
        no_docker=no_docker,
        max_functions=max_functions,
        no_react=no_react,
    )
    return JSONResponse({"job_id": job_id, "status": "queued"})


@app.post("/api/scan/zip")
async def scan_zip(
    request: Request,
    file: UploadFile = File(...),
    min_exploitability: str = Form("practical"),
    no_docker: bool = Form(False),
    max_functions: int = Form(5000),
    no_react: bool = Form(False),
):
    """ZIPファイルでスキャン"""
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail=".zipファイルをアップロードしてください")

    # サイズチェック
    content = await file.read()
    if len(content) > MAX_UPLOAD_MB * 1024 * 1024:
        raise HTTPException(status_code=413, detail=f"ファイルサイズは{MAX_UPLOAD_MB}MB以内にしてください")

    # 保存
    save_path = UPLOAD_DIR / f"{uuid.uuid4()}.zip"
    save_path.write_bytes(content)

    db: JobDB = request.app.state.db
    job_id = _create_job(
        db=db,
        target=str(save_path),
        target_type="zip",
        target_display=file.filename,
        min_exploitability=min_exploitability,
        no_docker=no_docker,
        max_functions=max_functions,
        no_react=no_react,
    )
    return JSONResponse({"job_id": job_id, "status": "queued"})


@app.post("/api/scan/web")
async def scan_web(
    request: Request,
    site_url: str = Form(...),
    min_exploitability: str = Form("practical"),
    no_docker: bool = Form(False),
    max_functions: int = Form(5000),
    no_react: bool = Form(False),
):
    """WebサイトURLでスキャン（JS/HTML/APIクロール）"""
    if not site_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="URLはhttp://またはhttps://で始めてください")

    db: JobDB = request.app.state.db
    job_id = _create_job(
        db=db,
        target=site_url,
        target_type="web",
        min_exploitability=min_exploitability,
        no_docker=no_docker,
        max_functions=max_functions,
        no_react=no_react,
    )
    return JSONResponse({"job_id": job_id, "status": "queued"})


@app.get("/api/jobs")
async def api_list_jobs(request: Request):
    db: JobDB = request.app.state.db
    jobs = db.list_jobs(limit=50)
    return JSONResponse(jobs)

@app.get("/api/job/{job_id}")
async def api_job_status(request: Request, job_id: str):
    """ジョブステータス取得（ポーリング用）"""
    db: JobDB = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return JSONResponse(job)


@app.get("/api/job/{job_id}/log")
async def api_job_log(request: Request, job_id: str, offset: int = 0):
    """ジョブログ（差分取得）"""
    db: JobDB = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")

    log = job.get("log", "") or ""
    return JSONResponse({
        "log": log[offset:],
        "offset": len(log),
        "status": job["status"],
    })


@app.get("/api/job/{job_id}/report")
async def api_download_report(request: Request, job_id: str):
    """レポートダウンロード"""
    db: JobDB = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] != "done":
        raise HTTPException(status_code=400, detail="スキャン完了後にダウンロードできます")

    report_path = job.get("report_path")
    if not report_path or not Path(report_path).exists():
        raise HTTPException(status_code=404, detail="レポートファイルが見つかりません")

    return FileResponse(
        path=report_path,
        filename=Path(report_path).name,
        media_type="text/markdown",
    )


@app.get("/api/job/{job_id}/report/uncertain")
async def api_download_uncertain_report(request: Request, job_id: str):
    """曖昧検出レポートダウンロード（confidence 40-64）"""
    db: JobDB = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] != "done":
        raise HTTPException(status_code=400, detail="スキャン完了後にダウンロードできます")

    report_path = job.get("report_path")
    if not report_path:
        raise HTTPException(status_code=404, detail="レポートが見つかりません")

    # メインレポートのパスから uncertain パスを生成
    main_path = Path(report_path)
    stem = main_path.stem
    uncertain_path = main_path.parent / f"{stem}_uncertain.md"

    if not uncertain_path.exists():
        raise HTTPException(status_code=404, detail="曖昧レポートが存在しません（曖昧な検出がありませんでした）")

    return FileResponse(
        path=str(uncertain_path),
        filename=uncertain_path.name,
        media_type="text/markdown",
    )


@app.get("/api/runpod/status")
async def api_runpod_status(request: Request):
    """RunPodの現在状態"""
    manager: RunPodManager = request.app.state.manager
    status = await manager.get_status()
    return JSONResponse(status)


@app.post("/api/job/{job_id}/cancel")
async def api_cancel_job(request: Request, job_id: str):
    """ジョブキャンセル"""
    db: JobDB = request.app.state.db
    job = db.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    if job["status"] not in ("queued", "running"):
        raise HTTPException(status_code=400, detail="キャンセルできない状態です")

    db.update_job(job_id, status="cancelled")
    return JSONResponse({"status": "cancelled"})


@app.delete("/api/jobs/old")
async def api_cleanup_old_jobs(request: Request, days: int = 7):
    """古いジョブのクリーンアップ"""
    db: JobDB = request.app.state.db
    count = db.cleanup_old_jobs(days=days)
    return JSONResponse({"deleted": count})


# ===========================
# ヘルパー
# ===========================
def _create_job(
    db: JobDB,
    target: str,
    target_type: str,
    min_exploitability: str = "practical",
    no_docker: bool = False,
    max_functions: int = 5000,
    no_react: bool = False,
    target_display: Optional[str] = None,
) -> str:
    job_id = str(uuid.uuid4())
    db.create_job(
        job_id=job_id,
        target=target,
        target_type=target_type,
        target_display=target_display or target,
        options={
            "min_exploitability": min_exploitability,
            "no_docker": no_docker,
            "max_functions": max_functions,
            "no_react": no_react,
        },
    )
    logger.info(f"Job created: {job_id} | {target_type} | {target_display or target}")
    return job_id

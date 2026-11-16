"""FastAPI web application for the secure file encryption and management system (ICS0027)."""
import os
import secrets
import sys
import asyncio
import time
from threading import Lock
from contextlib import asynccontextmanager

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from cryptography.exceptions import InvalidTag
from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession
from starlette.formparsers import MultiPartParser
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool

from core import accounts, files, storage
from core.db import FileRecord, SessionLocal, get_db, init_db, reset_sessions
from core.security import audit, audit_source, secure_wipe
from src.web import sessions

COOKIE_NAME = "session_id"
BASE_DIR = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

MAX_FORM_SIZE = 64 * 1024
MAX_UPLOAD_REQUEST = storage.MAX_FILE_SIZE + MAX_FORM_SIZE
# Starlette otherwise spools uploads larger than 1 MiB to disk in plaintext.
MultiPartParser.spool_max_size = MAX_UPLOAD_REQUEST


class RequestSizeLimit:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return
        limit = MAX_UPLOAD_REQUEST if scope["path"] == "/files/upload" else MAX_FORM_SIZE
        lengths = [value for name, value in scope["headers"] if name.lower() == b"content-length"]
        if lengths:
            if len(lengths) != 1 or not lengths[0].isdigit():
                await Response("Invalid request.", status_code=400)(scope, receive, send)
                return
            if int(lengths[0]) > limit:
                audit("request_error", "denied")
                await Response("Request too large.", status_code=413)(scope, receive, send)
                return
        size = 0

        async def limited_receive():
            nonlocal size
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > limit:
                    audit("request_error", "denied")
                    raise StarletteHTTPException(status_code=413)
            return message

        await self.app(scope, limited_receive, send)


@asynccontextmanager
async def lifespan(app):
    init_db()
    reset_sessions()
    sessions.clear_cached_keys()
    task = asyncio.create_task(_expire_sessions())
    try:
        yield
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        sessions.clear_cached_keys()


# The generated API documentation would disclose every route and needs scripts the CSP forbids.
app = FastAPI(title="Secure File Manager", lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(RequestSizeLimit)
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

_preauth: dict[str, tuple[str, float]] = {}
_attempts: dict[str, list[float]] = {}
_lock = Lock()


async def _expire_sessions() -> None:
    while True:
        await asyncio.sleep(60)
        with SessionLocal() as db:
            sessions.purge_expired(db)


@app.exception_handler(RequestValidationError)
async def invalid_request(request: Request, exc: RequestValidationError):
    audit("request_error", "failure")
    return Response("Invalid request.", status_code=400)


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    audit("request_error", "failure")
    return Response("Invalid request.", status_code=exc.status_code, headers=exc.headers)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    with audit_source(request.client.host if request.client else None):
        try:
            response = await call_next(request)
        except Exception:
            audit("request_error", "failure")
            response = Response("The request could not be completed.", status_code=500)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'none'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Strict-Transport-Security"] = "max-age=31536000"
    response.headers["Cache-Control"] = "no-store"
    return response


def _current_session(request: Request, db: DbSession):
    token = request.cookies.get(COOKIE_NAME)
    return sessions.get_session(db, token) if token else None


def _csrf_ok(web_session, token: str) -> bool:
    valid = secrets.compare_digest(token.encode(), web_session.csrf_token.encode())
    if not valid:
        audit("csrf", "denied", web_session.user_id)
    return valid


def _auth_form(request: Request, template: str, error: str | None = None, status_code: int = 200):
    now = time.monotonic()
    cookie = secrets.token_urlsafe(32)
    token = secrets.token_urlsafe(32)
    with _lock:
        for key, (_, expiry) in list(_preauth.items()):
            if expiry <= now:
                del _preauth[key]
        if len(_preauth) >= 10000:
            return Response("Please try again later.", status_code=503)
        _preauth[cookie] = (token, now + 600)
    response = templates.TemplateResponse(
        request=request, name=template, context={"error": error, "csrf_token": token}, status_code=status_code
    )
    response.set_cookie("preauth", cookie, max_age=600, httponly=True, secure=True, samesite="strict")
    return response


def _preauth_ok(request: Request, token: str) -> bool:
    cookie = request.cookies.get("preauth", "")
    with _lock:
        value = _preauth.pop(cookie, None)
    valid = value is not None and value[1] > time.monotonic() and secrets.compare_digest(
        value[0].encode(), token.encode()
    )
    if not valid:
        audit("csrf", "denied")
    return valid


def _allow_auth(request: Request) -> bool:
    now = time.monotonic()
    address = request.client.host if request.client else "unknown"
    with _lock:
        for key, times in list(_attempts.items()):
            _attempts[key] = [t for t in times if now - t < 300]
            if not _attempts[key]:
                del _attempts[key]
        if len(_attempts) >= 10000 and address not in _attempts:
            return False
        times = _attempts.setdefault(address, [])
        if len(times) >= 10:
            return False
        times.append(now)
        return True


def _login_redirect() -> RedirectResponse:
    return RedirectResponse("/auth/login", status_code=303)


def _set_session_cookie(response: Response, token: str) -> None:
    # No max_age: a browser-session cookie; server-side idle/absolute timeouts are authoritative.
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=True, samesite="strict")


def _user_files(db: DbSession, user_id: int):
    audit("file_list", "success", user_id)
    return db.query(FileRecord).filter(FileRecord.user_id == user_id).order_by(FileRecord.id.desc()).all()


def _dashboard(request: Request, db: DbSession, web_session, error: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(
        request=request, name="dashboard.html",
        context={
            "request": request,
            "files": _user_files(db, web_session.user_id),
            "csrf_token": web_session.csrf_token,
            "error": error,
        },
        status_code=status_code,
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return _login_redirect()
    return _dashboard(request, db, web_session)


@app.get("/auth/register", response_class=HTMLResponse)
def register_form(request: Request):
    return _auth_form(request, "register.html")


@app.post("/auth/register", response_class=HTMLResponse)
def register_submit(
    request: Request,
    csrf_token: str = Form(""),
    username: str = Form(..., max_length=64),
    password: str = Form(..., max_length=accounts.MAX_PASSWORD_LEN),
    confirm_password: str = Form(..., max_length=accounts.MAX_PASSWORD_LEN),
    db: DbSession = Depends(get_db),
):
    if not _preauth_ok(request, csrf_token):
        return Response("Invalid request.", status_code=403)
    if not _allow_auth(request):
        audit("registration", "denied")
        return Response("Please try again later.", status_code=429)
    if password != confirm_password:
        return _auth_form(request, "register.html", "Passwords do not match.", 400)
    try:
        accounts.register_user(db, username, password)
    except (ValueError, accounts.UsernameTakenError) as exc:
        return _auth_form(request, "register.html", str(exc), 400)
    response = _login_redirect()
    response.delete_cookie("preauth", secure=True, httponly=True, samesite="strict")
    return response


@app.get("/auth/login", response_class=HTMLResponse)
def login_form(request: Request):
    return _auth_form(request, "login.html")


@app.post("/auth/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    csrf_token: str = Form(""),
    username: str = Form(..., max_length=64),
    password: str = Form(..., max_length=accounts.MAX_PASSWORD_LEN),
    db: DbSession = Depends(get_db),
):
    if not _preauth_ok(request, csrf_token):
        return Response("Invalid request.", status_code=403)
    if not _allow_auth(request):
        audit("authentication", "denied")
        return Response("Please try again later.", status_code=429)
    try:
        user, master_key = accounts.authenticate_and_unlock(db, username, password)
    except accounts.AuthenticationError as exc:
        return _auth_form(request, "login.html", str(exc), 401)

    # Regenerate the session on every successful login to prevent session fixation.
    old_token = request.cookies.get(COOKIE_NAME)
    try:
        if old_token:
            sessions.destroy_session(db, old_token)
        token, _csrf = sessions.create_session(db, user.id, master_key)
    finally:
        secure_wipe(master_key)

    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, token)
    response.delete_cookie("preauth", secure=True, httponly=True, samesite="strict")
    return response


@app.post("/auth/logout")
def logout(request: Request, csrf_token: str = Form(""), db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return _login_redirect()
    if not _csrf_ok(web_session, csrf_token):
        return Response("Invalid CSRF token.", status_code=403)
    sessions.destroy_session(db, web_session.session_token)
    response = _login_redirect()
    response.delete_cookie(COOKIE_NAME, httponly=True, secure=True, samesite="strict")
    return response


@app.get("/files")
def files_index():
    return RedirectResponse("/", status_code=303)


@app.get("/files/upload", response_class=HTMLResponse)
def upload_form(request: Request, db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return _login_redirect()
    return templates.TemplateResponse(
        request=request, name="upload.html", context={"csrf_token": web_session.csrf_token, "error": None}
    )


@app.post("/files/upload")
async def upload_file(
    request: Request,
    csrf_token: str = Form(""),
    file: UploadFile = File(...),
    db: DbSession = Depends(get_db),
):
    web_session = _current_session(request, db)
    if web_session is None:
        return _login_redirect()
    if not _csrf_ok(web_session, csrf_token):
        return Response("Invalid CSRF token.", status_code=403)

    def _error(message: str, status_code: int):
        return templates.TemplateResponse(
            request=request, name="upload.html",
            context={"csrf_token": web_session.csrf_token, "error": message},
            status_code=status_code,
        )

    master_key = sessions.get_master_key(web_session.session_token)
    if master_key is None:
        sessions.destroy_session(db, web_session.session_token)
        return _login_redirect()

    try:
        try:
            display_name = storage.sanitize_upload_name(file.filename)
            storage.validate_upload_type(display_name)
        except storage.InvalidFileNameError:
            audit("file_encrypt", "denied", web_session.user_id)
            return _error("Invalid file name or unsupported file type.", 400)
        try:
            await run_in_threadpool(files.store_file_stream, db, web_session.user_id, master_key, display_name, file.file)
        except storage.FileTooLargeError as exc:
            audit("file_encrypt", "denied", web_session.user_id)
            return _error(str(exc), 413)
    finally:
        secure_wipe(master_key)
        await file.close()
    return RedirectResponse("/", status_code=303)


def _owned_record(db: DbSession, web_session, file_id: int):
    return (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.user_id == web_session.user_id)
        .first()
    )


@app.get("/files/download/{file_id}")
def download_file(request: Request, file_id: int, db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return _login_redirect()

    record = _owned_record(db, web_session, file_id)
    if record is None:
        audit("file_decrypt", "denied", web_session.user_id)
        return Response("Not found.", status_code=404)

    master_key = sessions.get_master_key(web_session.session_token)
    if master_key is None:
        sessions.destroy_session(db, web_session.session_token)
        return _login_redirect()

    try:
        try:
            plaintext = bytearray(files.read_file(db, web_session.user_id, file_id, master_key))
        except (FileNotFoundError, InvalidTag):
            audit("file_decrypt", "failure", web_session.user_id)
            return Response("The request could not be completed.", status_code=500)
    finally:
        secure_wipe(master_key)

    def _stream():
        try:
            for offset in range(0, len(plaintext), 1024 * 1024):
                yield bytes(memoryview(plaintext)[offset:offset + 1024 * 1024])
        finally:
            secure_wipe(plaintext)

    # original_name is restricted to [A-Za-z0-9._ -] at upload time, so it is header-safe.
    headers = {"Content-Disposition": f'attachment; filename="{record.original_name}"'}
    return StreamingResponse(_stream(), media_type="application/octet-stream", headers=headers,
                             background=BackgroundTask(secure_wipe, plaintext))


@app.post("/files/delete/{file_id}")
def delete_file(request: Request, file_id: int, csrf_token: str = Form(""), db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return _login_redirect()
    if not _csrf_ok(web_session, csrf_token):
        return Response("Invalid CSRF token.", status_code=403)

    record = _owned_record(db, web_session, file_id)
    if record is None:
        audit("file_delete", "denied", web_session.user_id)
        return Response("Not found.", status_code=404)
    files.remove_file(db, web_session.user_id, file_id)
    return RedirectResponse("/", status_code=303)

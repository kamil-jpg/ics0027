"""FastAPI web application for the secure file encryption and management system (ICS0027)."""
import os
import secrets
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from cryptography.exceptions import InvalidTag
from fastapi import Depends, FastAPI, File, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from core import accounts, files, storage
from core.db import FileRecord, get_db, init_db, reset_sessions
from src.web import sessions

COOKIE_NAME = "session_id"
BASE_DIR = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

app = FastAPI(title="Secure File Manager")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    reset_sessions()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; frame-ancestors 'none'; form-action 'self'"
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
    return secrets.compare_digest(token.encode(), web_session.csrf_token.encode())


def _login_redirect() -> RedirectResponse:
    return RedirectResponse("/auth/login", status_code=303)


def _set_session_cookie(response: Response, token: str) -> None:
    # No max_age: a browser-session cookie; server-side idle/absolute timeouts are authoritative.
    response.set_cookie(COOKIE_NAME, token, httponly=True, secure=True, samesite="strict")


def _user_files(db: DbSession, user_id: int):
    return db.query(FileRecord).filter(FileRecord.user_id == user_id).order_by(FileRecord.id.desc()).all()


def _dashboard(request: Request, db: DbSession, web_session, error: str | None = None, status_code: int = 200):
    return templates.TemplateResponse(
        "dashboard.html",
        {
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
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@app.post("/auth/register", response_class=HTMLResponse)
def register_submit(
    request: Request,
    username: str = Form(..., max_length=64),
    password: str = Form(..., max_length=accounts.MAX_PASSWORD_LEN),
    confirm_password: str = Form(..., max_length=accounts.MAX_PASSWORD_LEN),
    db: DbSession = Depends(get_db),
):
    if password != confirm_password:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": "Passwords do not match."}, status_code=400
        )
    try:
        accounts.register_user(db, username, password)
    except (ValueError, accounts.UsernameTakenError) as exc:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": str(exc)}, status_code=400
        )
    return _login_redirect()


@app.get("/auth/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/auth/login", response_class=HTMLResponse)
def login_submit(
    request: Request,
    username: str = Form(..., max_length=64),
    password: str = Form(..., max_length=accounts.MAX_PASSWORD_LEN),
    db: DbSession = Depends(get_db),
):
    try:
        user, master_key = accounts.authenticate_and_unlock(db, username, password)
    except accounts.AuthenticationError as exc:
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": str(exc)}, status_code=401
        )

    # Regenerate the session on every successful login to prevent session fixation.
    old_token = request.cookies.get(COOKIE_NAME)
    if old_token:
        sessions.destroy_session(db, old_token)
    token, _csrf = sessions.create_session(db, user.id, master_key)

    response = RedirectResponse("/", status_code=303)
    _set_session_cookie(response, token)
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
        "upload.html", {"request": request, "csrf_token": web_session.csrf_token, "error": None}
    )


@app.post("/files/upload")
async def upload_file(
    request: Request,
    csrf_token: str = Form(...),
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
            "upload.html",
            {"request": request, "csrf_token": web_session.csrf_token, "error": message},
            status_code=status_code,
        )

    master_key = sessions.get_master_key(web_session.session_token)
    if master_key is None:
        sessions.destroy_session(db, web_session.session_token)
        return _login_redirect()

    try:
        display_name = storage.sanitize_upload_name(file.filename)
    except storage.InvalidFileNameError:
        return _error("Invalid file name.", 400)

    plaintext = await file.read(storage.MAX_FILE_SIZE + 1)
    try:
        files.store_file(db, web_session.user_id, master_key, display_name, plaintext)
    except storage.FileTooLargeError as exc:
        return _error(str(exc), 413)
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
        return Response("Not found.", status_code=404)

    master_key = sessions.get_master_key(web_session.session_token)
    if master_key is None:
        sessions.destroy_session(db, web_session.session_token)
        return _login_redirect()

    try:
        plaintext = files.read_file(record, master_key)
    except FileNotFoundError:
        return Response("Encrypted data is missing.", status_code=404)
    except InvalidTag:
        return Response("Decryption failed: data is corrupted or tampered with.", status_code=500)

    def _stream():
        yield plaintext

    # original_name is restricted to [A-Za-z0-9._ -] at upload time, so it is header-safe.
    headers = {"Content-Disposition": f'attachment; filename="{record.original_name}"'}
    return StreamingResponse(_stream(), media_type="application/octet-stream", headers=headers)


@app.post("/files/delete/{file_id}")
def delete_file(request: Request, file_id: int, csrf_token: str = Form(...), db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return _login_redirect()
    if not _csrf_ok(web_session, csrf_token):
        return Response("Invalid CSRF token.", status_code=403)

    record = _owned_record(db, web_session, file_id)
    if record is not None:
        files.remove_file(db, record)
    return RedirectResponse("/", status_code=303)

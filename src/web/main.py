"""FastAPI web application for the secure file encryption and management system (ICS0027)."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from fastapi import Depends, FastAPI, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DbSession

from core import accounts, crypto, storage
from core.db import FileRecord, get_db, init_db
from src.web import sessions

BASE_DIR = os.path.dirname(__file__)
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))

app = FastAPI(title="Secure File Manager")
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")


@app.on_event("startup")
def on_startup() -> None:
    init_db()


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


def _current_session(request: Request, db: DbSession):
    token = request.cookies.get("session_id")
    return sessions.get_session(db, token) if token else None


def require_login(request: Request, db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return None
    return web_session


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        "session_id", token, httponly=True, secure=True, samesite="strict", max_age=1800
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request, db: DbSession = Depends(get_db)):
    if _current_session(request, db) is not None:
        return RedirectResponse("/files", status_code=303)
    return RedirectResponse("/auth/login", status_code=303)


@app.get("/auth/register", response_class=HTMLResponse)
def register_form(request: Request):
    return templates.TemplateResponse("register.html", {"request": request, "error": None})


@app.post("/auth/register", response_class=HTMLResponse)
def register_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    confirm_password: str = Form(...),
    db: DbSession = Depends(get_db),
):
    if password != confirm_password:
        return templates.TemplateResponse(
            "register.html", {"request": request, "error": "Passwords do not match."}
        )
    try:
        accounts.register_user(db, username, password)
    except (ValueError, accounts.UsernameTakenError) as exc:
        return templates.TemplateResponse("register.html", {"request": request, "error": str(exc)})
    return RedirectResponse("/auth/login", status_code=303)


@app.get("/auth/login", response_class=HTMLResponse)
def login_form(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@app.post("/auth/login", response_class=HTMLResponse)
def login_submit(
    request: Request, username: str = Form(...), password: str = Form(...), db: DbSession = Depends(get_db)
):
    try:
        user, master_key = accounts.authenticate_and_unlock(db, username, password)
    except accounts.AuthenticationError as exc:
        return templates.TemplateResponse("login.html", {"request": request, "error": str(exc)})

    # Regenerate the session on every successful login to prevent session fixation.
    old_token = request.cookies.get("session_id")
    if old_token:
        sessions.destroy_session(db, old_token)
    token, _csrf = sessions.create_session(db, user.id, master_key)

    response = RedirectResponse("/files", status_code=303)
    _set_session_cookie(response, token)
    return response


@app.post("/auth/logout")
def logout(request: Request, db: DbSession = Depends(get_db)):
    token = request.cookies.get("session_id")
    if token:
        sessions.destroy_session(db, token)
    response = RedirectResponse("/auth/login", status_code=303)
    response.delete_cookie("session_id")
    return response


@app.get("/files", response_class=HTMLResponse)
def list_files(request: Request, db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return RedirectResponse("/auth/login", status_code=303)
    records = (
        db.query(FileRecord)
        .filter(FileRecord.user_id == web_session.user_id)
        .order_by(FileRecord.id.desc())
        .all()
    )
    return templates.TemplateResponse(
        "dashboard.html",
        {"request": request, "files": records, "csrf_token": web_session.csrf_token, "error": None},
    )


@app.post("/files/upload")
async def upload_file(
    request: Request,
    csrf_token: str = Form(...),
    file: UploadFile = None,
    db: DbSession = Depends(get_db),
):
    web_session = _current_session(request, db)
    if web_session is None:
        return RedirectResponse("/auth/login", status_code=303)
    if csrf_token != web_session.csrf_token:
        return Response("Invalid CSRF token.", status_code=403)

    master_key = sessions.get_master_key(web_session.session_token)
    if master_key is None or file is None:
        return RedirectResponse("/files", status_code=303)

    try:
        display_name = storage.sanitize_display_name(file.filename)
    except storage.InvalidFileNameError:
        records = db.query(FileRecord).filter(FileRecord.user_id == web_session.user_id).all()
        return templates.TemplateResponse(
            "dashboard.html",
            {
                "request": request,
                "files": records,
                "csrf_token": web_session.csrf_token,
                "error": "Invalid file name.",
            },
            status_code=400,
        )

    plaintext = await file.read()
    nonce, ciphertext = crypto.encrypt_bytes(master_key, plaintext)
    storage_name = storage.new_storage_name()
    storage.save_encrypted(storage_name, ciphertext)

    record = FileRecord(
        user_id=web_session.user_id, storage_name=storage_name, original_name=display_name, nonce=nonce
    )
    db.add(record)
    db.commit()
    return RedirectResponse("/files", status_code=303)


@app.get("/files/download/{file_id}")
def download_file(request: Request, file_id: int, db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return RedirectResponse("/auth/login", status_code=303)

    record = (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.user_id == web_session.user_id)
        .first()
    )
    if record is None:
        return Response("Not found.", status_code=404)

    master_key = sessions.get_master_key(web_session.session_token)
    if master_key is None:
        return RedirectResponse("/auth/login", status_code=303)

    ciphertext = storage.load_encrypted(record.storage_name)
    plaintext = crypto.decrypt_bytes(master_key, record.nonce, ciphertext)

    def _stream():
        yield plaintext

    headers = {"Content-Disposition": f'attachment; filename="{record.original_name}"'}
    return StreamingResponse(_stream(), media_type="application/octet-stream", headers=headers)


@app.post("/files/delete/{file_id}")
def delete_file(request: Request, file_id: int, csrf_token: str = Form(...), db: DbSession = Depends(get_db)):
    web_session = _current_session(request, db)
    if web_session is None:
        return RedirectResponse("/auth/login", status_code=303)
    if csrf_token != web_session.csrf_token:
        return Response("Invalid CSRF token.", status_code=403)

    record = (
        db.query(FileRecord)
        .filter(FileRecord.id == file_id, FileRecord.user_id == web_session.user_id)
        .first()
    )
    if record is not None:
        storage.delete_encrypted(record.storage_name)
        db.delete(record)
        db.commit()
    return RedirectResponse("/files", status_code=303)

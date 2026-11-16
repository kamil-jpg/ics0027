# Usage Instructions

Secure File Manager: a CLI (`secfile`) and a web app sharing one encrypted per-user file store.

Run all commands from the repository root.

## 1. Setup (once)

Requirements: Python 3.11+ on Linux and `openssl` (or `mkcert`). Checkpoint verification used Python 3.12.16. Reinstall dependencies after updating this project because the runtime pins have changed.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Activate the venv in every new terminal.

## 2. CLI

Format: `python -m src.cli.main <command> [options]`. Use `--help` for help.

The program asks for your password. It does not show the password on screen. You cannot give it as an argument.

| Command | Purpose |
|---|---|
| `register -u USER` | Create an account (asks for the password twice) |
| `login -u USER` | Check your credentials |
| `encrypt -u USER -i FILE -o NAME` | Encrypt a local file and store it as `NAME` |
| `decrypt -u USER -i NAME -o PATH [-f]` | Decrypt stored file `NAME` to `PATH` |
| `list -u USER` | Show your stored files |
| `delete -u USER -i NAME [-y]` | Authenticate, overwrite and delete an owned stored file and its metadata |
| `wipe FILE [-y]` | Overwrite a local file with zeros, then delete it |

Notes:
- `encrypt -o` is a name in the store, not a path. Allowed characters: `A-Za-z0-9._ -`. No `/`.
- `decrypt -i` is the name shown by `list`.
- `decrypt` does not overwrite an existing file unless you use `-f`.
- `delete` and `wipe` ask for confirmation unless you use `-y`. `delete` requires the owning account's password; `wipe` uses OS permissions for a local file. Both overwrite before unlinking and are best-effort on SSDs, snapshots, backups and copy-on-write filesystems.
- File operations refuse symlinks, including symlinked parent directories, and `..` components. Overwriting and deletion also refuse hard links. Use an absolute path or a relative path without `..`.
- Input files must be regular files, up to 50 MiB.
- Username: 1-64 characters from `A-Za-z0-9._-`. Password: 8-128 characters.
- On error, the program prints `Error: ...` and exits with code 1.

Example:
```bash
echo "top secret" > notes.txt
python -m src.cli.main register -u alice
python -m src.cli.main encrypt -u alice -i notes.txt -o notes.enc
python -m src.cli.main wipe notes.txt -y
python -m src.cli.main list -u alice
python -m src.cli.main decrypt -u alice -i notes.enc -o notes.txt
```

## 3. Web app

### Start
```bash
./certs/generate_cert.sh        # once; creates certs/cert.pem and certs/key.pem
uvicorn src.web.main:app --host 127.0.0.1 --port 8000 \
  --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem --no-access-log --no-proxy-headers
```

Open **https://localhost:8000**. With the `openssl` certificate, the browser shows a warning. Accept it. Install `mkcert` to avoid the warning.

### Use
1. **Register**, then **log in**. You see the dashboard.
2. **Upload**: choose a file (max 50 MiB). Allowed extensions: TXT, MD, CSV, JSON, PDF, PNG, JPG, JPEG, ZIP and BIN. The server encrypts opaque bytes; it does not inspect contents for malware.
3. **Download**: the server decrypts the file and sends it to you.
4. **Delete**: overwrites the encrypted blob before removing it and its owned metadata. This cannot guarantee physical erasure from all storage copies.
5. **Log out**: ends the session.

### Sessions
- Idle timeout: 15 minutes. Maximum lifetime: 12 hours.
- A server restart logs everyone out.
- All POST forms, including login and registration, need a CSRF token. The forms include it automatically.
- Ten login/registration attempts per client address are allowed per five minutes, including successful attempts.
- Run one worker only: session keys, pre-login tokens and rate limits are process-local. Configure additional rate limiting and trusted IP handling at any proxy.
- Security events contain UTC time, operation, outcome, optional numeric user ID and validated source IP (`local` for CLI). They exclude passwords, tokens, keys, filenames and content. Do not enable request-body, cookie, credential, or URL/query-string logging in the server or proxy.

## 4. Data

| Item | Path | Change with |
|---|---|---|
| Database (users, keys, file metadata) | `data/secfile.db` | `SECFILE_DATA_DIR` |
| Encrypted files | `data/encrypted/` | `SECFILE_STORAGE_DIR` |

- The CLI and the web server must use the same paths to see the same files.
- Back up the whole `data/` folder. Without `secfile.db`, files cannot be decrypted.
- There is no password recovery.
- Python cannot guarantee that all copies of passwords, keys or plaintext are erased from process memory. Downloads and multipart uploads can hold plaintext in memory.
- To reset everything, stop the server and delete `data/`.

## 5. Tests and report

Install `requirements-dev.txt` and run `python -m pytest -v --junitxml=docs/checkpoint3-results.xml` and `python -m pip check`.
The tests use temporary storage; the HTTPS test uses a temporary certificate and requires `openssl`. The [checkpoint assessment](docs/CHECKPOINT_3.md) maps requirements to evidence and gives reproducible attack demonstrations. The report is written in the TalTech thesis template in `report/`; build it with `cd report && latexmk -pdf main.tex` (needs a LaTeX distribution with `biber`). The recorded result is 53 passing tests and one test-client deprecation warning.

## 6. Troubleshooting

| Problem | Fix |
|---|---|
| `No module named 'src'` | Run from the repository root with `python -m src.cli.main`. |
| `No module named 'fastapi'` (or similar) | Activate the venv. Run `pip install -r requirements.txt`. |
| `key.pem` not found | Run `./certs/generate_cert.sh`. |
| Logged out suddenly | 15 minutes idle, or the server restarted. |
| `Invalid output file or output already exists` | Use another path, or add `-f` for a regular file. |
| `a file named ... already exists` | Use another `-o` name. |
| Port in use | Use another `--port`. |

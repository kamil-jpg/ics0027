# Usage Instructions

Secure File Manager: a CLI (`secfile`) and a web app. Both use the same encrypted file store for each user.

Run all commands from the repository root.

## 1. Setup (once)

Requirements: Python 3.11+ and `openssl` (or `mkcert`).

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
| `wipe FILE [-y]` | Overwrite a local file with zeros, then delete it |

Notes:
- `encrypt -o` is a name in the store, not a path. Allowed characters: `A-Za-z0-9._ -`. No `/`.
- `decrypt -i` is the name shown by `list`.
- `decrypt` does not overwrite an existing file unless you use `-f`.
- `wipe` asks for confirmation unless you use `-y`. It refuses symlinks.
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
  --ssl-keyfile certs/key.pem --ssl-certfile certs/cert.pem
```

Open **https://localhost:8000**. With the `openssl` certificate, the browser shows a warning. Accept it. Install `mkcert` to avoid the warning.

### Use
1. **Register**, then **log in**. You see the dashboard.
2. **Upload**: choose a file (max 50 MiB). The server encrypts it.
3. **Download**: the server decrypts the file and sends it to you.
4. **Delete**: removes the file.
5. **Log out**: ends the session.

### Sessions
- Idle timeout: 15 minutes. Maximum lifetime: 12 hours.
- A server restart logs everyone out.
- Upload, delete and logout need a CSRF token. The forms include it automatically.

## 4. Data

| Item | Path | Change with |
|---|---|---|
| Database (users, keys, file metadata) | `data/secfile.db` | `SECFILE_DATA_DIR` |
| Encrypted files | `data/encrypted/` | `SECFILE_STORAGE_DIR` |

- The CLI and the web server must use the same paths to see the same files.
- Back up the whole `data/` folder. Without `secfile.db`, files cannot be decrypted.
- There is no password recovery.
- To reset everything, stop the server and delete `data/`.

## 5. Troubleshooting

| Problem | Fix |
|---|---|
| `No module named 'src'` | Run from the repository root with `python -m src.cli.main`. |
| `No module named 'fastapi'` (or similar) | Activate the venv. Run `pip install -r requirements.txt`. |
| `key.pem` not found | Run `./certs/generate_cert.sh`. |
| Logged out suddenly | 15 minutes idle, or the server restarted. |
| `Output file already exists` | Use another path, or add `-f`. |
| `a file named ... already exists` | Use another `-o` name. |
| Port in use | Use another `--port`. |

"""Command-line interface for the secure file manager (ICS0022).

Usage examples:
    python -m src.cli.main register -u alice
    python -m src.cli.main login -u alice
    python -m src.cli.main encrypt -u alice -i notes.txt -o notes.enc
    python -m src.cli.main decrypt -u alice -n notes.enc -o notes.out.txt
    python -m src.cli.main list -u alice
    python -m src.cli.main wipe path/to/file
"""
import argparse
import getpass
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from core import accounts, crypto, storage
from core.db import FileRecord, SessionLocal, init_db
from core.security import secure_wipe


def _prompt_password(confirm: bool = False) -> str:
    password = getpass.getpass("Password: ")
    if confirm:
        again = getpass.getpass("Confirm password: ")
        if password != again:
            print("Error: passwords do not match.", file=sys.stderr)
            sys.exit(1)
    return password


def _unlock(db, username: str) -> tuple:
    password = _prompt_password()
    try:
        user, master_key = accounts.authenticate_and_unlock(db, username, password)
    except accounts.AuthenticationError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        password = None
    return user, master_key


def cmd_register(args) -> None:
    db = SessionLocal()
    try:
        password = _prompt_password(confirm=True)
        try:
            accounts.register_user(db, args.username, password)
        except (ValueError, accounts.UsernameTakenError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            sys.exit(1)
        print(f"User '{args.username}' registered successfully.")
    finally:
        db.close()


def cmd_login(args) -> None:
    db = SessionLocal()
    try:
        _unlock(db, args.username)
        print("Login successful.")
    finally:
        db.close()


def cmd_encrypt(args) -> None:
    if not os.path.isfile(args.input):
        print(f"Error: input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    try:
        display_name = storage.sanitize_display_name(args.output)
    except storage.InvalidFileNameError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    db = SessionLocal()
    master_key_buf = None
    try:
        user, master_key = _unlock(db, args.username)
        master_key_buf = bytearray(master_key)

        if db.query(FileRecord).filter(
            FileRecord.user_id == user.id, FileRecord.original_name == display_name
        ).first():
            print(f"Error: a file named '{display_name}' already exists for this user.", file=sys.stderr)
            sys.exit(1)

        with open(args.input, "rb") as f:
            plaintext = f.read()

        nonce, ciphertext = crypto.encrypt_bytes(bytes(master_key_buf), plaintext)
        storage_name = storage.new_storage_name()
        storage.save_encrypted(storage_name, ciphertext)

        record = FileRecord(
            user_id=user.id, storage_name=storage_name, original_name=display_name, nonce=nonce
        )
        db.add(record)
        db.commit()
        print(f"Encrypted '{args.input}' -> stored as '{display_name}' (id={record.id}).")
    finally:
        if master_key_buf is not None:
            secure_wipe(master_key_buf)
        db.close()


def cmd_decrypt(args) -> None:
    out_dir = os.path.dirname(os.path.abspath(args.output)) or "."
    if not os.path.isdir(out_dir):
        print(f"Error: output directory does not exist: {out_dir}", file=sys.stderr)
        sys.exit(1)

    db = SessionLocal()
    master_key_buf = None
    try:
        user, master_key = _unlock(db, args.username)
        master_key_buf = bytearray(master_key)

        record = db.query(FileRecord).filter(
            FileRecord.user_id == user.id, FileRecord.original_name == args.name
        ).first()
        if record is None:
            print(f"Error: no file named '{args.name}' found for this user.", file=sys.stderr)
            sys.exit(1)

        ciphertext = storage.load_encrypted(record.storage_name)
        try:
            plaintext = crypto.decrypt_bytes(bytes(master_key_buf), record.nonce, ciphertext)
        except Exception:
            print("Error: decryption failed (wrong key or corrupted data).", file=sys.stderr)
            sys.exit(1)

        with open(args.output, "wb") as f:
            f.write(plaintext)
        print(f"Decrypted '{args.name}' -> '{args.output}'.")
    finally:
        if master_key_buf is not None:
            secure_wipe(master_key_buf)
        db.close()


def cmd_list(args) -> None:
    db = SessionLocal()
    try:
        user, master_key = _unlock(db, args.username)
        secure_wipe(bytearray(master_key))

        records = db.query(FileRecord).filter(FileRecord.user_id == user.id).order_by(FileRecord.id).all()
        if not records:
            print("No files stored.")
            return
        print(f"{'ID':<5} {'Name':<30} {'Created':<20}")
        for r in records:
            print(f"{r.id:<5} {r.original_name:<30} {r.created_at}")
    finally:
        db.close()


def cmd_wipe(args) -> None:
    path = args.path
    if not os.path.isfile(path):
        print(f"Error: file not found: {path}", file=sys.stderr)
        sys.exit(1)
    if not args.yes:
        confirm = input(f"Securely delete '{path}'? This cannot be undone. [y/N]: ")
        if confirm.strip().lower() != "y":
            print("Aborted.")
            return
    storage.secure_delete_path(path)
    print(f"Wiped '{path}'.")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="secfile", description="Secure file manager CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("register", help="Create a user account")
    p.add_argument("-u", "--username", required=True)
    p.set_defaults(func=cmd_register)

    p = sub.add_parser("login", help="Verify credentials")
    p.add_argument("-u", "--username", required=True)
    p.set_defaults(func=cmd_login)

    p = sub.add_parser("encrypt", help="Encrypt a file into the vault")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-i", "--input", required=True, help="Path to the plaintext file")
    p.add_argument("-o", "--output", required=True, help="Display name to store the file under")
    p.set_defaults(func=cmd_encrypt)

    p = sub.add_parser("decrypt", help="Decrypt a file from the vault")
    p.add_argument("-u", "--username", required=True)
    p.add_argument("-n", "--name", required=True, help="Stored display name of the file")
    p.add_argument("-o", "--output", required=True, help="Path to write the decrypted file to")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("list", help="List the user's encrypted files")
    p.add_argument("-u", "--username", required=True)
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("wipe", help="Securely delete a local file")
    p.add_argument("path")
    p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation prompt")
    p.set_defaults(func=cmd_wipe)

    return parser


def main(argv=None) -> None:
    init_db()
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

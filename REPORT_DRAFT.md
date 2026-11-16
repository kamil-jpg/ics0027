# Secure File Encryption and Management System

Checkpoint 3 draft report — 16 November 2026  
Tallinn University of Technology, School of Information Technologies  
ICS0027 Web Application Security and ICS0022 Secure Programming

## 1. Introduction

This project implements the **file-manager option** for both courses: a web application for uploading, downloading and deleting encrypted files, and a command-line tool for encrypting, decrypting, listing and deleting the same users' files. A shared Python core provides authentication, encryption, ownership checks and storage.

The objectives are to protect file contents at rest and in transit, prevent one account from accessing another account's files, validate untrusted input, and demonstrate the security controls through reproducible tests. These objectives connect web security controls such as CSRF prevention and output encoding with secure programming practices such as bounded memory use, safe filesystem operations and error handling.

The threat model includes unauthenticated visitors, authenticated users trying to access other users' files, malicious form fields and filenames, and modified encrypted blobs. The application process and its private storage directories are trusted. An attacker controlling the server, the operating-system account running the application, or an unlocked client device is outside that boundary. This is server-side encryption: the server sees plaintext during use.

The structure follows Section 1.3 of both supplied project descriptions: Introduction, Implementation, Security Analysis and Conclusion. The detailed checkpoint mapping and demonstration instructions are in [the checkpoint assessment](docs/CHECKPOINT_3.md).

## 2. Implementation

### 2.1 Architecture and interfaces

`core/` contains the shared account, cryptographic, database, file and storage services. `src/cli/main.py` provides the CLI; `src/web/main.py` provides FastAPI routes and Jinja templates. SQLite stores accounts, wrapped keys, file metadata and session records. Encrypted blobs live outside the static web directory, under random UUID names. The architecture and trust-boundary diagram are in the README.

The CLI prompts for account passwords without echo. Its `encrypt`, `decrypt`, `list` and `delete` commands authenticate the selected account. The separate `wipe` command overwrites a local file selected by the operating-system user; it does not identify a stored application file and is governed by OS permissions. The web interface uses server-side sessions and provides the same stored-file operations.

### 2.2 Authentication and encryption

Account passwords are hashed with salted Argon2id. A separate Argon2id derivation produces a 256-bit key-encryption key using a random 16-byte salt, three iterations, 64 MiB of memory and parallelism four. This key wraps a random 256-bit per-user master key. The database stores the wrapped key, salt and nonce, rather than an unwrapped master key.

File encryption uses AES-256-GCM with a fresh random 12-byte nonce. The random storage identifier is authenticated as additional data, binding each encrypted blob to its record. The blob consists of ciphertext followed by the 16-byte authentication tag; the nonce is stored in the database. Decryption verifies the tag before returning plaintext. Tampering, a wrong key or a different identifier causes decryption to fail.

Streaming encryption uses a reusable 1 MiB mutable buffer and enforces a 50 MiB plaintext limit while reading. Web multipart files remain in memory to avoid plaintext temporary files. Downloads authenticate the complete encrypted file before returning attachment bytes. The local HTTPS setup protects transport; a test starts a real Uvicorn TLS endpoint with a temporary certificate and verifies it using that certificate as its trust anchor.

### 2.3 Memory and filesystem handling

Mutable key buffers are overwritten after registration, authentication key derivation, CLI operations and web requests. Cached session keys are overwritten on logout, expiry, replacement and shutdown. Logout also clears the key if database deletion fails. Encryption buffers and the mutable download/decryption buffers are cleared on their tested success and error paths. Python and native libraries can retain immutable or internal copies; these operations provide best-effort clearing, not a guarantee of complete process-memory erasure.

Stored names accept only a conservative character set and never determine the blob path. Uploaded names are reduced to a safe basename. Web uploads allow TXT, MD, CSV, JSON, PDF, PNG, JPG, JPEG, ZIP and BIN extensions. This is an extension policy, not file-content or malware detection. Uploaded bytes are opaque: the application does not execute, extract or render them, and downloads use `application/octet-stream` and `Content-Disposition: attachment`.

Filesystem operations reject parent-traversal components and follow no symbolic links in the opened path. Directory descriptors pin the parent directories used for operations. Reads require regular files and enforce size limits. Outputs use owner-only permissions and refuse replacement without `--force`; overwriting and deletion reject hard-linked targets. Encrypted-file reads also reject symbolic links and invalid sizes.

Stored-file deletion and local wiping overwrite the opened regular file with zeroes, flush and sync it, verify its identity, then unlink it. Stored deletion also removes the owner-scoped database record. This is best-effort logical erasure; SSD remapping, copy-on-write filesystems, snapshots and backups can retain previous bytes. The master key remains usable for the account's other files, so deleting one blob is not cryptographic key destruction.

### 2.4 Web and database security

Every state-changing form requires a CSRF token. Login and registration use cookie-bound, single-use tokens with a ten-minute expiry. Authenticated forms use the token associated with the session. A missing, forged or other-session token cannot upload or delete a file or log the user out.

Jinja HTML autoescaping protects displayed names and form values. The Content Security Policy disables scripts, objects and base-URL changes, restricts form submissions, and prevents framing. Responses also include `nosniff`, `no-store`, HSTS and a no-referrer policy. File bytes are sent only as downloads. The framework's generated `/docs`, `/redoc` and `/openapi.json` endpoints are disabled so the route surface is not advertised.

Session cookies use `Secure`, `HttpOnly` and `SameSite=Strict`. Successful login replaces the old session. The idle timeout is 15 minutes and the absolute lifetime is 12 hours. Sessions without cached keys are invalidated. Authentication and registration are limited to ten attempts per transport address in five minutes, including successful attempts.

Usernames, stored filenames, form lengths, upload types, file sizes and local paths are validated on the server. Requests are limited to 64 KiB, except uploads, which permit 50 MiB plus 64 KiB of multipart overhead. No application file operation invokes a shell. SQLAlchemy generates parameterized SQL for account, session and file operations. The only direct SQL statement enables SQLite foreign keys and contains no user input.

Every stored-file list, read and delete filters by the authenticated user ID. New records receive that ID from the authenticated session or CLI account. The same owner check is enforced in the shared file service, so the browser is not the authorization boundary.

### 2.5 Error handling and audit events

Expected validation errors return fixed messages. Unexpected operation errors return a generic response or CLI error without exception text or stack traces. Security events are JSON objects containing `timestamp` in UTC, `event`, `outcome`, `user_id` and `source_address`. Known users have numeric IDs; unauthenticated or local-wipe events may use `null`. CLI events identify the source as `local`; web events use a validated transport IP address. Unrecognized address text becomes `unknown`.

Events distinguish encryption, decryption, deletion, listing, authentication, CSRF denial and session creation/destruction. The logger accepts fixed event and outcome names and numeric IDs. It does not accept filenames, credentials, cookies, tokens, key material, request bodies or exception strings. Tests capture emitted events, validate their schema, and check that sample secrets and tokens are absent.

## 3. Security Analysis

### 3.1 Verification method and results

The suite ran on **16 November 2026**, using Linux, Python **3.12.16**, pytest **9.2.0**, and the updated pinned dependencies. All **53 tests passed**, with no failures or skips. One warning concerns Starlette's future preference for `httpx2` over the currently supported `httpx` test client. `pip check` reported no broken requirements.

The tests use temporary accounts, databases, blob directories and TLS certificates. They do not modify the existing application data. The exact run output is in [checkpoint3-test-results.txt](docs/checkpoint3-test-results.txt), machine-readable results in [checkpoint3-results.xml](docs/checkpoint3-results.xml), and installed versions in [checkpoint3-environment.txt](docs/checkpoint3-environment.txt).

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -v --junitxml=docs/checkpoint3-results.xml
python -m pip check
```

The verification combined source inspection, HTTP requests against the application, direct shared-core and CLI calls, fault injection, filesystem observation, log inspection and a real local TLS connection. It is a checkpoint verification of the tested properties, not a proof that the application has no vulnerabilities.

### 3.2 Attack vectors and mitigations

| Attack or failure | Attempt and observed result | Mitigation |
|---|---|---|
| CSRF | Missing, forged and other-session tokens on upload, deletion and logout returned 403 and left the stored file intact. Missing login/registration tokens, reused registration tokens and expired pre-login tokens were rejected. | Server-validated tokens and secure cookie settings. |
| Cross-user access | Bob could not list, download, decrypt or delete Alice's file through the web and CLI. Web read/delete returned 404; CLI operations failed without creating plaintext output. Alice retained access and could delete her own file. | Owner predicates at every stored-file operation. |
| SQL injection | `' OR 1=1 --`, `' UNION SELECT 1 --` and `'; DROP TABLE files; --` reached shared session/file lookups as bound parameters, not SQL text. No unauthorized record was returned or table removed. Injection-shaped route IDs returned 400. | SQLAlchemy parameter binding and integer route validation. |
| XSS | An HTML-shaped upload filename was normalized. Script text in legacy metadata was escaped. A TXT file containing a script was returned only as an octet-stream attachment. | Name validation, autoescaping, restrictive CSP and download headers. |
| Unsafe uploads | HTML, SVG, PHP, Python, executable and extensionless uploads returned 400 without adding records. A 50 MiB file was accepted; one extra byte was rejected and partial encrypted output removed. | Extension allowlist and enforced request/file limits. |
| Command injection and traversal | Stored names such as `test;touch pwn`, `../file`, `a/b` and `a\b` were rejected. Parent traversal and symlinked parent directories were refused for reads, writes and wiping. | No shell evaluation, strict stored names and descriptor-based path handling. |
| Link attacks | Symlinked encrypted blobs could not be read or deleted; outside targets survived. Hard-linked local targets could not be overwritten or wiped. | No-follow opens and regular-file/link-count checks. |
| Encryption failures | Empty and binary files round-tripped. Wrong keys, modified ciphertext and incorrect additional data failed authentication. Plaintext samples were absent from encrypted storage. | AES-GCM authenticated encryption. |
| Deletion | Tests observed zero-filled local and stored files immediately before unlink, and confirmed removal of the owned metadata. | Overwrite, flush, fsync, identity check and owner-scoped deletion. |
| Authentication/session abuse | Wrong or unknown credentials failed; the eleventh attempt was rate-limited. Login rotated the session; logout, idle expiry and absolute expiry cleared cached keys. | Argon2id, throttling and session lifecycle checks. |
| Internal errors and secret leakage | Simulated storage/database failures produced generic errors. Captured events excluded sample passwords, plaintext, session/CSRF tokens, key encodings and internal exception text. | Fixed event schema, request context and generic error boundaries. |
| Memory cleanup | Tests observed zeroed encryption buffers after success/read failure, key and plaintext buffers after failed CLI output, download buffers after completion, and cached keys after failed logout. | Mutable buffers and cleanup in `finally` blocks. |
| TLS | A real HTTPS request succeeded with certificate verification and returned secure cookies, CSRF markup and HSTS. | Uvicorn TLS configuration. |

The original implementation lacked complete audit fields, an authenticated CLI stored-file deletion command, overwrite-before-delete for stored blobs, and web upload type restrictions. The checkpoint changes address these gaps and add direct file-manager evidence. Path handling and memory-cleanup failure paths were also strengthened.

Dependencies were updated from the older 2024 pins and the application adapted to current lifespan, template and multipart interfaces. Starlette has published fixes for multipart parsing vulnerabilities; retaining old framework versions would miss those fixes [3]. The test environment and runtime pins record the versions verified here.

### 3.3 Deployment assumptions and remaining limitations

Use one Uvicorn worker: cached keys, pre-login tokens and rate limits are process-local, and startup resets session records. Use HTTPS with a trusted certificate outside the local demonstration. The documented direct-server command disables access logging and proxy-header interpretation; a deployment behind a proxy must explicitly configure trusted peers and rate limits without accepting forged client addresses.

The application audit stream is designed to exclude secrets. Independently configured proxy logs, HTTP debugging, tracing, crash dumps and request-body logging can defeat that property. Do not enable them for sensitive requests. Keep the application data directory private and back up the database and encrypted blobs together. There is no password recovery or MFA.

Memory wiping and deletion have the limits described in Section 2.3. Filenames, usernames, file timestamps and access patterns remain visible to the server. Upload limits bound individual requests, not aggregate traffic; a public deployment needs connection, concurrency and storage quotas. SQLite and filesystem deletion are not one atomic transaction: a failure after blob removal may leave an unusable metadata row, but it must not expose plaintext or authorize another account.

The Markdown report supplies the required draft content. The final submission should be typeset with the School of Information Technologies thesis template, including author details, a table of contents and consistent references as required by Section 1.3 [1, 2]. The in-class demonstration and repository history are separate assessment activities.

## 4. Conclusion

The file manager implements the web and CLI functionality required for checkpoint 3 and includes reproducible evidence for authentication, ownership, encryption, CSRF, XSS, SQL injection prevention, input handling, deletion, logging and memory cleanup. The completed suite passes all 53 tests.

The main engineering lessons are that shared ownership checks prevent differences between interfaces, authenticated encryption must verify data before releasing it, and failure paths need the same cleanup as successful operations. A generic JSON log is insufficient unless it includes the required operational context and excludes secrets by construction. Secure filesystem operations must check the file actually opened, including its parent path and links.

The principal challenges are balancing plaintext processing with bounded memory, preserving web behavior while updating dependencies, and testing deletion and cleanup without overstating their guarantees. Python memory management and storage-device behavior remain explicit limits rather than claims of guaranteed erasure.

## References

1. Ali Ghasempour, *ICS0027 Web Application Security: Project Instructions*, autumn semester 2026/2027, supplied `Project.pdf`, Section 1.3 (p. 5), Sections 3.2–3.4.3 (pp. 9–12).
2. *Secure Programming: Project Instructions*, supplied `Projects.pdf`, Section 1.3 (p. 5), Sections 3.1–3.4.3 (pp. 9–11).
3. Starlette maintainers, [multipart denial-of-service advisory GHSA-2c2j-9gv5-cj73](https://github.com/Kludex/starlette/security/advisories/GHSA-2c2j-9gv5-cj73) and [release notes](https://starlette.dev/release-notes/), accessed 16 November 2026.

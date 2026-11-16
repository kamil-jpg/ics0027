# File manager checkpoint 3 assessment

Verified on 16 November 2026 against the **file-manager** requirements in the supplied `Project.pdf` (Web Application Security) and `Projects.pdf` (Secure Programming). Password-manager requirements do not apply to this assessment, and the project contains no password-vault feature.

**Result:** the technical checkpoint requirements have implementations and passing evidence. Memory clearing and deletion are best effort under Python and modern storage; they must not be presented as guaranteed erasure. The draft report contains all four sections required by Section 1.3. Final thesis formatting and the in-class demonstration remain submission activities.

## Requirement mapping

| Course requirement | Implementation and evidence | Result |
|---|---|---|
| Feature-complete web application and CLI | Shared encrypted store; register/login, upload/encrypt, download/decrypt, list, delete, local wipe; CLI/web interoperability and real HTTPS tests. | Pass |
| CSRF on every state-changing form, demonstrated | `src/web/main.py`; missing, forged and another-session tokens rejected on file upload/delete/logout; registration/login attacks, replay and expiry tested. | Pass |
| XSS defenses | Autoescaped templates; filename normalization; CSP with scripts disabled; attachment-only downloads. File-specific payload test in `test_checkpoint3.py`. | Pass |
| Full input validation and secure handling | Names, paths, IDs, credentials and request/file sizes checked; web extension allowlist; no shell calls; symlink parents and hard-linked output/deletion targets rejected. | Pass |
| SQL injection prevention throughout | SQLAlchemy bound values throughout; static foreign-key PRAGMA only. Three payloads observed in DB parameters separately from SQL; route-ID attack rejected. | Pass |
| Ownership on every file operation | User-scoped create/list/read/delete in web and CLI; Bob cannot enumerate, read, decrypt or delete Alice's file; Alice's data remains intact. | Pass |
| Secure error handling and structured logging | Fixed user errors; JSON UTC timestamp, operation, outcome, numeric user ID when known, and source address; exception text excluded. | Pass |
| No secrets written to application logs | Event-schema checks plus captured logs checked against passwords, plaintext, tokens and key encoding; arbitrary event/outcome/user/address text rejected or normalized. | Pass within application audit stream |
| Secure memory management | Bounded encryption buffers, controlled key/plaintext clearing, failure cleanup, logout/expiry/rotation cleanup, no plaintext multipart spool files. | Pass for managed buffers; no guarantee for Python/library copies |
| Encryption/decryption and secure deletion tests | Empty/binary/large round trips, wrong key/tampering/AAD checks, zero-filled bytes observed before unlink, record removal, link refusal. | Pass; physical erasure is not guaranteed |
| Authentication failure and validation edge cases | Wrong/unknown credentials, rate limiting, session expiry, missing fields, traversal, command-shaped names, unsupported types and size boundaries. | Pass |
| Security cases with vectors, results and mitigations | [Run output](checkpoint3-test-results.txt), [JUnit results](checkpoint3-results.xml), report Section 3.2 and the demonstrations below. | Pass |
| Introduction, Implementation, Security Analysis, Conclusion | [REPORT_DRAFT.md](../REPORT_DRAFT.md), aligned with Section 1.3 of both PDFs. | Draft content complete |

## Recorded test run

**53 passed, 0 failed, 0 skipped**, in 15.72 seconds on Linux/Python 3.12.16. One non-failing Starlette warning recommends a future move from `httpx` to `httpx2` in tests. `pip check` reported no broken requirements. [Installed dependency versions](checkpoint3-environment.txt) are retained alongside the [complete output](checkpoint3-test-results.txt).

The run used a fresh temporary virtual environment built from `requirements-dev.txt`; the pre-existing repository `venv` holds older packages and was not upgraded (the updated tests fail there). Install the new `requirements-dev.txt` into your chosen environment before running the updated application or tests.

From the repository root:

```bash
python3 -m venv .venv-checkpoint3
source .venv-checkpoint3/bin/activate
python -m pip install -r requirements-dev.txt
python -m pytest -v --junitxml=docs/checkpoint3-results.xml
python -m pip check
```

`openssl` is needed for the real TLS smoke test; without it that test explicitly skips. Each test uses disposable data. Existing `data/` contents are not test fixtures. The suite includes 29 new file-manager/TLS cases plus 24 regression cases.

## Reproducible attack demonstrations

### CSRF

```bash
python -m pytest -v tests/test_checkpoint3.py::test_file_csrf_demonstration_and_cross_session_token
```

The test signs in Alice, uploads a real file, obtains a second session, and submits upload, delete and logout requests using no token, `forged-token`, and the second session's token. All nine requests return **403**. The original file remains downloadable and the record count is unchanged. Alice's valid token then deletes the file successfully.

For a browser demonstration, log in and upload `notes.txt`. In developer tools, change or remove the hidden `csrf_token` in the dashboard's delete form and submit it. The response is 403 and the file survives. Reloading the dashboard restores the valid token. This demonstrates the server check even when the browser sends a legitimate session cookie.

### Access to another user's file

```bash
python -m pytest -v tests/test_checkpoint3.py::test_owner_scoped_cli_list_decrypt_delete_and_web_list
```

Alice uploads `notes.txt`. Bob cannot see it in his list, cannot download or delete its known numeric ID, and cannot decrypt or delete it by name using the CLI. Web responses are **404**; CLI attempts exit **1**, leave no output and retain the blob. Alice can delete the same file.

For a browser demonstration, use separate browser profiles for Alice and Bob. Copy Alice's `/files/download/ID` URL to Bob's session. For deletion, edit a delete form in Bob's dashboard to target Alice's ID while retaining **Bob's valid CSRF token**; if needed, upload a disposable file as Bob first to obtain a form. Both attempts must return 404. Using Bob's valid token proves the ownership check independently of CSRF.

### SQL injection

```bash
python -m pytest -v tests/test_checkpoint3.py -k sql_injection
```

Payloads are `' OR 1=1 --`, `' UNION SELECT 1 --`, and `'; DROP TABLE files; --`. The tests observe these values reaching session and file queries as separate parameters while the SQL retains `?` placeholders. No record is returned; tables and legitimate records survive. `/files/download/1%20OR%201=1` returns **400**. This tests actual parameter binding in addition to validation at the web boundary.

### XSS, deletion and memory

```bash
python -m pytest -v tests/test_checkpoint3.py -k 'xss or overwritten or wiped or cleanup'
```

An `<img src=x onerror=alert(1)>.txt` filename is normalized. Legacy script-shaped metadata is HTML-escaped, and `<script>alert("checkpoint-xss")</script>` file bytes are attachment-only. Deletion tests inspect bytes immediately before unlink and observe only zeroes. Cleanup tests retain references to mutable buffers and verify they are zeroed after successful processing, failed reads/writes and failed logout.

## Changes made for this checkpoint review

The review added the missing audit fields and distinct file/session events, authenticated CLI `delete`, overwrite-before-delete of stored blobs, a web upload extension policy, stronger filesystem link/path defenses, encryption/download buffer cleanup, and logout cleanup after database failure. It upgraded runtime dependencies and adapted framework APIs, added direct file-manager attack evidence and a real TLS test, and corrected the report's project scope and its earlier incorrect statement that Section 1.3 was unavailable.

No commit, staging, publication or submission was performed. Existing uncommitted work was retained. The PDFs' instructions about checkpoint commits were treated as course context; the user's explicit request not to commit governed this review.

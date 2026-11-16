"""Memory handling and secret-free structured security events."""
import json
import logging
import datetime
import ipaddress
from contextlib import contextmanager
from contextvars import ContextVar

logger = logging.getLogger("secfile.security")
_source_address = ContextVar("audit_source_address", default="local")


@contextmanager
def audit_source(address: str | None):
    """Carry only a validated transport peer address into request/thread logs."""
    try:
        source = str(ipaddress.ip_address(address))
    except ValueError:
        source = "unknown"
    token = _source_address.set(source)
    try:
        yield
    finally:
        _source_address.reset(token)


def secure_wipe(buffer: bytearray) -> None:
    """Overwrite a mutable byte buffer with zeros in place."""
    buffer[:] = b"\x00" * len(buffer)


def audit(event: str, outcome: str, user_id: int | None = None) -> None:
    """Log fixed events, UTC time, transport address and numeric IDs; never secrets."""
    allowed_events = {
        "registration", "authentication", "session", "csrf", "file",
        "request_error",
        "file_encrypt", "file_decrypt", "file_delete", "file_list", "local_wipe",
        "session_create", "session_destroy",
    }
    if event not in allowed_events or outcome not in {"success", "failure", "denied"}:
        raise ValueError("Invalid security event.")
    if user_id is not None and (not isinstance(user_id, int) or isinstance(user_id, bool)):
        raise ValueError("Invalid security event user ID.")
    logger.warning(json.dumps({
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "event": event, "outcome": outcome, "user_id": user_id,
        "source_address": _source_address.get(),
    }))

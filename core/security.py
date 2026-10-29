"""Memory-handling helpers: explicit wiping of sensitive byte buffers."""


def secure_wipe(buffer: bytearray) -> None:
    """Overwrite a mutable byte buffer with zeros in place."""
    if buffer is None:
        return
    for i in range(len(buffer)):
        buffer[i] = 0

"""Wire-level helpers for the transport layer."""

HEADER_DELIMITER = b"\r\n\r\n"


def format_client_address(client_address: tuple[str, int]) -> str:
    """Return a stable host:port string for logs."""
    return f"{client_address[0]}:{client_address[1]}"

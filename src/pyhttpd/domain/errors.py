"""Domain error hierarchy for HTTP request handling."""


class HttpError(Exception):
    """Base class for HTTP request handling errors."""


class ForbiddenPath(HttpError):
    """Raised when a requested path escapes the configured sandbox."""


class RequestEntityTooLarge(HttpError):
    """Raised when a request body exceeds configured limits."""

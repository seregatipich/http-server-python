"""Domain error hierarchy for HTTP request handling."""

from typing import Iterable

from pyhttpd.domain.ratelimit import RateLimitDecision


class HttpError(Exception):
    """Base class for HTTP request handling errors."""

    status: int = 500
    reason: str = "Internal Server Error"

    @property
    def status_line(self) -> str:
        """Return the HTTP/1.1 status line for this error."""
        return f"HTTP/1.1 {self.status} {self.reason}"


class ForbiddenPath(HttpError):
    """Raised when a requested path escapes the configured sandbox."""


class RequestEntityTooLarge(HttpError):
    """Raised when a request body exceeds configured limits."""


class BadRequest(HttpError):
    """Raised when the request is malformed."""

    status = 400
    reason = "Bad Request"


class Forbidden(HttpError):
    """Raised when access to a resource is denied."""

    status = 403
    reason = "Forbidden"


class NotFound(HttpError):
    """Raised when the requested resource does not exist."""

    status = 404
    reason = "Not Found"


class MethodNotAllowed(HttpError):
    """Raised when the request method is not supported for a resource."""

    status = 405
    reason = "Method Not Allowed"

    def __init__(self, allowed: Iterable[str]) -> None:
        super().__init__()
        self.allowed = tuple(allowed)


class Unauthorized(HttpError):
    """Raised when a request lacks valid authentication credentials."""

    status = 401
    reason = "Unauthorized"

    def __init__(self, challenge: str) -> None:
        super().__init__()
        self.challenge = challenge


class RateLimited(HttpError):
    """Raised when a client exceeds the configured rate limit."""

    status = 429
    reason = "Too Many Requests"

    def __init__(self, decision: RateLimitDecision) -> None:
        super().__init__()
        self.decision = decision


class ServiceUnavailable(HttpError):
    """Raised when the server cannot currently handle the request."""

    status = 503
    reason = "Service Unavailable"


class InternalServerError(HttpError):
    """Raised when an unexpected server-side failure occurs."""

    status = 500
    reason = "Internal Server Error"

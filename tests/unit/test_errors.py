"""Unit tests for the domain HTTP error hierarchy."""

import pytest

from pyhttpd.domain import (
    BadRequest,
    Forbidden,
    ForbiddenPath,
    HttpError,
    InternalServerError,
    MethodNotAllowed,
    NotFound,
    RateLimited,
    RequestEntityTooLarge,
    ServiceUnavailable,
)

STATUS_CASES = [
    (BadRequest, 400, "Bad Request"),
    (Forbidden, 403, "Forbidden"),
    (NotFound, 404, "Not Found"),
    (ServiceUnavailable, 503, "Service Unavailable"),
    (InternalServerError, 500, "Internal Server Error"),
]


def test_base_defaults_to_internal_server_error():
    """HttpError defaults to a 500 status line."""
    assert HttpError().status == 500
    assert HttpError().status_line == "HTTP/1.1 500 Internal Server Error"


@pytest.mark.parametrize("error_cls, status, reason", STATUS_CASES)
def test_simple_errors_carry_status_and_status_line(error_cls, status, reason):
    """Each simple error exposes its status, reason, and formatted status line."""
    error = error_cls()
    assert error.status == status
    assert error.reason == reason
    assert error.status_line == f"HTTP/1.1 {status} {reason}"


@pytest.mark.parametrize(
    "error_cls",
    [
        HttpError,
        ForbiddenPath,
        RequestEntityTooLarge,
        BadRequest,
        Forbidden,
        NotFound,
        MethodNotAllowed,
        RateLimited,
        ServiceUnavailable,
        InternalServerError,
    ],
)
def test_every_error_is_an_http_error(error_cls):
    """The whole hierarchy derives from HttpError (and Exception)."""
    assert issubclass(error_cls, HttpError)
    assert issubclass(error_cls, Exception)


def test_sandbox_errors_inherit_base_500():
    """Path/entity errors inherit the base 500 status line."""
    assert ForbiddenPath().status == 500
    assert RequestEntityTooLarge().status == 500


def test_method_not_allowed_records_allowed_methods():
    """MethodNotAllowed stores the allowed methods as a tuple and is a 405."""
    error = MethodNotAllowed(["GET", "POST"])
    assert error.status == 405
    assert error.allowed == ("GET", "POST")


def test_rate_limited_carries_decision():
    """RateLimited stores the rate-limit decision and is a 429."""
    decision = object()
    error = RateLimited(decision)
    assert error.status == 429
    assert error.decision is decision


def test_errors_are_raisable_and_catchable_as_base():
    """A typed error can be caught via the HttpError base."""
    with pytest.raises(HttpError):
        raise NotFound()

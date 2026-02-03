"""Unit tests for sensitive data redaction."""

from server.bootstrap.logging_setup import redact_sensitive


def test_redact_authorization_header():
    """Test that authorization values are redacted."""
    assert redact_sensitive("Authorization: Bearer token123") == "[REDACTED]"
    assert redact_sensitive("authorization: secret") == "[REDACTED]"


def test_redact_token_values():
    """Test that token values are redacted."""
    assert redact_sensitive("token=abc123def456") == "[REDACTED]"
    assert redact_sensitive("api_key=secret") == "[REDACTED]"
    assert redact_sensitive("api-key=secret") == "[REDACTED]"


def test_redact_password_values():
    """Test that password values are redacted."""
    assert redact_sensitive("password=secret123") == "[REDACTED]"
    assert redact_sensitive("Password: mypass") == "[REDACTED]"


def test_redact_hex_sequences():
    """Test that long hex sequences are redacted."""
    assert redact_sensitive("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6") == "[REDACTED]"
    assert redact_sensitive("0123456789abcdef0123456789abcdef") == "[REDACTED]"


def test_redact_base64_sequences():
    """Test that long base64 sequences are redacted."""
    assert redact_sensitive("YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=") == "[REDACTED]"
    assert redact_sensitive("SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0") == "[REDACTED]"


def test_no_redaction_for_safe_values():
    """Test that safe values are not redacted."""
    assert redact_sensitive("user_id=123") == "user_id=123"
    assert redact_sensitive("name=John Doe") == "name=John Doe"
    assert redact_sensitive("path=/files/test.txt") == "path=/files/test.txt"
    assert redact_sensitive("short_hex=abc123") == "short_hex=abc123"


def test_redact_empty_string():
    """Test that empty strings are handled correctly."""
    assert redact_sensitive("") == ""


def test_redact_none_value():
    """Test that None values are handled correctly."""
    assert redact_sensitive(None) is None


def test_redact_signature_values():
    """Test that signature values are redacted."""
    assert redact_sensitive("signature=xyz789") == "[REDACTED]"
    assert redact_sensitive("Signature: abc") == "[REDACTED]"


def test_redact_secret_values():
    """Test that secret values are redacted."""
    assert redact_sensitive("secret=mysecret") == "[REDACTED]"
    assert redact_sensitive("client_secret=abc123") == "[REDACTED]"


def test_case_insensitive_redaction():
    """Test that redaction is case-insensitive."""
    assert redact_sensitive("TOKEN=abc") == "[REDACTED]"
    assert redact_sensitive("Password=xyz") == "[REDACTED]"
    assert redact_sensitive("AUTHORIZATION=bearer") == "[REDACTED]"

import pytest

from .safe_http import (
    SafeRequestError,
    validate_public_url,
)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1",
        "http://localhost",
        "http://192.168.1.1",
        "http://10.0.0.1",
        "http://169.254.169.254",
        "file:///etc/passwd",
        "https://user:password@example.com",
        "https://example.com/#fragment",
    ],
)
def test_unsafe_urls_are_rejected(url):
    with pytest.raises(SafeRequestError):
        validate_public_url(url)


def test_invalid_url_is_rejected():
    with pytest.raises(SafeRequestError):
        validate_public_url("not-a-valid-url")


def test_non_http_scheme_is_rejected():
    with pytest.raises(SafeRequestError):
        validate_public_url("ftp://example.com")
import ipaddress
import socket
from urllib.parse import urlsplit


class ScanValidationError(Exception):
    """Raised when an assessment target fails validation."""


def validate_target_url(url):
    """
    Validate a target URL before an assessment.

    This function does not send network requests.
    """

    if not url or not isinstance(url, str):
        raise ScanValidationError("A target URL is required.")

    if url != url.strip():
        raise ScanValidationError("The URL must not contain surrounding whitespace.")

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise ScanValidationError("The URL or port is invalid.") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise ScanValidationError("Only HTTP and HTTPS URLs are supported.")

    if not parsed.hostname:
        raise ScanValidationError("The URL must include a hostname.")

    if parsed.username or parsed.password:
        raise ScanValidationError("URLs containing embedded credentials are not allowed.")

    if parsed.fragment:
        raise ScanValidationError("Remove the URL fragment before registering the target.")

    hostname = parsed.hostname.rstrip(".").lower()

    if hostname == "localhost" or hostname.endswith(".localhost"):
        raise ScanValidationError("Localhost targets are not allowed.")

    if hostname.endswith(".local"):
        raise ScanValidationError("Local network hostnames are not allowed.")

    if hostname.endswith(".internal"):
        raise ScanValidationError("Internal hostnames are not allowed.")

    if port is not None and not (1 <= port <= 65535):
        raise ScanValidationError("The target port is invalid.")

    try:
        address = ipaddress.ip_address(hostname)
    except ValueError:
        address = None

    if address is not None:
        if not address.is_global:
            raise ScanValidationError(
                "Private, loopback, and non-public IP addresses are not allowed."
            )

    return {
        "url": url,
        "scheme": parsed.scheme.lower(),
        "hostname": hostname,
        "port": port or (443 if parsed.scheme.lower() == "https" else 80),
        "path": parsed.path or "/",
    }


def validate_public_dns(hostname):
    """
    Resolve a hostname and reject it if any returned address is non-public.

    This function performs DNS resolution, but does not send an HTTP request.
    """

    try:
        results = socket.getaddrinfo(
            hostname,
            None,
            type=socket.SOCK_STREAM
        )
    except socket.gaierror as exc:
        raise ScanValidationError(
            "The hostname could not be resolved."
        ) from exc

    if not results:
        raise ScanValidationError("The hostname returned no IP addresses.")

    addresses = set()

    for result in results:
        address_text = result[4][0]

        try:
            address = ipaddress.ip_address(address_text)
        except ValueError as exc:
            raise ScanValidationError(
                "DNS returned an invalid IP address."
            ) from exc

        if not address.is_global:
            raise ScanValidationError(
                "The hostname resolves to a non-public IP address."
            )

        addresses.add(str(address))

    return sorted(addresses)
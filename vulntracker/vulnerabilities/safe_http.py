import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

import requests


CONNECT_TIMEOUT = 3.05
READ_TIMEOUT = 5
MAX_RESPONSE_BYTES = 1_000_000
MAX_REDIRECTS = 3

USER_AGENT = "VulnTracker-Security-Assessment/1.0"


class SafeRequestError(Exception):
    """Raised when an HTTP request fails a safety check."""


def validate_public_url(url):
    """
    Validate an HTTPS URL and reject private or non-public destinations.

    DNS is checked before connecting, but this alone does not prevent
    DNS rebinding. Use connection-time IP enforcement before deploying
    this transport against arbitrary user-supplied targets.
    """

    if not isinstance(url, str) or not url or url != url.strip():
        raise SafeRequestError("A valid URL is required.")

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise SafeRequestError("Invalid URL or port.") from exc

    if parsed.scheme.lower() not in ("http", "https"):
        raise SafeRequestError("Only HTTP and HTTPS targets are permitted.")

    if not parsed.hostname:
        raise SafeRequestError("A hostname is required.")

    if parsed.username or parsed.password:
        raise SafeRequestError("URLs containing credentials are forbidden.")

    if parsed.fragment:
        raise SafeRequestError("URL fragments are not permitted.")

    hostname = parsed.hostname.rstrip(".").lower()

    if hostname == "localhost" or hostname.endswith(
        (".localhost", ".local", ".internal")
    ):
        raise SafeRequestError("Local and internal hostnames are forbidden.")

    port = port or (443 if parsed.scheme.lower() == "https" else 80)

    if not 1 <= port <= 65535:
        raise SafeRequestError("Invalid port.")

    try:
        ip = ipaddress.ip_address(hostname)
    except ValueError:
        ip = None

    if ip is not None:
        if not ip.is_global:
            raise SafeRequestError("Non-public IP addresses are forbidden.")
        addresses = {str(ip)}
    else:
        try:
            results = socket.getaddrinfo(
                hostname,
                port,
                type=socket.SOCK_STREAM,
            )
        except socket.gaierror as exc:
            raise SafeRequestError("Hostname resolution failed.") from exc

        addresses = set()

        for result in results:
            address_text = result[4][0]

            try:
                address = ipaddress.ip_address(address_text)
            except ValueError as exc:
                raise SafeRequestError(
                    "DNS returned an invalid IP address."
                ) from exc

            if not address.is_global:
                raise SafeRequestError(
                    "Hostname resolves to a non-public IP address."
                )

            addresses.add(str(address))

        if not addresses:
            raise SafeRequestError("Hostname has no resolved addresses.")

    return {
        "url": url,
        "hostname": hostname,
        "port": port,
        "addresses": sorted(addresses),
    }


def safe_get(url):
    """
    Perform a bounded HTTPS GET with manual redirect handling.

    Important: DNS validation is a preliminary safeguard, not a
    guarantee that the HTTP connection uses a validated IP address.
    Do not expose this function as a public arbitrary-target scanner.
    """

    current_url = url

    # Ignore proxy environment variables such as HTTP_PROXY and HTTPS_PROXY.
    session = requests.Session()
    session.trust_env = False

    try:
        for redirect_count in range(MAX_REDIRECTS + 1):
            validate_public_url(current_url)

            try:
                with session.get(
                    current_url,
                    allow_redirects=False,
                    stream=True,
                    timeout=(CONNECT_TIMEOUT, READ_TIMEOUT),
                    verify=True,
                    headers={"User-Agent": USER_AGENT},
                ) as response:

                    if response.is_redirect or response.is_permanent_redirect:
                        location = response.headers.get("Location")

                        if not location:
                            raise SafeRequestError(
                                "Redirect response has no Location header."
                            )

                        if redirect_count >= MAX_REDIRECTS:
                            raise SafeRequestError("Too many redirects.")

                        next_url = urljoin(current_url, location)

                        # Validate the redirect destination before following it.
                        validate_public_url(next_url)
                        current_url = next_url
                        continue

                    content_length = response.headers.get("Content-Length")

                    if content_length is not None:
                        try:
                            length = int(content_length)
                        except ValueError as exc:
                            raise SafeRequestError(
                                "Invalid Content-Length header."
                            ) from exc

                        if length < 0 or length > MAX_RESPONSE_BYTES:
                            raise SafeRequestError(
                                "Response exceeds the permitted size."
                            )

                    body = bytearray()

                    for chunk in response.iter_content(chunk_size=8192):
                        body.extend(chunk)

                        if len(body) > MAX_RESPONSE_BYTES:
                            raise SafeRequestError(
                                "Response exceeds the permitted size."
                            )

                    return {
                        "url": response.url,
                        "status_code": response.status_code,
                        "headers": dict(response.headers),
                        "body": bytes(body),
                    }

            except requests.RequestException as exc:
                raise SafeRequestError(
                    f"HTTP request failed: {exc}"
                ) from exc

        raise SafeRequestError("Request could not be completed.")

    finally:
        session.close()
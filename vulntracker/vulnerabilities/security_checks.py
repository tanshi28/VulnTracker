SECURITY_HEADERS = {
    "content-security-policy": {
        "title": "Content Security Policy Missing",
        "severity": "MEDIUM",
        "category": "Security Headers",
        "description": (
            "The HTTP response does not contain a Content-Security-Policy "
            "header. This header can help restrict the sources from which "
            "a browser loads content."
        ),
        "remediation": (
            "Define a Content-Security-Policy appropriate for the application. "
            "Test the policy before enforcing it in production."
        ),
    },
    "strict-transport-security": {
        "title": "HTTP Strict Transport Security Missing",
        "severity": "LOW",
        "category": "Security Headers",
        "description": (
            "The HTTPS response does not contain a Strict-Transport-Security "
            "header. HSTS can instruct browsers to use HTTPS for future visits."
        ),
        "remediation": (
            "If the website is intended to operate exclusively over HTTPS, "
            "consider configuring an appropriate Strict-Transport-Security "
            "header after verifying the deployment."
        ),
    },
    "x-content-type-options": {
        "title": "X-Content-Type-Options Missing",
        "severity": "LOW",
        "category": "Security Headers",
        "description": (
            "The HTTP response does not contain X-Content-Type-Options. "
            "The nosniff value helps prevent browsers from interpreting "
            "content as a different MIME type."
        ),
        "remediation": (
            "Consider setting X-Content-Type-Options: nosniff and verify "
            "that the application serves correct Content-Type values."
        ),
    },
    "referrer-policy": {
        "title": "Referrer Policy Missing",
        "severity": "INFO",
        "category": "Security Headers",
        "description": (
            "The HTTP response does not specify a Referrer-Policy header. "
            "Without an explicit policy, referrer information may be shared "
            "according to browser defaults."
        ),
        "remediation": (
            "Choose a Referrer-Policy that matches the application's "
            "privacy requirements, such as strict-origin-when-cross-origin."
        ),
    },
    "permissions-policy": {
        "title": "Permissions Policy Missing",
        "severity": "INFO",
        "category": "Security Headers",
        "description": (
            "The HTTP response does not contain a Permissions-Policy header. "
            "This header can restrict access to selected browser features."
        ),
        "remediation": (
            "Consider defining a Permissions-Policy that disables browser "
            "features the application does not need."
        ),
    },
}


def check_security_headers(headers, scheme="https"):
    """
    Analyze an HTTP response's headers.

    Args:
        headers: A mapping of HTTP response header names to values.
        scheme: The scheme of the final response URL.

    Returns:
        A list of finding dictionaries.

    This function does not perform network requests.
    """

    normalized_headers = {
        str(name).lower(): str(value)
        for name, value in headers.items()
    }

    findings = []

    for header_name, details in SECURITY_HEADERS.items():

        # HSTS is relevant to HTTPS responses.
        if (
            header_name == "strict-transport-security"
            and scheme.lower() != "https"
        ):
            continue

        if header_name not in normalized_headers:
            findings.append({
                **details,
                "evidence": (
                    f"Response header '{header_name}' was not present."
                ),
            })

    return findings


def check_cookie_attributes(set_cookie_headers):
    """
    Inspect Set-Cookie header values for common security attributes.

    Args:
        set_cookie_headers: A list of individual Set-Cookie header values.

    Returns:
        A list of informational finding dictionaries.

    Pass individual Set-Cookie values, not a combined comma-separated
    header, because cookie attributes and expiration dates can contain commas.

    This function does not perform network requests.
    """

    findings = []

    for cookie_header in set_cookie_headers:
        parts = [
            part.strip()
            for part in cookie_header.split(";")
        ]

        if not parts or not parts[0] or "=" not in parts[0]:
            continue

        cookie_name = parts[0].split("=", 1)[0].strip()

        if not cookie_name:
            continue

        attributes = {
            part.split("=", 1)[0].strip().lower()
            for part in parts[1:]
            if part
        }

        if "secure" not in attributes:
            findings.append({
                "title": "Cookie Missing Secure Attribute",
                "category": "Cookie Security",
                "severity": "LOW",
                "description": (
                    "A cookie was set without the Secure attribute. "
                    "Depending on how it is used and the application "
                    "configuration, this may allow it to be transmitted "
                    "over an unencrypted connection."
                ),
                "evidence": (
                    f"Cookie '{cookie_name}' does not specify Secure."
                ),
                "remediation": (
                    "For cookies that should only be transmitted over HTTPS, "
                    "set the Secure attribute."
                ),
            })

        if "httponly" not in attributes:
            findings.append({
                "title": "Cookie Missing HttpOnly Attribute",
                "category": "Cookie Security",
                "severity": "LOW",
                "description": (
                    "A cookie was set without HttpOnly. If the cookie contains "
                    "sensitive session information, client-side scripts may "
                    "be able to access it."
                ),
                "evidence": (
                    f"Cookie '{cookie_name}' does not specify HttpOnly."
                ),
                "remediation": (
                    "Set HttpOnly on cookies that do not need to be accessed "
                    "by client-side JavaScript."
                ),
            })

        if "samesite" not in attributes:
            findings.append({
                "title": "Cookie Missing SameSite Attribute",
                "category": "Cookie Security",
                "severity": "INFO",
                "description": (
                    "A cookie was set without an explicit SameSite attribute. "
                    "Cross-site cookie behavior can depend on browser defaults "
                    "and the application's authentication design."
                ),
                "evidence": (
                    f"Cookie '{cookie_name}' does not specify SameSite."
                ),
                "remediation": (
                    "Choose an appropriate SameSite policy, such as Lax or "
                    "Strict, after reviewing the application's cross-site "
                    "authentication and navigation requirements."
                ),
            })

    return findings
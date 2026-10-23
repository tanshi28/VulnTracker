from urllib.parse import urlsplit

from django.db import transaction
from django.utils import timezone

from .models import AssessmentRun
from .finding_utils import save_findings
from .scanner import ScanValidationError, validate_target_url
from .safe_http import SafeRequestError, safe_get
from .security_checks import (
    check_security_headers,
    check_cookie_attributes,
)


def run_assessment(assessment_id):
    """
    Run non-intrusive security checks against an authorized web asset.

    Checks HTTPS response headers and cookie attributes, saves findings,
    and records the assessment outcome.
    """

    assessment = AssessmentRun.objects.select_related("asset").get(
        id=assessment_id
    )

    if assessment.status != "PENDING":
        raise ValueError("Only pending assessments can be started.")

    asset = assessment.asset

    if not asset.is_active:
        raise ValueError("This web asset is inactive.")

    if not asset.is_authorized:
        raise ValueError(
            "This asset is not marked as authorized for assessment."
        )

    assessment.status = "RUNNING"
    assessment.started_at = timezone.now()
    assessment.error_message = ""
    assessment.save(
        update_fields=["status", "started_at", "error_message"]
    )

    try:
        # Apply the existing target validation first.
        validate_target_url(asset.url)

        # Perform the bounded HTTP request.
        response = safe_get(asset.url)

        headers = response["headers"]

        # Identify absent security headers using the actual response scheme.
        response_scheme = urlsplit(response["url"]).scheme.lower() or "https"
        findings = check_security_headers(
            headers,
            scheme=response_scheme,
        )

        # Retrieve Set-Cookie values without losing multiple cookies.
        cookie_headers = []

        for header_name, header_value in headers.items():
            if header_name.lower() == "set-cookie":
                cookie_headers.append(header_value)

        findings.extend(
            check_cookie_attributes(cookie_headers)
        )

        # Store findings and complete the assessment.
        with transaction.atomic():
            save_findings(assessment, findings)

            assessment.status = "COMPLETED"
            assessment.completed_at = timezone.now()
            assessment.summary = (
                f"Assessment completed. HTTP status: "
                f"{response['status_code']}. "
                f"{len(findings)} security observations recorded."
            )
            assessment.error_message = ""
            assessment.save(
                update_fields=[
                    "status",
                    "completed_at",
                    "summary",
                    "error_message",
                ]
            )

        return assessment

    except Exception as exc:
        assessment.status = "FAILED"
        assessment.completed_at = timezone.now()
        assessment.error_message = str(exc)
        assessment.save(
            update_fields=[
                "status",
                "completed_at",
                "error_message",
            ]
        )
        raise
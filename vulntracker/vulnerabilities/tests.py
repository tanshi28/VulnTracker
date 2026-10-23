from unittest.mock import patch

from django.test import TestCase

from .models import WebAsset, AssessmentRun, AssessmentFinding
from .finding_utils import save_findings


class AssessmentWorkflowTests(TestCase):

    def setUp(self):
        self.asset = WebAsset.objects.create(
            name="Test Website",
            url="https://example.com",
            description="Test asset",
            is_authorized=True,
            is_active=True,
        )

        self.assessment = AssessmentRun.objects.create(
            asset=self.asset,
            status="PENDING",
        )

    def test_authorized_asset_is_registered(self):
        self.assertTrue(self.asset.is_authorized)
        self.assertTrue(self.asset.is_active)

    def test_assessment_starts_as_pending(self):
        self.assertEqual(self.assessment.status, "PENDING")

    def test_inactive_asset_is_marked_correctly(self):
        self.asset.is_active = False
        self.asset.save()
        self.asset.refresh_from_db()
        self.assertFalse(self.asset.is_active)

    def test_unauthorized_asset_is_marked_correctly(self):
        self.asset.is_authorized = False
        self.asset.save()
        self.asset.refresh_from_db()
        self.assertFalse(self.asset.is_authorized)

    def test_findings_cannot_be_saved_to_pending_assessment(self):
        finding = {
            "title": "Missing CSP",
            "category": "Security Headers",
            "severity": "MEDIUM",
            "description": "Content Security Policy header is missing.",
        }

        with self.assertRaises(ValueError):
            save_findings(self.assessment, [finding])

        self.assertEqual(
            AssessmentFinding.objects.filter(
                assessment=self.assessment
            ).count(),
            0,
        )

    def test_findings_can_be_saved_to_running_assessment(self):
        self.assessment.status = "RUNNING"
        self.assessment.save()

        findings = [
            {
                "title": "Missing CSP",
                "category": "Security Headers",
                "severity": "MEDIUM",
                "description": "Content Security Policy header is missing.",
                "evidence": "The response did not include Content-Security-Policy.",
                "remediation": "Configure an appropriate Content-Security-Policy.",
            },
            {
                "title": "Missing Referrer Policy",
                "category": "Security Headers",
                "severity": "INFO",
                "description": "Referrer-Policy header is missing.",
            },
        ]

        created_count = save_findings(self.assessment, findings)

        self.assertEqual(created_count, 2)

        self.assertEqual(
            AssessmentFinding.objects.filter(
                assessment=self.assessment
            ).count(),
            2,
        )

    def test_saved_findings_have_open_status(self):
        self.assessment.status = "RUNNING"
        self.assessment.save()

        save_findings(
            self.assessment,
            [
                {
                    "title": "Missing CSP",
                    "category": "Security Headers",
                    "severity": "MEDIUM",
                    "description": "Content Security Policy header is missing.",
                }
            ],
        )

        finding = AssessmentFinding.objects.get(
            assessment=self.assessment
        )

        self.assertEqual(finding.status, "OPEN")

    def test_runner_rejects_unauthorized_asset(self):
        from .assessment_runner import run_assessment

        self.asset.is_authorized = False
        self.asset.save()

        with self.assertRaisesMessage(
            ValueError,
            "This asset is not marked as authorized for assessment.",
        ):
            run_assessment(self.assessment.id)

        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.status, "PENDING")

    def test_runner_rejects_inactive_asset(self):
        from .assessment_runner import run_assessment

        self.asset.is_active = False
        self.asset.save()

        with self.assertRaisesMessage(
            ValueError,
            "This web asset is inactive.",
        ):
            run_assessment(self.assessment.id)

        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.status, "PENDING")

    def test_runner_rejects_non_pending_assessment(self):
        from .assessment_runner import run_assessment

        self.assessment.status = "COMPLETED"
        self.assessment.save()

        with self.assertRaisesMessage(
            ValueError,
            "Only pending assessments can be started.",
        ):
            run_assessment(self.assessment.id)

        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.status, "COMPLETED")

    @patch("vulnerabilities.assessment_runner.safe_get")
    def test_runner_completes_assessment(self, mock_safe_get):
        from .assessment_runner import run_assessment

        mock_safe_get.return_value = {
            "url": "https://example.com",
            "status_code": 200,
            "headers": {
                "Content-Type": "text/html",
                "X-Frame-Options": "SAMEORIGIN",
            },
            "body": b"<html>Test</html>",
        }

        run_assessment(self.assessment.id)
        self.assessment.refresh_from_db()

        self.assertEqual(self.assessment.status, "COMPLETED")
        self.assertIsNotNone(self.assessment.started_at)
        self.assertIsNotNone(self.assessment.completed_at)
        self.assertIn("Assessment completed", self.assessment.summary)

        self.assertGreater(
            AssessmentFinding.objects.filter(
                assessment=self.assessment
            ).count(),
            0,
        )

        mock_safe_get.assert_called_once_with(self.asset.url)

    @patch("vulnerabilities.assessment_runner.safe_get")
    def test_runner_handles_transport_failure(self, mock_safe_get):
        from .assessment_runner import run_assessment
        from .safe_http import SafeRequestError

        mock_safe_get.side_effect = SafeRequestError(
            "Simulated transport failure."
        )

        with self.assertRaises(SafeRequestError):
            run_assessment(self.assessment.id)

        self.assessment.refresh_from_db()

        self.assertEqual(self.assessment.status, "FAILED")
        self.assertIn(
            "Simulated transport failure",
            self.assessment.error_message,
        )
        self.assertIsNotNone(self.assessment.completed_at)

    @patch("vulnerabilities.assessment_runner.safe_get")
    def test_runner_detects_missing_security_headers(self, mock_safe_get):
        from .assessment_runner import run_assessment

        mock_safe_get.return_value = {
            "url": "https://example.com",
            "status_code": 200,
            "headers": {},
            "body": b"Test response",
        }

        run_assessment(self.assessment.id)

        findings = AssessmentFinding.objects.filter(
            assessment=self.assessment
        )

        self.assertTrue(
            findings.filter(category="Security Headers").exists()
        )

    @patch("vulnerabilities.assessment_runner.safe_get")
    def test_runner_checks_cookie_security(self, mock_safe_get):
        from .assessment_runner import run_assessment

        mock_safe_get.return_value = {
            "url": "https://example.com",
            "status_code": 200,
            "headers": {
                "Set-Cookie": "sessionid=abc123; Path=/",
            },
            "body": b"Test response",
        }

        run_assessment(self.assessment.id)

        findings = AssessmentFinding.objects.filter(
            assessment=self.assessment
        )

        self.assertTrue(
            findings.filter(category__icontains="cookie").exists()
        )
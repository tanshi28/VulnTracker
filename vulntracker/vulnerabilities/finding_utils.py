from .models import AssessmentFinding


def save_findings(assessment, findings):
    """
    Save security observations against an assessment run.

    Args:
        assessment: An AssessmentRun instance.
        findings: A list of finding dictionaries.

    Returns:
        The number of findings created.
    """

    if assessment.status != 'RUNNING':
        raise ValueError(
            "Findings can only be saved for a running assessment."
        )

    created_count = 0

    for finding in findings:
        AssessmentFinding.objects.create(
            assessment=assessment,
            title=finding['title'],
            category=finding['category'],
            severity=finding['severity'],
            description=finding['description'],
            evidence=finding.get('evidence', ''),
            remediation=finding.get('remediation', ''),
        )

        created_count += 1

    return created_count
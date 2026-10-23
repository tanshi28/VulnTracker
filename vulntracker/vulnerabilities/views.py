from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.views.decorators.http import require_http_methods

from .models import (
    Vulnerability,
    AffectedSystem,
    ThreatActor,
    WebAsset,
    AssessmentRun,
    AssessmentFinding,
)


def home(request):
    recent = Vulnerability.objects.select_related(
        'affected_system'
    ).all()[:6]

    critical = Vulnerability.objects.filter(
        severity='C'
    ).select_related('affected_system')[:4]

    return render(request, 'vulnerabilities/home.html', {
        'recent': recent,
        'critical': critical,
        'total_vulns': Vulnerability.objects.count(),
        'open_count': Vulnerability.objects.filter(status='O').count(),
    })


def vuln_list(request):
    vulns = Vulnerability.objects.select_related(
        'affected_system',
        'threat_actor'
    ).all()

    severity = request.GET.get('severity', '')
    status = request.GET.get('status', '')
    search = request.GET.get('q', '').strip()

    if severity in dict(Vulnerability.SEV_CHOICES):
        vulns = vulns.filter(severity=severity)

    if status in dict(Vulnerability.STATUS_CHOICES):
        vulns = vulns.filter(status=status)

    if search:
        from django.db.models import Q

        vulns = vulns.filter(
            Q(cve_id__icontains=search) |
            Q(title__icontains=search) |
            Q(description__icontains=search) |
            Q(affected_system__name__icontains=search)
        )

    return render(request, 'vulnerabilities/vuln_list.html', {
        'vulns': vulns,
        'severity_choices': Vulnerability.SEV_CHOICES,
        'status_choices': Vulnerability.STATUS_CHOICES,
        'selected_severity': severity,
        'selected_status': status,
        'search_query': search,
    })


def vuln_detail(request, slug):
    vuln = get_object_or_404(
        Vulnerability.objects.select_related(
            'affected_system',
            'threat_actor'
        ),
        slug=slug
    )

    return render(request, 'vulnerabilities/vuln_detail.html', {
        'vuln': vuln,
    })


def system_detail(request, slug):
    system = get_object_or_404(AffectedSystem, slug=slug)

    vulns = Vulnerability.objects.filter(
        affected_system=system
    ).select_related('threat_actor')

    return render(request, 'vulnerabilities/system_detail.html', {
        'system': system,
        'vulns': vulns,
    })


def actor_detail(request, slug):
    actor = get_object_or_404(ThreatActor, slug=slug)

    vulns = Vulnerability.objects.filter(
        threat_actor=actor
    ).select_related('affected_system')

    return render(request, 'vulnerabilities/actor_detail.html', {
        'actor': actor,
        'vulns': vulns,
    })


def by_severity(request, level):
    severity_map = {
        'critical': 'C',
        'high': 'H',
        'medium': 'M',
        'low': 'L',
    }

    severity_code = severity_map.get(level.lower())

    if severity_code is None:
        from django.http import Http404
        raise Http404("Unknown severity level")

    vulns = Vulnerability.objects.filter(
        severity=severity_code
    ).select_related('affected_system')

    return render(request, 'vulnerabilities/by_severity.html', {
        'vulns': vulns,
        'level': level.lower(),
    })


def open_vulns(request):
    vulns = Vulnerability.objects.filter(
        status='O'
    ).select_related('affected_system')

    return render(
        request,
        'vulnerabilities/open_vulns.html',
        {'vulns': vulns}
    )


def dashboard(request):
    return render(request, 'vulnerabilities/dashboard.html', {
        'total_vulns': Vulnerability.objects.count(),
        'total_systems': AffectedSystem.objects.count(),
        'total_actors': ThreatActor.objects.count(),

        'critical_count': Vulnerability.objects.filter(
            severity='C'
        ).count(),

        'high_count': Vulnerability.objects.filter(
            severity='H'
        ).count(),

        'medium_count': Vulnerability.objects.filter(
            severity='M'
        ).count(),

        'low_count': Vulnerability.objects.filter(
            severity='L'
        ).count(),

        'open_count': Vulnerability.objects.filter(
            status='O'
        ).count(),

        'in_progress_count': Vulnerability.objects.filter(
            status='IP'
        ).count(),

        'patched_count': Vulnerability.objects.filter(
            status='P'
        ).count(),
    })


def asset_list(request):
    assets = WebAsset.objects.all()

    return render(request, 'vulnerabilities/asset_list.html', {
        'assets': assets,
        'total_assets': assets.count(),
        'active_assets': assets.filter(is_active=True).count(),
        'authorized_assets': assets.filter(
            is_authorized=True,
            is_active=True
        ).count(),
    })


@require_http_methods(['GET', 'POST'])
def asset_create(request):
    if request.method == 'POST':
        name = request.POST.get('name', '').strip()
        url = request.POST.get('url', '').strip()
        description = request.POST.get('description', '').strip()
        authorization_confirmed = (
            request.POST.get('authorization_confirmed') == 'on'
        )

        if not name or not url:
            messages.error(request, 'Name and URL are required.')

        elif not authorization_confirmed:
            messages.error(
                request,
                'Confirm that you have permission to assess this website.'
            )

        else:
            from django.core.exceptions import ValidationError
            from django.core.validators import URLValidator

            validator = URLValidator(schemes=['http', 'https'])

            try:
                validator(url)
            except ValidationError:
                messages.error(
                    request,
                    'Enter a valid HTTP or HTTPS URL.'
                )
            else:
                if WebAsset.objects.filter(url=url).exists():
                    messages.error(
                        request,
                        'This URL is already registered.'
                    )
                else:
                    WebAsset.objects.create(
                        name=name,
                        url=url,
                        description=description,
                        is_authorized=True,
                    )

                    messages.success(
                        request,
                        'Web asset registered successfully.'
                    )

                    return redirect('asset-list')

    return render(request, 'vulnerabilities/asset_create.html')

@require_http_methods(['POST'])
def start_assessment(request, asset_id):
    asset = get_object_or_404(
        WebAsset,
        id=asset_id,
        is_active=True,
        is_authorized=True,
    )

    assessment = AssessmentRun.objects.create(
        asset=asset,
        status='PENDING',
        summary='Assessment created and waiting to be run.',
    )

    messages.success(
        request,
        f'Assessment #{assessment.id} has been created and is pending execution.'
    )

    return redirect(
        'assessment-detail',
        assessment_id=assessment.id
    )

def assessment_list(request):
    assessments = AssessmentRun.objects.select_related(
        'asset'
    ).prefetch_related(
        'findings'
    ).order_by('-created_at')

    return render(
        request,
        'vulnerabilities/assessment_list.html',
        {
            'assessments': assessments,
            'total_assessments': assessments.count(),
            'completed_count': assessments.filter(
                status='COMPLETED'
            ).count(),
            'running_count': assessments.filter(
                status='RUNNING'
            ).count(),
            'failed_count': assessments.filter(
                status='FAILED'
            ).count(),
        }
    )


def assessment_detail(request, assessment_id):
    assessment = get_object_or_404(
        AssessmentRun.objects.select_related(
            'asset'
        ).prefetch_related('findings'),
        id=assessment_id,
    )

    findings = assessment.findings.all().order_by(
        '-first_seen'
    )

    severity_counts = {
        severity: findings.filter(severity=severity).count()
        for severity, _ in AssessmentFinding.SEVERITY_CHOICES
    }

    return render(
        request,
        'vulnerabilities/assessment_detail.html',
        {
            'assessment': assessment,
            'findings': findings,
            'severity_counts': severity_counts,
            'total_findings': findings.count(),
        }
    )
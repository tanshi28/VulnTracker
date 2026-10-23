from django.db import models
from django.core.validators import URLValidator


class AffectedSystem(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class ThreatActor(models.Model):
    name = models.CharField(max_length=100)
    slug = models.SlugField(unique=True)
    origin = models.CharField(max_length=80)
    description = models.TextField()

    def __str__(self):
        return self.name

    class Meta:
        ordering = ['name']


class Vulnerability(models.Model):
    SEV_CHOICES = [
        ('C', 'Critical'),
        ('H', 'High'),
        ('M', 'Medium'),
        ('L', 'Low'),
    ]

    STATUS_CHOICES = [
        ('O', 'Open'),
        ('IP', 'In-Progress'),
        ('P', 'Patched'),
    ]

    cve_id = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=200)
    slug = models.SlugField(unique=True)
    description = models.TextField()
    remediation = models.TextField()

    affected_system = models.ForeignKey(
        AffectedSystem,
        on_delete=models.CASCADE,
        related_name='vulnerabilities'
    )

    severity = models.CharField(
        max_length=1,
        choices=SEV_CHOICES,
        default='M'
    )

    status = models.CharField(
        max_length=2,
        choices=STATUS_CHOICES,
        default='O'
    )

    discovered = models.DateTimeField(auto_now_add=True)

    threat_actor = models.ForeignKey(
        ThreatActor,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='vulnerabilities'
    )

    def __str__(self):
        return self.cve_id

    class Meta:
        ordering = ['-discovered']
        verbose_name_plural = 'Vulnerabilities'


class WebAsset(models.Model):
    name = models.CharField(max_length=100)
    url = models.URLField(
        max_length=500,
        validators=[URLValidator(schemes=['http', 'https'])]
    )
    description = models.TextField(blank=True)

    is_authorized = models.BooleanField(
        default=False,
        help_text='Enable only after confirming permission to assess this asset.'
    )

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.name} ({self.url})'

    class Meta:
        ordering = ['name']
        verbose_name = 'Web Asset'
        verbose_name_plural = 'Web Assets'


class AssessmentRun(models.Model):
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('RUNNING', 'Running'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
    ]

    asset = models.ForeignKey(
        WebAsset,
        on_delete=models.CASCADE,
        related_name='assessments'
    )

    status = models.CharField(
        max_length=10,
        choices=STATUS_CHOICES,
        default='PENDING'
    )

    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    summary = models.TextField(blank=True)
    error_message = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f'Assessment #{self.pk} - {self.asset.name}'

    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Assessment Run'
        verbose_name_plural = 'Assessment Runs'


class AssessmentFinding(models.Model):
    SEVERITY_CHOICES = [
        ('INFO', 'Informational'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('IN_PROGRESS', 'In Progress'),
        ('RESOLVED', 'Resolved'),
        ('ACCEPTED', 'Risk Accepted'),
    ]

    assessment = models.ForeignKey(
        AssessmentRun,
        on_delete=models.CASCADE,
        related_name='findings'
    )

    title = models.CharField(max_length=200)
    category = models.CharField(max_length=100)
    severity = models.CharField(
        max_length=10,
        choices=SEVERITY_CHOICES,
        default='INFO'
    )

    description = models.TextField()
    evidence = models.TextField(blank=True)
    remediation = models.TextField(blank=True)

    status = models.CharField(
        max_length=12,
        choices=STATUS_CHOICES,
        default='OPEN'
    )

    first_seen = models.DateTimeField(auto_now_add=True)
    last_updated = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f'{self.title} - {self.get_severity_display()}'

    class Meta:
        ordering = ['-first_seen']
        verbose_name = 'Assessment Finding'
        verbose_name_plural = 'Assessment Findings'
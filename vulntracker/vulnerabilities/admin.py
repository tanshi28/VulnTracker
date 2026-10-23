from django.contrib import admin

from .models import (
    AffectedSystem,
    ThreatActor,
    Vulnerability,
    WebAsset,
    AssessmentRun,
    AssessmentFinding,
)


@admin.register(AffectedSystem)
class AffectedSystemAdmin(admin.ModelAdmin):
    list_display = ['name', 'slug']
    search_fields = ['name']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['name']


@admin.register(ThreatActor)
class ThreatActorAdmin(admin.ModelAdmin):
    list_display = ['name', 'origin', 'slug']
    list_filter = ['origin']
    search_fields = ['name', 'origin', 'description']
    prepopulated_fields = {'slug': ('name',)}
    ordering = ['name']


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = [
        'cve_id',
        'title',
        'severity',
        'status',
        'affected_system',
        'threat_actor',
        'discovered',
    ]

    list_filter = [
        'severity',
        'status',
        'affected_system',
        'discovered',
    ]

    search_fields = [
        'cve_id',
        'title',
        'description',
        'remediation',
        'affected_system__name',
        'threat_actor__name',
    ]

    prepopulated_fields = {'slug': ('title',)}
    readonly_fields = ['discovered']
    list_select_related = ['affected_system', 'threat_actor']
    date_hierarchy = 'discovered'
    ordering = ['-discovered']
    list_per_page = 25


@admin.register(WebAsset)
class WebAssetAdmin(admin.ModelAdmin):
    list_display = [
        'name',
        'url',
        'is_authorized',
        'is_active',
        'created_at',
    ]

    list_filter = ['is_authorized', 'is_active', 'created_at']

    search_fields = ['name', 'url', 'description']

    readonly_fields = ['created_at', 'updated_at']

    list_editable = ['is_authorized', 'is_active']

    ordering = ['name']
    list_per_page = 25


class AssessmentFindingInline(admin.TabularInline):
    model = AssessmentFinding
    extra = 0
    show_change_link = True


@admin.register(AssessmentRun)
class AssessmentRunAdmin(admin.ModelAdmin):
    list_display = [
        'id',
        'asset',
        'status',
        'started_at',
        'completed_at',
        'created_at',
    ]

    list_filter = ['status', 'created_at']

    search_fields = ['asset__name', 'asset__url', 'summary']

    readonly_fields = [
        'started_at',
        'completed_at',
        'created_at',
    ]

    list_select_related = ['asset']
    inlines = [AssessmentFindingInline]
    ordering = ['-created_at']
    list_per_page = 25


@admin.register(AssessmentFinding)
class AssessmentFindingAdmin(admin.ModelAdmin):
    list_display = [
        'title',
        'category',
        'severity',
        'status',
        'assessment',
        'first_seen',
    ]

    list_filter = [
        'severity',
        'status',
        'category',
        'first_seen',
    ]

    search_fields = [
        'title',
        'category',
        'description',
        'evidence',
        'assessment__asset__name',
    ]

    readonly_fields = ['first_seen', 'last_updated']

    list_select_related = ['assessment', 'assessment__asset']
    ordering = ['-first_seen']
    list_per_page = 25
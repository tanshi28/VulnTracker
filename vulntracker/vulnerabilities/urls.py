from django.urls import path
from . import views

urlpatterns = [
    # Main pages
    path('', views.home, name='home'),
    path('dashboard/', views.dashboard, name='dashboard'),

    # Vulnerability management
    path('vulnerabilities/', views.vuln_list, name='vuln-list'),
    path(
        'vulnerabilities/<slug:slug>/',
        views.vuln_detail,
        name='vuln-detail'
    ),
    path('system/<slug:slug>/', views.system_detail, name='system-detail'),
    path('actor/<slug:slug>/', views.actor_detail, name='actor-detail'),
    path('severity/<str:level>/', views.by_severity, name='by-severity'),
    path('status/open/', views.open_vulns, name='open-vulns'),

    # Web asset management
    path('assets/', views.asset_list, name='asset-list'),
    path('assets/add/', views.asset_create, name='asset-create'),

    path('assets/<int:asset_id>/assess/',views.start_assessment,name='start-assessment'),

    # Security assessments
    path('assessments/', views.assessment_list, name='assessment-list'),
    path(
        'assessments/<int:assessment_id>/',
        views.assessment_detail,
        name='assessment-detail'
    ),
]
"""Dashboard URL configuration."""

from __future__ import annotations

from django.urls import path

from aisec.dashboard import views

app_name = "dashboard"

urlpatterns = [
    # Pages
    path("", views.home, name="home"),
    path("scans/", views.scan_list, name="scan-list"),
    path("scans/<str:scan_id>/", views.scan_detail, name="scan-detail"),
    path("findings/", views.findings_explorer, name="findings"),
    path("trends/", views.trends, name="trends"),
    path("policies/", views.policies, name="policies"),
    path("new-scan/", views.new_scan, name="new-scan"),
    # HTMX partials
    path("partials/scan-table/", views.partial_scan_table, name="partial-scan-table"),
    path("partials/scan-status/<str:scan_id>/", views.partial_scan_status, name="partial-scan-status"),
    path("partials/finding-rows/", views.partial_finding_rows, name="partial-finding-rows"),
]

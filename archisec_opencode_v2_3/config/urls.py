from django.urls import path
from core import views

urlpatterns = [
    path("", views.home, name="home"),
    path("profile/", views.profile, name="profile"),
    path("profile/analyze/", views.profile_analyze, name="profile_analyze"),
    path("api/threats/", views.catalog("threats"), name="api_threats"),
    path("api/threats/<str:code>/", views.catalog_detail("threats"), name="api_threat_detail"),
    path("api/measures/", views.catalog("measures"), name="api_measures"),
    path("api/tools/", views.catalog("tools"), name="api_tools"),
    path("api/tactics/", views.catalog("tactics"), name="api_tactics"),
    path("api/ai-threats/", views.catalog("ai_threats"), name="api_ai_threats"),
    path("api/levels/", views.catalog("levels"), name="api_levels"),
    path("api/profile/analyze/", views.api_profile_analyze, name="api_profile_analyze"),
]

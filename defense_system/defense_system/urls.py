
from django.contrib import admin
from django.urls import path
from attacks import views as attack_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('dashboard/', attack_views.dashboard, name='dashboard'),  # Clean version
    path('logs/', attack_views.logs_view, name='logs'),
    path('alerts/', attack_views.alerts_view, name='alerts'),
    path('settings/', attack_views.settings_view, name='settings'),
    path('analytics/', attack_views.analytics_view, name='analytics'),
    path('api/attacks/', attack_views.get_attacks, name='get_attacks'),
    path('api/trend/', attack_views.get_trend_data, name='get_trend_data'),
    path('', attack_views.custom_login, name='login'),  # Login at root
    path('logout/', attack_views.custom_logout, name='logout'),
    path('api/analytics_summary/', attack_views.get_analytics_summary, name='get_analytics_summary'),
    path('settings/send-test/', attack_views.send_test_alert, name='send_test_alert'),
    path('settings/send-summary/', attack_views.send_summary_email, name='send_summary_email'),


]

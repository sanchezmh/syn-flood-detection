from django.contrib import admin
from django.urls import path
from attacks import views as attack_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', attack_views.dashboard, name='dashboard2'),  # dashboard is main page
    path('dashboard2/', attack_views.dashboard, name='dashboard'),
    path('logs/', attack_views.logs_view, name='logs'),
    path('alerts/', attack_views.alerts_view, name='alerts'),
    path('settings/', attack_views.settings_view, name='settings'),
    path('analytics/', attack_views.analytics_view, name='analytics'),
    path('api/attacks/', attack_views.get_attacks, name='get_attacks'),
    path('api/trend/', attack_views.get_trend_data, name='get_trend_data'),
    path('login/', attack_views.custom_login, name='login'),
    path('logout/', attack_views.custom_logout, name='logout'),
]

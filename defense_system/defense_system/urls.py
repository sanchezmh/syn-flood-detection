"""
URL configuration for defense_system project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
'''from django.contrib import admin
from django.urls import path

urlpatterns = [
    path('admin/', admin.site.urls),
]
'''
# defense_system/urls.py
from django.contrib import admin
from django.urls import path
from attacks import views as attack_views
from django.shortcuts import redirect
from django.contrib.auth.views import LogoutView


urlpatterns = [
    #path('', lambda request: redirect('dashboard')), 
    path('admin/', admin.site.urls),
    path('dashboard/', attack_views.dashboard, name='dashboard'),
    path('api/attacks/', attack_views.get_attacks, name='get_attacks'),
    path('login/', attack_views.custom_login, name='login'),  
    #path('logout/', LogoutView.as_view(next_page='login'), name='logout'),
    path('logout/', attack_views.custom_logout, name='logout'), 
]

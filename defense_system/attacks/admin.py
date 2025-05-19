from django.contrib import admin

# Register your models here.

from .models import AttackLog

admin.site.register(AttackLog)

from django.contrib import admin

# Register your models here.

from .models import AttackLog, AttackCounter

admin.site.register(AttackLog)
admin.site.register(AttackCounter)


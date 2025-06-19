from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect, JsonResponse
from django.core.paginator import Paginator
from django.core.mail import send_mail
from django.conf import settings
from django.db.models.functions import TruncMinute
from django.db.models import Count
from .models import AttackLog

# Main dashboard page
@login_required
def dashboard(request):
    return render(request, 'attacks/dashboard2.html')

# API endpoint for fetching attacks as JSON
@login_required
def get_attacks(request):
    attacks = AttackLog.objects.all().order_by('-timestamp')[:10]
    data = [
        {
            'timestamp': attack.timestamp.isoformat(),
            'source_ip': attack.source_ip,
            'status': attack.status,
            'score': attack.score,
            'risk': (
                'High' if attack.score > 0.5 else
                'Medium' if attack.score == 0.5 else
                'Low')
        }
        for attack in attacks
    ]
    return JsonResponse({'attacks': data})

# Login
def custom_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')
        else:
            return render(request, 'attacks/login.html', {'error': 'Invalid username or password'})
    return render(request, 'attacks/login.html')

# Logout
def custom_logout(request):
    logout(request)
    return HttpResponseRedirect('/login/')

# Email alert
def send_attack_email(total_count):
    send_mail(
        subject='🔥 SYN Flood Alert: New Attacks Blocked',
        message=f'A total of {total_count} SYN flood attacks have been blocked so far.',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=['mhemberesanchez@gmail.com'],
        fail_silently=False,
    )

# Logs view
@login_required
def logs_view(request):
    logs = AttackLog.objects.all().order_by('-timestamp')
    paginator = Paginator(logs, 25)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, 'attacks/logs.html', {'logs': page_obj})

# Alerts view
@login_required
def alerts_view(request):
    alerts = AttackLog.objects.filter(status='malicious').order_by('-timestamp')[:10]
    return render(request, 'attacks/alerts.html', {'alerts': alerts})

# Settings view
@login_required
def settings_view(request):
    return render(request, 'attacks/settings.html')

# Analytics view
@login_required
def analytics_view(request):
    return render(request, 'attacks/analytics.html')

# API trend data
@login_required
def get_trend_data(request):
    data = (
        AttackLog.objects
        .annotate(minute=TruncMinute('timestamp'))
        .values('minute', 'status')
        .annotate(count=Count('id'))
        .order_by('minute')
    )

    timeline = {}
    for entry in data:
        ts = entry['minute'].strftime('%H:%M')
        status = entry['status'].lower()
        if ts not in timeline:
            timeline[ts] = {'malicious': 0, 'benign': 0}
        timeline[ts][status] = entry['count']

    sorted_timeline = sorted(timeline.items())
    labels = [t[0] for t in sorted_timeline]
    mal_data = [t[1]['malicious'] for t in sorted_timeline]
    ben_data = [t[1]['benign'] for t in sorted_timeline]

    return JsonResponse({
        'labels': labels,
        'malicious': mal_data,
        'benign': ben_data,
    })

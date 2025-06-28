
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

# Dashboard
@login_required
def dashboard(request):
    return render(request, 'attacks/dashboard2.html')

# API endpoint for fetching attacks
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
            return redirect('dashboard')  # Go to dashboard after login
        else:
            return render(request, 'attacks/login.html', {'error': 'Invalid username or password'})
    return render(request, 'attacks/login.html')

# Logout
def custom_logout(request):
    logout(request)
    return redirect('login')  # Go back to login after logout

# Email alert
def send_attack_email(total_count):
    send_mail(
        subject='SYN Flood Alert: New Attacks Blocked',
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
    critical_alerts = AttackLog.objects.filter(status='malicious', score__gt=0.5).order_by('-timestamp')
    paginator = Paginator(critical_alerts, 10)
    page_number = request.GET.get("page")
    page_obj = paginator.get_page(page_number)
    return render(request, 'attacks/alerts.html', {'alerts': page_obj})



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


@login_required
def get_analytics_summary(request):
    total = AttackLog.objects.count()
    malicious = AttackLog.objects.filter(status__iexact='malicious').count()
    benign = total - malicious

    risk_counts = (
        AttackLog.objects
        .exclude(score__isnull=True)
        .values('score')
        .annotate(count=Count('id'))
    )
    ip_counts = (
        AttackLog.objects
        .values('source_ip')
        .annotate(count=Count('id'))
        .order_by('-count')[:5]
    )

    risk_levels = {'High': 0, 'Medium': 0, 'Low': 0}
    for r in risk_counts:
        score = r['score']
        if score > 0.5:
            risk_levels['High'] += r['count']
        elif score == 0.5:
            risk_levels['Medium'] += r['count']
        else:
            risk_levels['Low'] += r['count']

    return JsonResponse({
        'total': total,
        'malicious_pct': (malicious / total * 100) if total else 0,
        'benign_pct': (benign / total * 100) if total else 0,
        'risk_levels': risk_levels,
        'top_ips': list(ip_counts),
    })


#SETTINGS BELOW PAY ATTENTION
from django.utils.timezone import now
import random
from django.views.decorators.csrf import csrf_exempt

SECURITY_TIPS = [
    "Use strong admin passwords and rotate them regularly.",
    "Monitor blocked IPs to identify persistent attackers.",
    "Set email alert thresholds based on your traffic baseline.",
    "Keep this system's dependencies updated.",
    "Enable two-factor authentication for admin access.",
]

@login_required
def settings_view(request):
    context = {
        'last_update': now().strftime("%Y-%m-%d %H:%M"),
        'threshold': 0.5,
        'email_status': 'Enabled',
        'autoblock_status': 'Enabled',
        'total_attacks': AttackLog.objects.count(),
        'security_tip': random.choice(SECURITY_TIPS),
    }
    return render(request, 'attacks/settings.html', context)

@login_required
@csrf_exempt
def send_test_alert(request):
    if request.method == "POST":
        send_mail(
            subject='[Test] SYN Flood Alert System',
            message='This is a test alert from your detection system.',
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=['mhemberesanchez@gmail.com'],  # <- Update this
            fail_silently=False,
        )
    return redirect('settings')

@login_required
@csrf_exempt
def send_summary_email(request):
    if request.method == "POST":
        total = AttackLog.objects.count()
        send_attack_email(total)
    return redirect('settings')

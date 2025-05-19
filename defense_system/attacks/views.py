from django.shortcuts import render
from django.contrib.auth import authenticate, login
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.views.generic.base import RedirectView
from django.contrib.auth import logout
from django.http import HttpResponseRedirect

# Create your views here.
# attacks/views.py
from django.http import JsonResponse
from .models import AttackLog

@login_required
def dashboard(request):
    return render(request, 'attacks/dashboard.html')

# Main dashboard page
def dashboard(request):
    return render(request, 'attacks/dashboard.html')


# API endpoint for fetching attacks as JSON
def get_attacks(request):
    attacks = AttackLog.objects.all().order_by('-timestamp')[:50]  # Get last 50 attacks
    data = [
        {
            'timestamp': attack.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            'source_ip': attack.source_ip,
            'status': attack.status,
        }
        for attack in attacks
    ]
    return JsonResponse({'attacks': data})

def custom_login(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('dashboard')  # 👈 make sure this matches your dashboard route name
        else:
            return render(request, 'attacks/login.html', {'error': 'Invalid username or password'})
    return render(request, 'attacks/login.html')
from django.views.generic.base import RedirectView
from django.contrib.auth import logout
from django.http import HttpResponseRedirect

# Replace LogoutView with this simple custom redirect:
def custom_logout(request):
    logout(request)
    return HttpResponseRedirect('/login/')


from django.core.mail import send_mail
from django.conf import settings

def send_attack_email(total_count):
    send_mail(
        subject='🔥 SYN Flood Alert: 50 New Attacks Blocked',
        message=f'A total of {total_count} SYN flood attacks have been blocked so far.',
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=['mhemberesanchez@gmail.com'],  # Replace with your address
        fail_silently=False,
    )

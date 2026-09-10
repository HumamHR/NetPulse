# sniffapp/urls.py
from django.urls import path
from . import views

urlpatterns = [
    path('sniff/', views.sniff_page, name='sniff_page'),
    path('analyze_live/', views.analyze_live_capture, name='analyze_live_capture'),
    path('dashboard/', views.live_dashboard, name='live_dashboard'),
    path('analysis-success/<str:cache_key>/', views.live_analysis_handler, name='live_analysis_handler'),
    
    # --- NEW: WAF ALERT WEBHOOK ---
    path('waf-alert/', views.waf_alert_webhook, name='waf_alert'),
]
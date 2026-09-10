from django.urls import path, include
from . import views
from django.conf import settings
from django.conf.urls.static import static
from .views import download_malformed_pcap, view_report
from .views import download_report
from .views import upload_progress
from .views import download_malicious_pcap
from django.contrib import admin


urlpatterns = [
    
    path( '' , views.index , name='index' ),
    path( 'login/' , views.login , name='login' ),
    path('ip_info/', views.ipinfo, name='ip_info'),
    path("port_scan/", views.port_scan, name="port_scan"),
    path("upload/", views.upload, name="upload"),
    path("pcap_results/", views.pcap_results, name="pcap_results"),
    #path('analyze/', views.pcap_analysis, name='pcap_analysis'),
    path('download/', views.download_file, name='download_file'),
    path('view-report/', view_report, name='view_report'),
    path('download-report/', download_report, name='download_report'),
    path('virus_total/', views.virus_total, name='virus_total'),
    path('upload_progress/', views.upload_progress, name='upload_progress'),
    path('ip_analysis/', views.ip_analysis, name='ip_analysis'),
    path('download-malicious/', download_malicious_pcap, name='download_malicious_pcap'),
    path('download_malformed_pcap/', download_malformed_pcap, name='download_malformed_pcap'),
    path('email-analysis/', views.EmailAnalysisView.as_view(), name='email_analysis'),
    path('analyze-email-headers/', views.analyze_email_headers, name='analyze_email_headers'),
    path('macro_identifier/', views.macro_identifier, name='macro_identifier'),
    path('generate-report/', views.generate_report_view, name='generate_report'),
    path('powershell_analyzer/', views.powershell_analyzer_view, name='powershell_analyzer'),
 
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
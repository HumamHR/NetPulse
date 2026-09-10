from django.db import models

# Create your models here.
from django.db import models
from django.contrib.auth.models import User

class PacketCapture(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True)
    name = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    interface = models.CharField(max_length=100, default='any')
    filter_expression = models.CharField(max_length=500, blank=True)
    packet_count = models.IntegerField(default=0)
    capture_duration = models.IntegerField(default=60)  # seconds
    created_at = models.DateTimeField(auto_now_add=True)
    pcap_file = models.FileField(upload_to='pcaps/', null=True, blank=True)
    
    STATUS_CHOICES = [
        ('stopped', 'Stopped'),
        ('running', 'Running'),
        ('paused', 'Paused'),
    ]
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='stopped')
    
    def __str__(self):
        return f"{self.name} - {self.status}"

class Packet(models.Model):
    capture = models.ForeignKey(PacketCapture, on_delete=models.CASCADE, related_name='packets')
    timestamp = models.DateTimeField()
    source_ip = models.GenericIPAddressField(null=True, blank=True)
    destination_ip = models.GenericIPAddressField(null=True, blank=True)
    source_port = models.IntegerField(null=True, blank=True)
    destination_port = models.IntegerField(null=True, blank=True)
    protocol = models.CharField(max_length=20)
    length = models.IntegerField()
    summary = models.TextField()
    raw_data = models.BinaryField(null=True, blank=True)
    hex_dump = models.TextField(blank=True)
    
    # Protocol specific fields
    tcp_flags = models.CharField(max_length=50, blank=True)
    http_method = models.CharField(max_length=10, blank=True)
    http_url = models.TextField(blank=True)
    dns_query = models.CharField(max_length=255, blank=True)
    
    class Meta:
        ordering = ['-timestamp']
    
    def __str__(self):
        return f"{self.protocol}: {self.source_ip}:{self.source_port} -> {self.destination_ip}:{self.destination_port}"
from django.urls import re_path
from .consumers import SnifferConsumer

websocket_urlpatterns = [
    re_path(r'ws/sniff/$', SnifferConsumer.as_asgi()),
]

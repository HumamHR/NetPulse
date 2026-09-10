from django.test import TestCase

# Create your tests here.

import threading
import time  # Added for throttling
from threading import Lock
from scapy.all import AsyncSniffer, wrpcap, Packet
from scapy.layers.inet import IP
from scapy.layers.l2 import Ether
from datetime import datetime
from django.conf import settings
from asgiref.sync import async_to_sync

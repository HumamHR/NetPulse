# sniffapp/sniffer.py
import threading
import time
import os
import requests
import socket
import whois
import geoip2.database
import re
import traceback
from threading import Lock
from scapy.all import AsyncSniffer, wrpcap, Packet
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether
from datetime import datetime
from django.conf import settings
from django.core.cache import cache
from asgiref.sync import async_to_sync

# --- IMPORTS ---
from pages.utils.malicious_detector import parse_rules, check_packet
from pages.utils.abuse_checker import check_abuseipdb

# --- CONFIGURATION ---
# SECURITY: Key and Path loaded from settings
RAPIDAPI_KEY = settings.RAPIDAPI_KEY
RAPIDAPI_HOST = "pointsdb-bulk-whois-v1.p.rapidapi.com"
SNORT_LOG_PATH = settings.SNORT_LOG_PATH

# --- Global State ---
_packets = []
_sniffer_instance = None 
_lock = Lock()
_last_update_time = 0
_rules = []             
_geo_reader = None
_ip_reputation_cache = {} 
_pending_geo = []
_waf_alerts = [] 

# Monitor Thread Globals
_snort_thread = None
_snort_running = False

SNIFF_GROUP_NAME = 'sniff_group'

def add_waf_alert(alert_data):
    global _waf_alerts
    with _lock:
        _waf_alerts.append(alert_data)

def get_and_clear_waf_alerts():
    global _waf_alerts
    with _lock:
        alerts = list(_waf_alerts)
        _waf_alerts.clear()
    return alerts

# --- MONITORING FUNCTIONS (Suricata/Snort) ---
def monitor_snort_alerts():
    global _snort_running
    print(f"[IDS] Starting Suricata log monitor for: {SNORT_LOG_PATH}")
    
    retries = 0
    while _snort_running and not os.path.exists(SNORT_LOG_PATH):
        time.sleep(1)
        retries += 1
        print(f"[IDS] Waiting for fast.log to be created... ({retries}s)")
        if retries > 10: 
            try: 
                open(SNORT_LOG_PATH, 'a').close()
                print(f"[IDS] Created fast.log at {SNORT_LOG_PATH}")
            except Exception as e:
                print(f"[IDS] Failed to create fast.log: {e}")

    if not _snort_running: 
        return

    print(f"[IDS] Successfully monitoring fast.log for alerts")
    
    try:
        with open(SNORT_LOG_PATH, 'r') as f:
            f.seek(0, os.SEEK_END)
            while _snort_running:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                if line.strip():
                    print(f"[IDS] New alert detected: {line[:150].strip()}")
                    process_snort_alert(line)
    except Exception as e:
        print(f"[IDS] Error reading Suricata/Snort logs: {e}")
        traceback.print_exc()

def process_snort_alert(raw_line):
    try:
        pattern = r'\[\*\*\] \[\d+:(\d+):\d+\] (.*?) \[\*\*\] .*? \{(.*?)\} (\d+\.\d+\.\d+\.\d+)(?::(\d+))? -> (\d+\.\d+\.\d+\.\d+)(?::(\d+))?'
        match = re.search(pattern, raw_line)
        if match:
            sid = match.group(1)
            msg = match.group(2).strip('"')
            proto = match.group(3)
            src_ip = match.group(4)
            src_port = match.group(5) if match.group(5) else 'unknown'
            dst_ip = match.group(6)
            dst_port = match.group(7) if match.group(7) else 'unknown'
            
            print(f"[IDS] Parsed Alert - SID: {sid}, Message: {msg}, Src: {src_ip}, Dst: {dst_ip}")
            
            # Skip ICMP test alerts if they're just noise
            is_test_ping = sid == '999999' and 'ICMP Ping' in msg
            
            threat_payload = {
                'msg': f"[IDS] {msg}",
                'sid': sid,
                'payload': raw_line[:500]  # Include raw alert as payload
            }
            
            # Get geo and reputation data
            geo_info = _get_geo_info(src_ip)
            reputation = _get_ip_reputation(src_ip)
            
            # Build the WebSocket message
            ws_message = {
                'type': 'packet.message',
                'summary': f"IDS Alert: {msg}",
                'src': src_ip,
                'dst': dst_ip,
                'proto': proto,
                'timestamp': datetime.now().isoformat(),
                'severity': 'HIGH' if not is_test_ping else 'INFO',
                'threat': threat_payload,
                'geo_src': geo_info,
                'reputation': reputation,
                'url': f"Suricata IDS Detection",
                'method': 'ALERT',
                'host': dst_ip,
                'direction': 'inbound'
            }
            
            # Send to WebSocket for live dashboard
            if hasattr(settings, 'CHANNEL_LAYER') and settings.CHANNEL_LAYER:
                try:
                    async_to_sync(settings.CHANNEL_LAYER.group_send)(
                        SNIFF_GROUP_NAME, 
                        ws_message
                    )
                    print(f"[IDS] ✅ Alert sent to live dashboard")
                except Exception as e:
                    print(f"[IDS] ❌ WebSocket send error: {e}")
                    traceback.print_exc()
            else:
                print("[IDS] ⚠️ CHANNEL_LAYER not available")
            
            # Also store for post-analysis
            add_waf_alert({
                'msg': f"[IDS] {msg}",
                'sid': sid,
                'payload': raw_line[:500],
                'severity': 'HIGH' if not is_test_ping else 'INFO',
                'src': src_ip,
                'dst': dst_ip,
                'proto': proto
            })
        else:
            print(f"[IDS] Could not parse alert line: {raw_line[:100]}")
            
    except Exception as e:
        print(f"[IDS] Parse Error: {e}")
        traceback.print_exc()

# --- HELPERS ---
def _get_geo_info(ip_addr):
    global _geo_reader
    if not _geo_reader or not ip_addr: return None
    if ip_addr.startswith(('192.168.', '10.', '127.', '172.', '0.')): return None
    try:
        response = _geo_reader.city(ip_addr)
        return {
            'city': response.city.name or "Unknown",
            'country': response.country.name or "Unknown",
            'lat': response.location.latitude,
            'lon': response.location.longitude
        }
    except: return None

def get_rdap_date(ip_addr):
    """
    Fetches the registration date from RDAP (Regional Internet Registry).
    """
    try:
        # ARIN is a good default entry point; it often redirects to RIPE/APNIC/etc.
        response = requests.get(f"https://rdap.arin.net/registry/ip/{ip_addr}", timeout=2)
        if response.status_code == 200:
            data = response.json()
            for event in data.get('events', []):
                # Look for registration or allocation events
                if event.get('eventAction') in ['registration', 'allocation', 'last changed']:
                    return event.get('eventDate', '')[:10]
    except: pass
    return None

def _get_ip_reputation(ip_addr):
    global _ip_reputation_cache
    # Skip private IPs
    if not ip_addr or ip_addr.startswith(('192.168.', '10.', '127.', '172.', '0.', '224.', '240.', 'fe80:', '::1')): 
        return None
    
    if ip_addr in _ip_reputation_cache: 
        return _ip_reputation_cache[ip_addr]

    result = {
        'ip': ip_addr, 
        'org': 'Unknown', 
        'abuse_score': 0, 
        'is_safe': True, 
        'reports': [], 
        'whois': {'registrar': 'Unknown', 'creation_date': 'Unknown', 'emails': 'Unknown'}
    }

    # 1. AbuseIPDB (Score & ISP)
    try:
        abuse_response = check_abuseipdb([ip_addr])
        if isinstance(abuse_response, dict):
            for item in abuse_response.get('scanned', []):
                if item.get('ip') == ip_addr:
                    result['abuse_score'] = item.get('score', 0)
                    if result['abuse_score'] > 0: result['is_safe'] = False
                    if item.get('isp'): result['org'] = item['isp']
                    result['reports'] = item.get('reports', [])
                    break
    except: pass

    # 2. Basic Org Fallback
    if result['org'] == 'Unknown':
        try:
            r = requests.get(f"http://ip-api.com/json/{ip_addr}?fields=org,isp", timeout=1.5)
            if r.status_code == 200:
                d = r.json()
                result['org'] = d.get('org') or d.get('isp') or "Unknown"
        except: pass

    # 3. WHOIS / RDAP Data (Fix for "Unknown" Columns)
    
    # Method A: RapidAPI (PointsDB) - Best accuracy if key is valid
    api_success = False
    if RAPIDAPI_KEY:
        try:
            url = f"https://{RAPIDAPI_HOST}/api/v1"
            headers = {
                "X-RapidAPI-Key": RAPIDAPI_KEY,
                "X-RapidAPI-Host": RAPIDAPI_HOST
            }
            # Some APIs use 'ip' or 'domain' params. Attempting query.
            response = requests.get(url, headers=headers, params={"ip": ip_addr}, timeout=2)
            
            if response.status_code == 200:
                data = response.json()
                # Try to extract fields based on common API responses
                reg = data.get('registrar_name') or data.get('registrar')
                date = data.get('creation_date') or data.get('create_date') or data.get('registered_on')
                
                if reg: result['whois']['registrar'] = reg
                if date: result['whois']['creation_date'] = str(date)[:10]
                api_success = True
        except: pass

    # Method B: Python-WHOIS & RDAP (Fallback if API failed or missing info)
    if result['whois']['registrar'] == 'Unknown' or result['whois']['creation_date'] == 'Unknown':
        try:
            # RDAP is excellent for Dates on IPs
            rdap_date = get_rdap_date(ip_addr)
            if rdap_date: 
                result['whois']['creation_date'] = rdap_date
            
            # Python-Whois is better for Registrar names
            try:
                w = whois.whois(ip_addr)
                if w.registrar:
                    val = w.registrar[0] if isinstance(w.registrar, list) else w.registrar
                    result['whois']['registrar'] = val
                
                # If RDAP failed, try whois date
                if result['whois']['creation_date'] == 'Unknown' and w.creation_date:
                      d = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
                      result['whois']['creation_date'] = str(d)[:10]
            except: pass
            
        except: pass

    _ip_reputation_cache[ip_addr] = result
    return result

def _format_packet(pkt: Packet, threat_alert=None):
    ts = datetime.now().isoformat()
    summary = pkt.summary()
    src = 'N/A'; dst = 'N/A'; proto = 'Other'

    is_server_response = False

    if IP in pkt:
        src = pkt[IP].src; dst = pkt[IP].dst
        if pkt.haslayer(TCP):
            sport = pkt[TCP].sport; dport = pkt[TCP].dport
            if sport == 80 or dport == 80: proto = 'HTTP'
            elif sport == 443 or dport == 443: proto = 'HTTPS'
            elif sport == 22 or dport == 22: proto = 'SSH'
            elif sport == 53 or dport == 53: proto = 'DNS'
            else: proto = 'TCP'
            
            # Detect if packet is originating from a local web port
            if sport in [80, 443, 8000, 8080]:
                is_server_response = True
                
        elif pkt.haslayer(UDP):
            proto = 'DNS' if (pkt[UDP].sport == 53 or pkt[UDP].dport == 53) else 'UDP'
        elif pkt.haslayer(ICMP): proto = 'ICMP'
    elif IPv6 in pkt: 
        src = pkt[IPv6].src; dst = pkt[IPv6].dst; proto = 'IPv6'
        if pkt.haslayer(TCP) and pkt[TCP].sport in [80, 443, 8000, 8080]:
            is_server_response = True
    elif Ether in pkt: 
        src = f"L2:{pkt[Ether].src}"; dst = f"L2:{pkt[Ether].dst}"; proto = 'ARP' if 'ARP' in summary else 'L2'

    # Fallback check (bypassed if it's an outbound server response)
    if threat_alert is None and not is_server_response: 
        threat_alert = check_packet(pkt, _rules)
        
    geo_src = None; reputation = None
    if IP in pkt:
        geo_src = _get_geo_info(src)
        reputation = _get_ip_reputation(src)
        if not reputation:
            reputation = _get_ip_reputation(dst)
            if reputation: geo_src = _get_geo_info(dst)

    return {
        'type': 'packet.message', 'summary': summary, 'src': str(src), 'dst': str(dst),
        'proto': proto, 'timestamp': ts, 
        'severity': 'HIGH' if threat_alert else 'INFO', # <-- FIXED: Explicitly assigns severity
        'threat': threat_alert, 'geo_src': geo_src, 'reputation': reputation
    }

def packet_handler(pkt: Packet):
    global _packets, _last_update_time, _pending_geo
    with _lock:
        _packets.append(pkt)
        if IP in pkt:
            geo_info = _get_geo_info(pkt[IP].src)
            if geo_info: _pending_geo.append(geo_info)

    # 1. Skip scanning outbound web traffic to prevent double-flagging reflected payloads
    is_server_response = False
    if pkt.haslayer(TCP) and pkt[TCP].sport in [80, 443, 8000, 8080]:
        is_server_response = True

    threat_alert = None
    if not is_server_response:
        threat_alert = check_packet(pkt, _rules)

    now = time.time()
    if not threat_alert and (now - _last_update_time < 0.01): return
    _last_update_time = now
    
    data = _format_packet(pkt, threat_alert=threat_alert)
    with _lock:
        data['geo_batch'] = list(_pending_geo)
        _pending_geo.clear()

    try:
        if hasattr(settings, 'CHANNEL_LAYER'):
            async_to_sync(settings.CHANNEL_LAYER.group_send)(SNIFF_GROUP_NAME, data)
    except: pass

# --- START/STOP HANDLERS ---

def start_sniffer(bpf_filter=None, iface=None):
    global _sniffer_instance, _packets, _rules, _geo_reader, _ip_reputation_cache, _pending_geo, _waf_alerts
    global _snort_running, _snort_thread

    with _lock:
        if _sniffer_instance and _sniffer_instance.running: return False
        _packets.clear(); _waf_alerts.clear(); _ip_reputation_cache = {}; _pending_geo = []
        
        cache.set('sniffer_status', {'active': True, 'bpf': bpf_filter}, timeout=None)
        
        rule_path = os.path.join(settings.BASE_DIR, 'pages', 'rules', 'rules_for_malicious.rules')
        _rules = parse_rules(rule_path)
        
        try: _geo_reader = geoip2.database.Reader(os.path.join(settings.BASE_DIR, 'pages', 'utils', 'GeoLite2-City.mmdb'))
        except: _geo_reader = None

        try:
            _sniffer_instance = AsyncSniffer(prn=packet_handler, store=False, filter=bpf_filter, iface=iface)
            _sniffer_instance.start()
        except Exception as e:
            print(f"Scapy Sniffer Error: {e}")
            cache.set('sniffer_status', {'active': False}, timeout=None)
            return False

        _snort_running = True
        _snort_thread = threading.Thread(target=monitor_snort_alerts, daemon=True)
        _snort_thread.start()
        print("[SYSTEM] Sniffer and IDS monitor started successfully")
        return True

def stop_sniffer():
    global _sniffer_instance, _geo_reader, _snort_running, _snort_thread
    
    cache.set('sniffer_status', {'active': False}, timeout=None)
    
    _snort_running = False
    if _snort_thread: 
        _snort_thread.join(timeout=1.0)
        print("[SYSTEM] IDS monitor stopped")
    
    current = None
    with _lock:
        if not _sniffer_instance: return False
        current = _sniffer_instance
        _sniffer_instance = None 

    try:
        if current:
            current.stop()
            if hasattr(current, 'is_alive') and current.is_alive(): current.join(timeout=2.0)
        if _geo_reader: _geo_reader.close(); _geo_reader = None
        print("[SYSTEM] Sniffer stopped successfully")
        return True
    except: return False

def get_and_clear_packets():
    global _packets
    with _lock:
        captured = list(_packets)
        _packets.clear()
    return captured

def get_packets_without_stopping():
    global _packets
    with _lock: return list(_packets)

def export_pcap(path):
    with _lock:
        if not _packets: return False
        wrpcap(path, _packets)
    return True

def clear_packets():
    global _packets, _waf_alerts
    with _lock:
        _packets.clear()
        _waf_alerts.clear()
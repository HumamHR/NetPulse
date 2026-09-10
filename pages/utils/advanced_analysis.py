# pages/utils/advanced_analysis.py
from scapy.all import Packet, IP, ARP, TCP, UDP, ICMP
from collections import defaultdict
import time
import os

# For GeoIP (optional - comment out if not needed)
try:
    import geoip2.database
    GEOIP_AVAILABLE = True
except ImportError:
    GEOIP_AVAILABLE = False

# Define the path to your GeoLite2 database
GEOIP_DATABASE_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),  # Go up to pages/
    'rules', 'GeoLite2-City.mmdb'
)

def get_top_talkers(packets, top_n=10):
    """Analyzes packet size to find the top N talkers."""
    talker_bytes = defaultdict(int)
    
    for pkt in packets:
        if IP in pkt:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            
            # Count bytes for both source and destination
            talker_bytes[src_ip] += len(pkt)  # Bytes sent
            talker_bytes[dst_ip] += len(pkt)  # Bytes received
    
    # Convert to list of dictionaries
    results = []
    for ip, total_bytes in sorted(talker_bytes.items(), key=lambda x: x[1], reverse=True)[:top_n]:
        results.append({
            'ip_address': ip,
            'total_bytes': total_bytes,
            'total_mb': round(total_bytes / (1024 * 1024), 2),
            'total_kb': round(total_bytes / 1024, 2)
        })
    
    return results

def analyze_time_series(packets, window_seconds=5):
    """Calculates packet rate and byte rate in time windows."""
    if not packets:
        return []
    
    # Get timestamps
    timestamps = []
    for pkt in packets:
        if hasattr(pkt, 'time'):
            timestamps.append(pkt.time)
        else:
            timestamps.append(time.time())  # Fallback
    
    if not timestamps:
        return []
    
    start_time = min(timestamps)
    end_time = max(timestamps)
    
    results = []
    current_window_start = start_time
    
    while current_window_start < end_time:
        window_end = current_window_start + window_seconds
        
        window_packets = 0
        window_bytes = 0
        
        # Count packets and bytes in this window
        for i, pkt in enumerate(packets):
            pkt_time = timestamps[i]
            if current_window_start <= pkt_time < window_end:
                window_packets += 1
                window_bytes += len(pkt)
        
        # Calculate rates
        packets_per_sec = window_packets / window_seconds if window_seconds > 0 else 0
        bytes_per_sec = window_bytes / window_seconds if window_seconds > 0 else 0
        
        results.append({
            'timestamp': time.strftime('%H:%M:%S', time.localtime(current_window_start)),
            'packets': window_packets,
            'bytes': window_bytes,
            'packets_per_sec': round(packets_per_sec, 2),
            'bytes_per_sec': round(bytes_per_sec, 2),
            'mbps': round((bytes_per_sec * 8) / (1024 * 1024), 2)  # Mbps
        })
        
        current_window_start = window_end
    
    return results

def get_geoip_mapping(packets):
    """Performs GeoIP lookup for unique external IP addresses."""
    if not GEOIP_AVAILABLE:
        return {'error': 'GeoIP2 library not installed'}
    
    unique_ips = set()
    for pkt in packets:
        if IP in pkt:
            unique_ips.add(pkt[IP].src)
            unique_ips.add(pkt[IP].dst)
    
    geo_data = {}
    
    try:
        if os.path.exists(GEOIP_DATABASE_PATH):
            reader = geoip2.database.Reader(GEOIP_DATABASE_PATH)
            
            for ip in unique_ips:
                try:
                    response = reader.city(ip)
                    geo_data[ip] = {
                        'country': response.country.name if response.country.name else 'Unknown',
                        'city': response.city.name if response.city.name else 'Unknown',
                        'latitude': response.location.latitude,
                        'longitude': response.location.longitude,
                        'coordinates': f"{response.location.latitude},{response.location.longitude}"
                    }
                except:
                    geo_data[ip] = {
                        'country': 'Unknown',
                        'city': 'Unknown',
                        'latitude': None,
                        'longitude': None,
                        'coordinates': None
                    }
            
            reader.close()
        else:
            geo_data = {'error': f'GeoIP database not found at: {GEOIP_DATABASE_PATH}'}
    except Exception as e:
        geo_data = {'error': f'GeoIP error: {str(e)}'}
    
    return geo_data

def arp_spoofing_detection(packets):
    """Detects potential ARP spoofing by tracking IP-to-MAC mapping changes."""
    ip_to_mac = {}
    alerts = []
    
    for pkt in packets:
        if ARP in pkt:
            sender_ip = pkt[ARP].psrc
            sender_mac = pkt[ARP].hwsrc
            
            if sender_ip in ip_to_mac:
                if ip_to_mac[sender_ip] != sender_mac:
                    alerts.append({
                        'timestamp': time.strftime('%H:%M:%S', time.localtime(pkt.time)) if hasattr(pkt, 'time') else 'N/A',
                        'ip_address': sender_ip,
                        'old_mac': ip_to_mac[sender_ip],
                        'new_mac': sender_mac,
                        'type': 'ARP Spoofing Detected',
                        'description': f'IP {sender_ip} changed MAC from {ip_to_mac[sender_ip]} to {sender_mac}'
                    })
            
            ip_to_mac[sender_ip] = sender_mac
    
    return alerts

def analyze_bandwidth_usage(packets):
    """Analyze bandwidth usage by protocol"""
    protocol_bytes = defaultdict(int)
    
    for pkt in packets:
        if IP in pkt:
            if TCP in pkt:
                protocol_bytes['TCP'] += len(pkt)
            elif UDP in pkt:
                protocol_bytes['UDP'] += len(pkt)
            elif ICMP in pkt:
                protocol_bytes['ICMP'] += len(pkt)
            else:
                protocol_bytes['Other'] += len(pkt)
    
    total_bytes = sum(protocol_bytes.values())
    
    results = []
    for proto, bytes_used in protocol_bytes.items():
        percentage = (bytes_used / total_bytes * 100) if total_bytes > 0 else 0
        results.append({
            'protocol': proto,
            'bytes': bytes_used,
            'percentage': round(percentage, 2),
            'mb': round(bytes_used / (1024 * 1024), 2)
        })
    
    return results
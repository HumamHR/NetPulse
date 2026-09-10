# pages/utils/geo_ip.py
import os
import random
import geoip2.database
from django.conf import settings
from scapy.layers.inet import IP

def get_geo_data(packets):
    """
    Returns:
    1. geo_data: List of dicts for the MAP (lat/lon required)
    2. all_ips_list: List of dicts for the TABLE (includes everything)
    """
    geo_data = []
    all_ips_list = [] # New Master List
    processed_ips = set()
    
    db_path = os.path.join(settings.BASE_DIR, 'pages', 'utils', 'GeoLite2-City.mmdb')
    
    # Initialize reader if DB exists
    reader = None
    if os.path.exists(db_path):
        try:
            reader = geoip2.database.Reader(db_path)
        except:
            pass

    def process_ip(ip_addr, direction):
        if ip_addr not in processed_ips:
            processed_ips.add(ip_addr)
            
            # Default values
            status = "Skipped"
            location = "Unknown"
            coords = None
            
            # Try Lookup
            if reader:
                data, reason = _lookup_ip(reader, ip_addr, direction)
                if data:
                    # It's a valid mapped IP
                    geo_data.append(data)
                    status = "Mapped"
                    location = f"{data['city']}, {data['country']}"
                else:
                    # It's skipped (Private, Multicast, or Not Found)
                    location = reason # e.g. "Private/LAN" or "Not found in DB"
            else:
                location = "DB Missing"

            # Add to Master List
            all_ips_list.append({
                'ip': ip_addr,
                'status': status,
                'location': location,
                'type': direction
            })

    # Scan Packets
    try:
        for pkt in packets:
            if IP in pkt:
                process_ip(pkt[IP].src, "Source")
                process_ip(pkt[IP].dst, "Destination")
        
        if reader: reader.close()
        
        # Return geo_data (for map) AND all_ips_list (for table)
        return geo_data, all_ips_list

    except Exception as e:
        print(f"[ERROR] GeoIP failure: {e}")
        return [], []

def _lookup_ip(reader, ip_addr, direction):
    # 1. Filter Private / LAN IPs
    if ip_addr.startswith(('192.168.', '10.', '127.', '172.16.', '172.31.')):
        return None, "Private/LAN"

    # 2. Filter Multicast / Broadcast
    try:
        first = int(ip_addr.split('.')[0])
        if 224 <= first <= 239: return None, "Multicast"
    except: pass
    if ip_addr in ['0.0.0.0', '255.255.255.255']: return None, "Broadcast"

    try:
        response = reader.city(ip_addr)
        
        lat = response.location.latitude
        lon = response.location.longitude

        if lat is None or lon is None:
             return None, f"No Coords ({response.country.name or 'Unknown'})"

        # EXTREME JITTER (±5.0 Degrees)
        jitter_lat = lat + random.uniform(-5.0, 5.0)
        jitter_lon = lon + random.uniform(-5.0, 5.0)

        return {
            'ip': ip_addr,
            'country': response.country.name or "Unknown",
            'city': response.city.name or "Unknown",
            'lat': jitter_lat, 
            'lon': jitter_lon,
            'type': direction 
        }, None

    except geoip2.errors.AddressNotFoundError:
        return None, "Not in DB"
    except Exception as e:
        return None, f"Error: {str(e)}"
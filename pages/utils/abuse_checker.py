# pages/utils/abuse_checker.py
import requests
import ipaddress
import datetime
from django.conf import settings

# --- GLOBAL STATE ---
# 1. Cache results so we don't hit the API for the same IP twice
_ABUSE_CACHE = {}
# 2. Circuit Breaker: If we hit the limit, stop trying immediately
_API_LIMIT_REACHED = False

def is_public_ip(ip_str):
    """Returns True if IP is public, False if private/loopback/multicast."""
    if not ip_str: return False
    try:
        ip = ipaddress.ip_address(ip_str)
        return not (ip.is_private or ip.is_loopback or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False

def check_abuseipdb(ip_list, limit=15):
    global _API_LIMIT_REACHED, _ABUSE_CACHE

    if not hasattr(settings, 'ABUSEIPDB_API_KEY') or not settings.ABUSEIPDB_API_KEY:
        print("[AbuseIPDB] No API Key found.")
        return {'scanned': [], 'skipped': []}

    # --- CIRCUIT BREAKER ---
    # If we already hit the limit, just return cached/empty results instantly.
    if _API_LIMIT_REACHED:
        return {'scanned': [], 'skipped': ip_list}

    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': settings.ABUSEIPDB_API_KEY,
        'Accept': 'application/json'
    }

    unique_ips = list(set(ip_list))
    
    ips_to_check = []
    skipped_ips = []
    scanned_results = []

    # 1. Check Memory Cache First
    for ip in unique_ips:
        if not is_public_ip(ip):
            skipped_ips.append(ip)
            continue
            
        if ip in _ABUSE_CACHE:
            # We already have this data, use it!
            scanned_results.append(_ABUSE_CACHE[ip])
        else:
            ips_to_check.append(ip)

    # 2. Apply Limit to NEW checks only
    ips_to_call = ips_to_check[:limit]
    
    if ips_to_call:
        print(f"[AbuseIPDB] Scanning {len(ips_to_call)} new public IPs...")

    for ip in ips_to_call:
        # Double check inside loop in case limit hits mid-loop
        if _API_LIMIT_REACHED:
            break

        try:
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': '1'
            }
            # Low timeout prevents the dashboard from hanging
            response = requests.get(url, headers=headers, params=querystring, timeout=3)
            
            # --- GET RATE LIMIT HEADERS ---
            remaining = response.headers.get('x-ratelimit-remaining', '?')
            reset_ts = response.headers.get('x-ratelimit-reset', None)
            
            if reset_ts:
                # Convert Unix timestamp to readable time
                reset_time = datetime.datetime.fromtimestamp(int(reset_ts)).strftime('%Y-%m-%d %H:%M:%S')
            else:
                reset_time = "Unknown"

            if response.status_code == 200:
                data = response.json().get('data', {})
                result_entry = {
                    'ip': data.get('ipAddress'),
                    'score': data.get('abuseConfidenceScore', 0),
                    'isp': data.get('isp', 'Unknown'),
                    'country': data.get('countryName', data.get('countryCode', 'Unknown')),
                    'total_reports': data.get('totalReports', 0),
                    'last_reported': data.get('lastReportedAt', 'Never'),
                    'reports': data.get('reports', []) 
                }
                
                # Save to Cache
                _ABUSE_CACHE[ip] = result_entry
                scanned_results.append(result_entry)

            elif response.status_code == 429:
                print(f"\n[AbuseIPDB] ⚠️ RATE LIMIT EXCEEDED.")
                print(f" -> You have {remaining} requests remaining.")
                print(f" -> Limit will reset at: {reset_time}")
                print(f" -> Disabling checks for this session to prevent spam.")
                _API_LIMIT_REACHED = True
                break
            
            elif response.status_code == 401:
                print(f"[AbuseIPDB] ❌ Authentication Failed. Check API Key.")
                _API_LIMIT_REACHED = True
                break
                
            else:
                print(f"[AbuseIPDB] API Error {response.status_code} for {ip}")

        except Exception as e:
            print(f"[AbuseIPDB] Connection error for {ip}: {e}")
            continue

    scanned_results.sort(key=lambda x: x['score'], reverse=True)
    
    return {
        'scanned': scanned_results,
        'skipped': sorted(skipped_ips)
    }
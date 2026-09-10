# waf_addon.py
import re
import json
import time
import os
import requests
from mitmproxy import http
from urllib.parse import unquote_plus, unquote

# --- CONFIGURATION ---
DASHBOARD_URL = 'http://127.0.0.1:8000/waf-alert/' 
RULE_FILE = os.path.join(os.getcwd(), 'pages', 'rules', 'rules_for_malicious.rules')

class NetpulseWAF:
    def __init__(self):
        self.rules = self.load_rules(RULE_FILE)
        print(f"[WAF] Active. Loaded {len(self.rules)} detection rules.")

    def load_rules(self, file_path):
        rules = []
        if not os.path.exists(file_path):
            print(f"[WAF] Rule file not found: {file_path}")
            return []
        
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): continue
                
                match = re.search(r'msg:"([^"]+)".*?sid:(\d+)', line)
                if match:
                    rule = {'msg': match.group(1), 'sid': match.group(2)}
                    content = re.search(r'content:"([^"]+)"', line)
                    if content: rule['content'] = content.group(1)
                    pcre = re.search(r'pcre:"([^"]+)"', line)
                    if pcre: rule['pcre'] = pcre.group(1)
                    rules.append(rule)
        return rules

    def request(self, flow: http.HTTPFlow):
        url = flow.request.pretty_url
        method = flow.request.method
        # [FIX] Dynamically get scheme (http or https)
        scheme = flow.request.scheme.upper() 
        
        try:
            content_type = flow.request.headers.get("Content-Type", "").lower()
            if "image" in content_type or "octet-stream" in content_type:
                body_str = "[Binary Data Omitted]"
            else:
                body_str = flow.request.content.decode('utf-8', 'ignore')
        except:
            body_str = "[Encoding Error - Binary Data]"

        headers_dict = dict(flow.request.headers)
        
        detection_payload = unquote_plus(f"{url} {body_str}")
        display_url = unquote(url)
        display_payload = f"Method: {method}\nURL: {display_url}\n\nBody:\n{body_str}"

        is_detected = False
        detect_reason = "Traffic Monitor" 
        
        for rule in self.rules:
            matched = False
            if 'content' in rule and rule['content'].lower() in detection_payload.lower():
                matched = True
            
            if 'pcre' in rule and not matched:
                regex = rule['pcre'].strip('"').strip('/')
                if regex.endswith('/is') or regex.endswith('/i'):
                    regex = regex.rsplit('/', 1)[0]
                try:
                    if re.search(regex, detection_payload, re.IGNORECASE):
                        matched = True
                except: pass

            if matched:
                is_detected = True
                detect_reason = rule['msg']
                print(f"[WAF] DETECTED (Allowed): {detect_reason}")
                break 

        alert_data = {
            'type': 'packet.message',
            'summary': f"{scheme}: {method} {flow.request.host}",
            'src': flow.client_conn.address[0],
            'dst': flow.request.host,
            'proto': scheme, # [FIX] Sends HTTP or HTTPS correctly
            'timestamp': str(time.time()),
            'severity': 'HIGH' if is_detected else 'INFO', 
            'threat': {
                'msg': f"[WAF DETECTED] {detect_reason}" if is_detected else f"{scheme} Traffic Log",
                'sid': 'WAF-1000' if is_detected else 'INFO-000',
                'payload': display_payload[:1000]
            },
            'geo_src': {'city': 'WAF', 'country': 'Proxy', 'lat': 0, 'lon': 0},
            'url': display_url,
            'payload': display_payload[:1000],
            'reason': detect_reason,
            'headers': headers_dict,
            'method': method,
            'host': flow.request.host,
            'user_agent': headers_dict.get('User-Agent', 'Unknown'),
            'direction': 'outbound'
        }
        
        try: requests.post(DASHBOARD_URL, json=alert_data, timeout=1)
        except: pass

    def response(self, flow: http.HTTPFlow):
        headers_dict = dict(flow.response.headers)
        status_code = flow.response.status_code
        scheme = flow.request.scheme.upper() # [FIX]
        
        try:
            content_type = headers_dict.get("Content-Type", "").lower()
            if "image" in content_type or "octet-stream" in content_type:
                body_str = "[Binary Data Omitted]"
            else:
                body_str = flow.response.content.decode('utf-8', 'ignore')
        except:
            body_str = "[Encoding Error]"

        display_payload = f"Status: {status_code}\nHeaders: {json.dumps(headers_dict, indent=2)}\n\nBody Sample:\n{body_str[:500]}"

        alert_data = {
            'type': 'packet.message',
            'summary': f"{scheme} Response: {status_code} {flow.request.host}",
            'src': flow.request.host,
            'dst': flow.client_conn.address[0],
            'proto': scheme, # [FIX]
            'timestamp': str(time.time()),
            'severity': 'INFO',
            'threat': {
                'msg': f"{scheme} Response",
                'sid': 'INFO-RESP',
                'payload': display_payload
            },
            'headers': headers_dict,
            'status_code': status_code,
            'host': flow.request.host,
            'direction': 'inbound'
        }

        try: requests.post(DASHBOARD_URL, json=alert_data, timeout=1)
        except: pass

addons = [ NetpulseWAF() ]
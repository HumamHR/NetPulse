# sniffapp/views.py
import os
import time
import json
import traceback
import re
from collections import defaultdict
from django.shortcuts import render, redirect
from django.views.decorators.http import require_POST
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings 
from django.core.cache import cache
from django.http import JsonResponse
from channels.layers import get_channel_layer
from asgiref.sync import async_to_sync
from scapy.all import wrpcap, IP, IPv6, TCP

# --- Import Helper Functions ---
from sniffapp.sniffer import stop_sniffer, get_and_clear_packets, get_and_clear_waf_alerts, add_waf_alert
from pages.utils.analysis import analyze_pcap_for_stats 
from pages.utils.credentials_extractor import extract_credentials
from pages.utils.malformed_detector import analyze_pcap_for_malformed
from pages.utils.malicious_detector import analyze_pcap_for_malicious, save_malicious_packets 
from pages.views import save_malformed_packets 
from pages.utils.pcap_analyzer import analyze_pcap
from pages.utils.IP_hosts import analyze_hosts, analyze_ip_pairs 
from pages.utils.tls_analyzer import get_ja3_fingerprint, analyze_tls_server, fetch_active_cert
from pages.utils.macs import get_mac_addresses
from pages.utils.flowchart_maker import create_flow_diagram
from pages.utils.report_maker import pdf_and_html_report_maker
from pages.utils.protocols_dist import protocol_distribution
from pages.utils.geo_ip import get_geo_data
from pages.utils.abuse_checker import check_abuseipdb
from pages.utils.http_objects_extractor_scapy import extract_http_objects_scapy

def sniff_page(request):
    return render(request, 'sniffapp/sniff.html')

def live_dashboard(request):
    return render(request, 'sniffapp/dashboard.html')

def live_analysis_handler(request, cache_key):
    session_data = cache.get(cache_key)
    if session_data:
        request.session['pcap_results'] = session_data
        cache.delete(cache_key) 
        return redirect('pcap_results')
    else:
        return redirect('sniff_page')

@csrf_exempt
def waf_alert_webhook(request):
    if request.method == 'POST':
        try:
            sniffer_status = cache.get('sniffer_status')
            if not sniffer_status or not sniffer_status.get('active'):
                return JsonResponse({'status': 'ignored', 'reason': 'sniffer_inactive'})

            data = json.loads(request.body)
            
            print(f"[WAF Webhook] Received alert: {data.get('summary', 'No summary')}")

            bpf = sniffer_status.get('bpf', '')
            if bpf and 'port 80' in bpf and '443' not in bpf:
                if data.get('proto') == 'HTTPS':
                    return JsonResponse({'status': 'filtered', 'reason': 'https_ignored'})

            # Forward to WebSocket for live dashboard
            channel_layer = get_channel_layer()
            if channel_layer:
                # Ensure the data has the correct type for the consumer
                ws_data = {
                    'type': 'packet.message',
                    'summary': data.get('summary', 'WAF Alert'),
                    'src': data.get('src', 'Unknown'),
                    'dst': data.get('dst', 'Unknown'),
                    'proto': data.get('proto', 'HTTPS'),
                    'timestamp': data.get('timestamp', str(time.time())),
                    'severity': data.get('severity', 'HIGH'),
                    'threat': data.get('threat', {
                        'msg': 'WAF Detection',
                        'sid': 'WAF-1000',
                        'payload': data.get('payload', '')
                    }),
                    'geo_src': data.get('geo_src', {'city': 'WAF', 'country': 'Proxy', 'lat': 0, 'lon': 0}),
                    'reputation': None,
                    'url': data.get('url', ''),
                    'method': data.get('method', 'UNKNOWN'),
                    'host': data.get('host', ''),
                    'headers': data.get('headers', {}),
                    'direction': data.get('direction', 'outbound')
                }
                
                async_to_sync(channel_layer.group_send)(
                    'sniff_group', 
                    ws_data
                )
                print(f"[WAF Webhook] Alert forwarded to WebSocket")
            else:
                print(f"[WAF Webhook] ⚠️ Channel layer not available")

            data['source'] = 'WAF/HTTPS'
            add_waf_alert(data)

            return JsonResponse({'status': 'ok'})
        except Exception as e:
            print(f"[WAF Webhook] Error: {e}")
            traceback.print_exc()
            return JsonResponse({'status': 'error', 'msg': str(e)}, status=400)
    
    return JsonResponse({'status': 'bad_method'}, status=405)

# --- Helper Functions (Local Copy) ---
def detect_open_ports(packets):
    open_ports = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt[TCP].flags == 0x12:
            src_ip = None
            if pkt.haslayer(IP): src_ip = pkt[IP].src
            elif pkt.haslayer(IPv6): src_ip = pkt[IPv6].src
            if src_ip: open_ports[src_ip].add(pkt[TCP].sport)
    return {k: sorted(list(v)) for k, v in open_ports.items()}

def extract_cn_from_subject(subject_str):
    if not subject_str: return "-"
    match = re.search(r'CN=([^,]+)', subject_str)
    return match.group(1) if match else "-"

# --- NEW HELPER ---
def get_header(headers, key):
    if not headers: return '-'
    key_lower = key.lower()
    for k, v in headers.items():
        if k.lower() == key_lower:
            return v
    return '-'

@require_POST
def analyze_live_capture(request):
    temp_file_path = None
    try:
        stop_sniffer() 
        captured_packets = get_and_clear_packets()
    except Exception as e:
        return render(request, 'sniffapp/sniff.html', {'message': f'Error: {e}'})
        
    if not captured_packets:
        return render(request, 'sniffapp/sniff.html', {'message': 'No packets captured.'})

    try:
        upload_dir = os.path.join(settings.MEDIA_ROOT, 'temp_live_analysis')
        os.makedirs(upload_dir, exist_ok=True)
        filename = f'live_capture_{int(time.time())}.pcap'
        temp_file_path = os.path.join(upload_dir, filename)
        wrpcap(temp_file_path, captured_packets)

        # 2. Run Analysis Modules
        basic_stats = analyze_pcap_for_stats(captured_packets)
        protocol_counts = protocol_distribution(captured_packets)
        credentials = extract_credentials(captured_packets)
        geo_location_data, all_ips_list = get_geo_data(captured_packets)
        http_objects_data = extract_http_objects_scapy(temp_file_path)
        open_ports_data = detect_open_ports(captured_packets)

        # TLS Aggregation
        tls_ja3_data = []
        tls_aggregation = {} 
        ip_to_sni = {}

        for packet in captured_packets:
            ja3_result = get_ja3_fingerprint(packet)
            if ja3_result:
                tls_ja3_data.append(ja3_result)
                if ja3_result.get('sni') and ja3_result['sni'] != "Unknown":
                    if ja3_result.get('dest_ip') and ja3_result['dest_ip'] != "Unknown":
                        ip_to_sni[ja3_result['dest_ip']] = ja3_result['sni']
            
            server_results = analyze_tls_server(packet)
            if server_results:
                for res in server_results:
                    s_ip = res.get('server_ip')
                    if s_ip not in tls_aggregation:
                        discovered_name = ip_to_sni.get(s_ip, "-")
                        tls_aggregation[s_ip] = {
                            'server_ip': s_ip, 'server_name': discovered_name, 
                            'subject': "Unknown Service", 'issuer': "-",
                            'not_valid_before': "-", 'not_valid_after': "-", 'is_expired': False,
                            'is_self_signed': False, 'protocol_version': "" 
                        }
                    
                    if res['type'] == 'ServerHello':
                        clean_ver = res['subject'].replace("Handshake: ", "")
                        tls_aggregation[s_ip]['protocol_version'] = clean_ver
                        tls_aggregation[s_ip]['issuer'] = res['issuer']
                        if tls_aggregation[s_ip]['subject'] == "Unknown Service":
                            tls_aggregation[s_ip]['subject'] = f"Service ({clean_ver})"
                        if res['is_expired']: 
                             tls_aggregation[s_ip]['is_expired'] = True 
                             if "Cert Encrypted" not in tls_aggregation[s_ip]['issuer']:
                                 tls_aggregation[s_ip]['issuer'] = "WEAK PROTOCOL"
                    elif res['type'] == 'Certificate':
                        cn = extract_cn_from_subject(res['subject'])
                        current_name = tls_aggregation[s_ip]['server_name']
                        if current_name == "-" and cn != "-":
                             tls_aggregation[s_ip]['server_name'] = cn
                             
                        tls_aggregation[s_ip].update({
                            'subject': res['subject'], 'issuer': res['issuer'],
                            'not_valid_before': res['not_valid_before'], 'not_valid_after': res['not_valid_after'],
                            'is_self_signed': res['is_self_signed']
                        })
                        if res['is_expired']: tls_aggregation[s_ip]['is_expired'] = True

        for s_ip, data in tls_aggregation.items():
            if data['server_name'] == "-":
                 data['server_name'] = ip_to_sni.get(s_ip, "-")

            missing_dates = data['not_valid_before'] == "-"
            is_tls13 = "TLS 1.3" in data.get('protocol_version', '')
            if missing_dates or is_tls13:
                try:
                    active_data = fetch_active_cert(s_ip)
                    if active_data:
                        cn = extract_cn_from_subject(active_data['subject'])
                        if data['server_name'] == "-" and cn != "-":
                            data['server_name'] = cn

                        data.update({
                            'subject': active_data['subject'], 'issuer': active_data['issuer'],
                            'not_valid_before': active_data['not_valid_before'], 'not_valid_after': active_data['not_valid_after'],
                            'is_expired': active_data['is_expired'], 'is_self_signed': active_data['is_self_signed']
                        })
                        if is_tls13: data['subject'] = f"{active_data['subject']} [TLS 1.3]"
                except: pass

        tls_certs_data = list(tls_aggregation.values())
        for item in tls_certs_data:
            if item['protocol_version'] and "TLS" not in item['subject'] and item['subject'] != "Unknown Service":
                 item['subject'] = f"{item['subject']} [{item['protocol_version']}]"

        all_ips_for_abuse = []
        for pkt in captured_packets:
             if IP in pkt:
                 all_ips_for_abuse.append(pkt[IP].src)
                 all_ips_for_abuse.append(pkt[IP].dst)
             elif IPv6 in pkt:
                 all_ips_for_abuse.append(pkt[IPv6].src)
                 all_ips_for_abuse.append(pkt[IPv6].dst)
        abuse_data = check_abuseipdb(all_ips_for_abuse)

        rules_dir = os.path.join(settings.BASE_DIR, 'pages', 'rules')
        malformed_rule_file = os.path.join(rules_dir, 'rules_for_malformed.rules')
        malicious_rule_file = os.path.join(rules_dir, 'rules_for_malicious.rules')
        
        malformed_alerts, malformed_pkts = analyze_pcap_for_malformed(captured_packets, malformed_rule_file)
        malicious_alerts, malicious_pkts = analyze_pcap_for_malicious(captured_packets, malicious_rule_file)
        
        # =================================================================
        # UNIFIED ALERT & HEADER PROCESSING (Dynamic Protocol Label)
        # =================================================================
        unified_alerts = get_and_clear_waf_alerts()
        http_headers_list = []
        waf_counter = 1
        
        from scapy.layers.inet import TCP
        from scapy.layers.all import Raw
        from datetime import datetime as dt
        
        # 1. Process WAF & Suricata Data
        for item in unified_alerts:
            if not isinstance(item, dict): continue

            # A. Suricata Alert (IDS)
            if 'msg' in item and 'sid' in item and 'headers' not in item:
                formatted_alert = {
                    'msg': item.get('msg', 'Threat Detected'),
                    'sid': item.get('sid', '0'),
                    'payload': item.get('payload', 'Suricata Detected Activity'),
                    'packet_num': "IDS-Log",
                    'src': item.get('src', 'N/A'),
                    'dst': item.get('dst', 'N/A'),
                    'proto': item.get('proto', 'N/A'),
                    'severity': 'HIGH'
                }
                malicious_alerts.append(formatted_alert)

            # B. WAF Log (HTTP/HTTPS)
            else:
                raw_proto = item.get('proto', 'HTTPS').upper()
                url = item.get('url', '').lower()
                
                if raw_proto == 'HTTP' or url.startswith('http://'):
                    type_label = 'HTTP (WAF)'
                    is_https = False
                else:
                    type_label = 'HTTPS (Decrypted)'
                    is_https = True

                if item.get('headers'):
                    try:
                        ts = float(item.get('timestamp', time.time()))
                        time_str = dt.fromtimestamp(ts).strftime('%H:%M:%S')
                    except: time_str = "00:00:00"
                    
                    ua = get_header(item.get('headers', {}), 'User-Agent')
                    
                    header_entry = {
                        'timestamp': time_str,
                        'type': type_label, 
                        'method': item.get('method', '-'),
                        'host': item.get('host', '-'),
                        'url': item.get('url', '-'),
                        'user_agent': ua,
                        'full_headers': item.get('headers', {})
                    }
                    http_headers_list.append(header_entry)
                
                if item.get('severity') == 'HIGH':
                     sid = item.get('threat', {}).get('sid', 'INFO')
                     if sid != 'INFO-000':
                        synthetic_alert = {
                            'msg': f"[WAF] {item.get('reason', 'Malicious Request')}",
                            'sid': f"WAF-{1000 + waf_counter}",
                            'payload': item.get('payload', 'Payload Data'),
                            'packet_num': "HTTPS-Stream",
                            'src': item.get('src', 'WAF'),
                            'dst': item.get('dst', 'Target'),
                            'proto': 'HTTPS' if is_https else 'HTTP',
                            'severity': 'HIGH'
                        }
                        malicious_alerts.append(synthetic_alert)
                        waf_counter += 1

        # 2. Extract Plaintext HTTP from Scapy (Fallback)
        for pkt in captured_packets:
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                try:
                    payload = pkt[Raw].load
                    if payload.startswith((b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ')):
                        try:
                            text = payload.decode('utf-8', 'ignore')
                            lines = text.split('\r\n')
                            req_line = lines[0].split(' ')
                            method = req_line[0]
                            url = req_line[1] if len(req_line) > 1 else '-'
                            
                            headers = {}
                            for line in lines[1:]:
                                if ': ' in line:
                                    k, v = line.split(': ', 1)
                                    headers[k] = v
                                elif not line: break
                            
                            ts = dt.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S')
                            ua = get_header(headers, 'User-Agent')

                            http_headers_list.append({
                                'timestamp': ts,
                                'type': 'HTTP (Plaintext)',
                                'method': method,
                                'host': get_header(headers, 'Host'),
                                'url': url,
                                'user_agent': ua,
                                'full_headers': headers
                            })
                        except: pass
                except: pass

        malformed_pcap_path = save_malformed_packets(malformed_pkts) 
        malicious_pcap_path = save_malicious_packets(malicious_pkts)
        
        sessions_data = analyze_hosts(captured_packets)
        hosts_data_result = analyze_ip_pairs(captured_packets)
        ip_pairs_v4 = hosts_data_result.get('ipv4_pairs', {})
        ip_pairs_v6 = hosts_data_result.get('ipv6_pairs', {})
        
        mac_data = get_mac_addresses(captured_packets)
        flowchart_data = create_flow_diagram(temp_file_path, captured_packets)
        
        report_paths = pdf_and_html_report_maker(
             captured_packets, temp_file_path, malicious_count=len(malicious_alerts), malformed_count=len(malformed_alerts)
        )
        
        analysis_data = analyze_pcap(malformed_alerts, captured_packets, temp_file_path)
        stats_full = analyze_pcap_for_stats(captured_packets)
        timeline_data = stats_full.get('timeline_data', {})

        report_html_path = os.path.relpath(report_paths[1], settings.MEDIA_ROOT) if (report_paths and len(report_paths) > 1) else ""
        rel_malicious = os.path.relpath(malicious_pcap_path, settings.MEDIA_ROOT) if malicious_pcap_path else ""
        rel_malformed = os.path.relpath(malformed_pcap_path, settings.MEDIA_ROOT) if malformed_pcap_path else ""

        session_data = {
            'data': {
                **analysis_data['analysis_results'],
                'protocol_distribution': dict(protocol_counts),
                'timeline_data': timeline_data,
                'tls_ja3': tls_ja3_data, 
                'tls_certs': tls_certs_data, 
                'hosts_data': hosts_data_result,
                'sessions_data': sessions_data,
                'ip_pairs_v4': ip_pairs_v4,
                'ip_pairs_v6': ip_pairs_v6,
                'unique_src_macs': mac_data.get('unique_src_macs', []),
                'unique_dst_macs': mac_data.get('unique_dst_macs', []),
                'mac_pairs': mac_data.get('mac_pairs', []),
                'total_unique_macs': mac_data.get('total_unique_macs', 0),
                'credentials': credentials,
                'geo_data': geo_location_data,
                'all_geo_ips': all_ips_list,
                'open_ports': open_ports_data,
                'http_objects': http_objects_data,
                'alerts': malformed_alerts, 
                'malformed_count': len(malformed_alerts),
                'malicious_packets': malicious_alerts, 
                'malicious_count': len(malicious_alerts),
                'flowchart_path': flowchart_data, 
                'report_path': report_html_path,
                'malicious_pcap_path': rel_malicious,
                'malformed_pcap_path': rel_malformed,
                'total_packets': len(captured_packets),
                'abuse_data': abuse_data,
                'http_headers': http_headers_list
            },
            'terminal_output': f"Live Analysis Complete. Analyzed {len(captured_packets)} packets. (Incl. {len(unified_alerts)} External Alerts)"
        }
        
        request.session['pcap_results'] = session_data
        
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        
        return redirect('pcap_results')
        
    except Exception as e:
        traceback.print_exc() 
        if temp_file_path and os.path.exists(temp_file_path):
            os.remove(temp_file_path)
        return render(request, 'sniffapp/sniff.html', {'message': f'Analysis Error: {e}'})
# sniffapp/consumers.py
import json
import os
import time
import traceback
import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from asgiref.sync import sync_to_async  # NEW IMPORT ADDED HERE
from django.conf import settings
from django.core.cache import cache
from . import sniffer

# --- HELPER: DETECT OPEN PORTS ---
def detect_open_ports(packets):
    from scapy.layers.inet import TCP, IP
    from scapy.layers.inet6 import IPv6
    
    open_ports = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(TCP) and pkt[TCP].flags == 0x12: # SYN-ACK (0x12)
            src_ip = None
            if pkt.haslayer(IP): src_ip = pkt[IP].src
            elif pkt.haslayer(IPv6): src_ip = pkt[IPv6].src
            
            if src_ip: 
                open_ports[src_ip].add(pkt[TCP].sport)
    
    return {k: sorted(list(v)) for k, v in open_ports.items()}

# --- HELPER: EXTRACT CN ---
def extract_cn_from_subject(subject_str):
    if not subject_str: return "-"
    match = re.search(r'CN=([^,]+)', subject_str)
    return match.group(1) if match else "-"

# --- HELPER: CASE-INSENSITIVE HEADER GETTER ---
def get_header(headers, key):
    """Finds a header value ignoring case (User-Agent == user-agent)."""
    if not headers: return '-'
    key_lower = key.lower()
    for k, v in headers.items():
        if k.lower() == key_lower:
            return v
    return '-'

class SnifferConsumer(AsyncWebsocketConsumer):
    group_name = sniffer.SNIFF_GROUP_NAME

    async def connect(self):
        await self.channel_layer.group_add(self.group_name, self.channel_name)
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.group_name, self.channel_name)
        print("[Consumer] WebSocket disconnected. Stopping sniffer...")
        await sync_to_async(sniffer.stop_sniffer)()

    async def receive(self, text_data=None, bytes_data=None):
        try:
            data = json.loads(text_data or '{}')
            action = data.get('action')
            
            print(f"[Consumer] Received action: {action}")

            async def send_json(content):
                await self.send(text_data=json.dumps(content))

            if action == 'start':
                await sync_to_async(sniffer.clear_packets)()
                bpf = data.get('bpf')
                if bpf and bpf.strip().isdigit():
                    bpf = f"port {bpf.strip()}"

                iface = data.get('iface')
                # Wrap start in sync_to_async to prevent blocking
                started = await sync_to_async(sniffer.start_sniffer)(bpf_filter=bpf, iface=iface)
                status_msg = 'started' if started else 'already_running'
                await send_json({'status': status_msg})

            elif action == 'stop':
                # Wrap stop in sync_to_async so the UI doesn't freeze
                stopped = await sync_to_async(sniffer.stop_sniffer)()
                await send_json({'status': 'stopped'})

            elif action == 'clear':
                await sync_to_async(sniffer.clear_packets)()
                await send_json({'status': 'cleared'})

            elif action == 'download':
                media_root = Path(settings.MEDIA_ROOT)
                media_root.mkdir(parents=True, exist_ok=True)
                filename = f'capture_{int(time.time())}.pcap'
                outpath = media_root / filename
                
                ok = await sync_to_async(sniffer.export_pcap)(str(outpath))
                if ok:
                    await send_json({'download_url': settings.MEDIA_URL + filename})
                else:
                    await send_json({'error': 'no_packets'})
            
            elif action == 'analyze':
                print("[Consumer] Starting analysis...")
                packets = await sync_to_async(sniffer.get_packets_without_stopping)()
                
                if not packets:
                    await send_json({'error': 'no_packets'})
                    return
                
                media_root = Path(settings.MEDIA_ROOT) / 'temp_pcaps'
                media_root.mkdir(parents=True, exist_ok=True)
                temp_filename = f'live_capture_{int(time.time())}.pcap'
                temp_path = media_root / temp_filename
                
                from scapy.all import wrpcap
                await sync_to_async(wrpcap)(str(temp_path), packets)
                
                result = await self.perform_analysis(str(temp_path), packets)
                
                if result['success']:
                    await send_json({
                        'status': 'analysis_complete',
                        'redirect_url': result['redirect_url']
                    })
                else:
                    await send_json({'error': result.get('error', 'Analysis failed')})
        
        except Exception as e:
            traceback.print_exc()
            await self.send(text_data=json.dumps({'error': str(e)}))

    @database_sync_to_async
    def perform_analysis(self, file_path, packets):
        try:
            from pages.utils.analysis import analyze_pcap_for_stats
            from pages.utils.malformed_detector import analyze_pcap_for_malformed
            from pages.utils.malicious_detector import analyze_pcap_for_malicious
            from pages.utils.http_objects_extractor_scapy import extract_http_objects_scapy
            from pages.utils.protocols_dist import protocol_distribution
            from pages.utils.credentials_extractor import extract_credentials
            from pages.utils.geo_ip import get_geo_data
            from pages.utils.abuse_checker import check_abuseipdb
            from pages.utils.flowchart_maker import create_flow_diagram
            from pages.utils.report_maker import pdf_and_html_report_maker
            from pages.utils.IP_hosts import analyze_hosts, analyze_ip_pairs
            from pages.utils.macs import get_mac_addresses
            from pages.utils.pcap_analyzer import analyze_pcap
            from pages.utils.tls_analyzer import get_ja3_fingerprint, analyze_tls_server, fetch_active_cert
            from scapy.all import IP, wrpcap, Raw
            
            print("[Analysis] Step 1: Analyzing Malformed Packets")
            malformed_rule_file = os.path.join(settings.BASE_DIR, 'pages', 'rules', 'rules_for_malformed.rules')
            malformed_alerts, malformed_pkts = analyze_pcap_for_malformed(packets, malformed_rule_file)
            malformed_count = len(malformed_alerts)
            
            output_dir = os.path.join(settings.MEDIA_ROOT, 'resulting_pcap_files')
            os.makedirs(output_dir, exist_ok=True)
            malformed_pcap_path = os.path.join(output_dir, 'malformed.pcap')
            if malformed_pkts: wrpcap(malformed_pcap_path, malformed_pkts)
            
            print("[Analysis] Step 2: Analyzing Malicious Packets")
            malicious_rule_file = os.path.join(settings.BASE_DIR, 'pages', 'rules', 'rules_for_malicious.rules')
            malicious_alerts, malicious_pkts = analyze_pcap_for_malicious(packets, malicious_rule_file)
            
            # =================================================================
            # UNIFIED ALERT & HEADER PROCESSING (Dynamic Protocol Label)
            # =================================================================
            unified_alerts = sniffer.get_and_clear_waf_alerts()
            http_headers_list = []
            waf_counter = 1
            
            from datetime import datetime as dt
            
            for item in unified_alerts:
                if not isinstance(item, dict): continue

                if 'msg' in item and 'sid' in item and 'headers' not in item:
                    formatted_alert = {
                        'msg': f"[IDS] {item.get('msg', 'Threat Detected')}",
                        'sid': item.get('sid', '0'),
                        'payload': item.get('payload', 'Suricata Detected Activity'),
                        'packet_num': "IDS-Log",
                        'src': item.get('src', 'N/A'),
                        'dst': item.get('dst', 'N/A'),
                        'proto': item.get('proto', 'N/A'),
                        'severity': 'HIGH'
                    }
                    malicious_alerts.append(formatted_alert)

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
            from scapy.layers.inet import TCP
            for pkt in packets:
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

            malicious_count = len(malicious_alerts)
            malicious_pcap_path = os.path.join(output_dir, 'malicious.pcap')
            if malicious_pkts: wrpcap(malicious_pcap_path, malicious_pkts)
            
            print("[Analysis] Step 3: Extracting HTTP Objects")
            http_objects_data = extract_http_objects_scapy(file_path)
            web_objects = []
            for obj in http_objects_data:
                web_objects.append({
                    'path': obj['path'], 'md5': obj['md5'],
                    'filename': obj['filename'], 'type': obj['type'], 'size': obj['size']
                })
            
            print("[Analysis] Step 4-6: General Analysis")
            protocol_data = protocol_distribution(packets)
            credentials = extract_credentials(packets)
            geo_location_data, all_ips_list = get_geo_data(packets)
            
            print("[Analysis] Step 6.5: Detecting Open Ports")
            open_ports_data = detect_open_ports(packets)

            all_ips_for_abuse = []
            for pkt in packets:
                if IP in pkt:
                    all_ips_for_abuse.append(pkt[IP].src)
                    all_ips_for_abuse.append(pkt[IP].dst)
            abuse_data = check_abuseipdb(all_ips_for_abuse)

            print("[Analysis] Step 7: TLS Analysis")
            tls_ja3_data = []
            tls_aggregation = {} 
            ip_to_sni = {}

            for packet in packets:
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
                                'server_ip': s_ip, 
                                'server_name': discovered_name,
                                'subject': "Unknown Service", 
                                'issuer': "-",
                                'not_valid_before': "-", 'not_valid_after': "-", 
                                'is_expired': False,
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
                    except Exception: pass

            tls_certs_final = list(tls_aggregation.values())
            for item in tls_certs_final:
                if item['protocol_version'] and "TLS" not in item['subject'] and item['subject'] != "Unknown Service":
                      item['subject'] = f"{item['subject']} [{item['protocol_version']}]"
            
            print("[Analysis] Step 8-10: Flowchart, Report, Finalizing")
            flowchart_data = create_flow_diagram(file_path, packets)
            sessions_data = analyze_hosts(packets)
            hosts_data_result = analyze_ip_pairs(packets)
            
            ip_pairs_v4 = hosts_data_result.get('ipv4_pairs', {})
            ip_pairs_v6 = hosts_data_result.get('ipv6_pairs', {})
            
            mac_data = get_mac_addresses(packets)
            
            report_paths = pdf_and_html_report_maker(
                packets, file_path, malicious_count=malicious_count, malformed_count=malformed_count
            )
            
            analysis_data = analyze_pcap(malformed_alerts, packets, file_path)
            stats_full = analyze_pcap_for_stats(packets)
            timeline_data = stats_full.get('timeline_data', {})
            report_html_path = os.path.relpath(report_paths[1], settings.MEDIA_ROOT) if report_paths and len(report_paths) > 1 else ""
            
            session_key = f'live_analysis_{int(time.time())}'
            session_data = {
                'data': {
                    **analysis_data['analysis_results'],
                    'protocol_distribution': dict(protocol_data),
                    'credentials': credentials,
                    'http_objects': web_objects,
                    'flowchart_path': flowchart_data,
                    'report_path': report_html_path,
                    'alerts': malformed_alerts,
                    'malformed_count': malformed_count,
                    'malicious_packets': malicious_alerts, 
                    'malicious_count': malicious_count,
                    'sessions_data': sessions_data,
                    'hosts_data': hosts_data_result,
                    'ip_pairs_v4': ip_pairs_v4, 
                    'ip_pairs_v6': ip_pairs_v6, 
                    'geo_data': geo_location_data,
                    'all_geo_ips': all_ips_list,
                    'open_ports': open_ports_data, 
                    'unique_src_macs': mac_data.get('unique_src_macs', []),
                    'unique_dst_macs': mac_data.get('unique_dst_macs', []),
                    'mac_pairs': mac_data.get('mac_pairs', []),
                    'total_unique_macs': mac_data.get('total_unique_macs', 0),
                    'tls_ja3': tls_ja3_data,
                    'tls_certs': tls_certs_final,
                    'abuse_data': abuse_data,
                    'malicious_pcap_path': os.path.relpath(malicious_pcap_path, settings.MEDIA_ROOT) if malicious_pcap_path else "",
                    'malformed_pcap_path': os.path.relpath(malformed_pcap_path, settings.MEDIA_ROOT) if malformed_pcap_path else "",
                    'total_packets': len(packets),
                    'timeline_data': timeline_data,
                    'http_headers': http_headers_list
                },
                'terminal_output': f"Live Analysis Complete. Analyzed {len(packets)} packets. (Incl. {len(unified_alerts)} External Alerts)"
            }
            
            cache.set(session_key, session_data, 300)
            if os.path.exists(file_path): os.remove(file_path)
            
            return {
                'success': True, 
                'redirect_url': f'/analysis-success/{session_key}/'
            }
            
        except Exception as e:
            print(f"[Analysis] CRITICAL ERROR: {str(e)}")
            traceback.print_exc()
            return {'success': False, 'error': str(e)}

    async def packet_message(self, event):
        if 'message' in event:
            await self.send(text_data=json.dumps(event['message']))
        else:
            await self.send(text_data=json.dumps(event))
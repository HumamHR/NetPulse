# pages/views.py

from ast import arguments
import json
from django.shortcuts import render
import requests
import ipaddress
from django.conf import settings

from pages.utils.IP_hosts import analyze_hosts, analyze_ip_pairs
from pages.utils.malicious_detector import analyze_pcap_for_malicious, save_malicious_packets

################ home page function ################
def index(request) :
    return render( request , 'pages/index.html' )


################ login page function ################
def login(request) :
    return render( request , 'pages/login.html' )


################ ipinfo page function ################
def get_ip_info(ip_address):
    access_token = settings.IPINFO_TOKEN
    url = f"https://ipinfo.io/{ip_address}?token={access_token}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def is_valid_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def ipinfo(request):  
    context = {}
    
    if request.method == "POST":
        ip = request.POST.get("ip_address", "").strip()
        
        if ip and is_valid_ip(ip):
            ip_info = get_ip_info(ip)
            context["ip"] = ip
            context["ip_info"] = ip_info
        else:
            context["error"] = "Invalid IP address."
    
    return render(request, "pages/ip_info.html", context)

from django.shortcuts import render
import socket
import concurrent.futures

def scan_single_port(ip, port):
    """Helper function to scan a single port."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.05)
        result = sock.connect_ex((ip, port))
        sock.close()

        if result == 0:
            try:
                service_name = socket.getservbyport(port, "tcp")
            except:
                service_name = "Unknown"
            
            return {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": service_name,
            }
    except:
        pass
    return None

def port_scan(request):
    scan_results = None
    error_message = None

    if request.method == "POST":
        target = "Localhost"
        target_ip = "127.0.0.1"
        scan_type = request.POST.get("scan_type", "fat")

        try:
            if scan_type == "fat":
                ports = list(range(1, 1025))
            elif scan_type == "confined":
                try:
                    start = int(request.POST.get("start_port", "1"))
                    end = int(request.POST.get("end_port", "100"))
                    start = max(1, min(start, 65535))
                    end = max(1, min(end, 65535))
                    real_start = min(start, end)
                    real_end = max(start, end)
                    ports = list(range(real_start, real_end + 1))
                except ValueError:
                    error_message = "Invalid port range."
                    return render(request, "pages/port_scan.html", {"error_message": error_message})
            else:
                ports = list(range(1, 65536))

            if len(ports) > 10000:
                ports = ports[:10000]

            open_ports = []
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
                future_to_port = {executor.submit(scan_single_port, target_ip, port): port for port in ports}
                
                for future in concurrent.futures.as_completed(future_to_port):
                    result = future.result()
                    if result:
                        open_ports.append(result)

            open_ports.sort(key=lambda x: x['port'])

            scan_results = {
                "ip_address": target_ip,
                "hostname": target,
                "state": "up",
                "open_ports": open_ports
            }

        except Exception as e:
            error_message = f"Scan error: {str(e)}"

    return render(request, "pages/port_scan.html", {
        "scan_results": scan_results,
        "error_message": error_message
    })

from django.shortcuts import render, redirect
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse, StreamingHttpResponse
from django.urls import reverse
import os
from pages.utils.pcap_analyzer import analyze_pcap
import requests
import ipaddress
import nmap
from io import StringIO
from contextlib import redirect_stdout

# Re-declare some views that are also in this file (consolidated)
def index(request):
    return render(request, 'pages/index.html')

def login(request):
    return render(request, 'pages/login.html')

def get_ip_info(ip_address):
    access_token = settings.IPINFO_TOKEN
    url = f"https://ipinfo.io/{ip_address}?token={access_token}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}

def is_valid_ip(ip_address):
    try:
        ipaddress.ip_address(ip_address)
        return True
    except ValueError:
        return False

def ipinfo(request):  
    context = {}
    if request.method == "POST":
        ip = request.POST.get("ip_address", "").strip()
        if ip and is_valid_ip(ip):
            ip_info = get_ip_info(ip)
            context["ip"] = ip
            context["ip_info"] = ip_info
            context["ip_submitted"] = True
        else:
            context["error"] = "Invalid IP address."
            context["ip_submitted"] = False
    else:
        context["ip_submitted"] = False

    return render(request, "pages/ip_info.html", context)

def port_scan(request):
    scan_results = None
    error_message = None
    if request.method == "POST":
        target = request.POST.get("target")
        if target:
            nm = nmap.PortScanner()
            try:
                nm.scan(target, arguments="-A -T5")
                if target in nm.all_hosts():
                    host_data = nm[target]
                    scan_results = {
                        "ip_address": target,
                        "state": host_data.state(),
                        "hostname": host_data.hostname(),
                        "os_matches": host_data.get("osmatch", []),
                        "open_ports": [],
                    }
                    for port, details in host_data.get("tcp", {}).items():
                        scan_results["open_ports"].append({
                            "port": port,
                            "state": details.get("state", "unknown"),
                            "service": details.get("name", "unknown"),
                            "product": details.get("product", "unknown"),
                            "version": details.get("version", "unknown"),
                        })
                else:
                    error_message = "No results found. The target may be unreachable."
            except nmap.PortScannerError as e:
                error_message = f"Nmap error: {str(e)}"
            except Exception as e:
                error_message = f"Unexpected error: {str(e)}"
        else:
            error_message = "Please enter a valid IP or domain."
    return render(request, "pages/port_scan.html", {"scan_results": scan_results, "error_message": error_message})

# =============================================
# PCAP Upload & Analysis Views
# =============================================

import os
import time
import json
import re
from collections import defaultdict
from django.conf import settings
from django.shortcuts import render, redirect
from django.http import JsonResponse, FileResponse, HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.core.cache import cache
from scapy.all import rdpcap, wrpcap, IP, IPv6, TCPSession, TCP, Raw
from scapy.layers.inet import TCP as ScapyTCP
from datetime import datetime as dt

from pages.utils.http_objects_extractor import extract_http_objects
from pages.utils.http_objects_extractor_scapy import extract_http_objects_scapy
from pages.utils.flowchart_maker import create_flow_diagram
from pages.utils.report_maker import pdf_and_html_report_maker
from pages.utils.malformed_detector import analyze_pcap_for_malformed
from pages.utils.malicious_detector import analyze_pcap_for_malicious, save_malicious_packets
from pages.utils.IP_hosts import analyze_hosts, analyze_ip_pairs
from pages.utils.macs import get_mac_addresses
from pages.utils.credentials_extractor import extract_credentials
from pages.utils.pcap_analyzer import analyze_pcap
from pages.utils.protocols_dist import protocol_distribution
from pages.utils.geo_ip import get_geo_data
from pages.utils.abuse_checker import check_abuseipdb
from pages.utils.tls_analyzer import get_ja3_fingerprint, analyze_tls_server, fetch_active_cert

# --- HELPER: Detect Open Ports ---
def detect_open_ports(packets):
    open_ports = defaultdict(set)
    for pkt in packets:
        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            if flags == 0x12:  # SYN+ACK
                src_ip = None
                if pkt.haslayer(IP): src_ip = pkt[IP].src
                elif pkt.haslayer(IPv6): src_ip = pkt[IPv6].src
                
                if src_ip:
                    open_ports[src_ip].add(pkt[TCP].sport)
    return {k: sorted(list(v)) for k, v in open_ports.items()}

def extract_cn_from_subject(subject_str):
    if not subject_str: return "-"
    match = re.search(r'CN=([^,]+)', subject_str)
    if match: return match.group(1)
    return "-"

# --- HELPER: Case-insensitive header getter ---
def get_header(headers, key):
    """Finds a header value ignoring case (User-Agent == user-agent)."""
    if not headers: return '-'
    key_lower = key.lower()
    for k, v in headers.items():
        if k.lower() == key_lower:
            return v
    return '-'

# --- HELPER: Save malformed packets ---
def save_malformed_packets(malformed_packets):
    output_dir = os.path.join(settings.MEDIA_ROOT, 'resulting_pcap_files')
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, 'malformed.pcap')
    if malformed_packets:
        wrpcap(output_path, malformed_packets)
    return output_path

def upload(request):
    if request.method == 'POST' and request.FILES.get('pcap_file'):
        file_path = None
        try:
            # --- FILE SAVING ---
            pcap_file = request.FILES['pcap_file']
            upload_dir = os.path.join(settings.MEDIA_ROOT, 'temp_pcaps')
            os.makedirs(upload_dir, exist_ok=True)
            file_path = os.path.join(upload_dir, pcap_file.name)
            
            with open(file_path, 'wb+') as destination:
                for chunk in pcap_file.chunks():
                    destination.write(chunk)
            
            # --- PACKET LOADING ---
            try:
                packets = rdpcap(file_path, session=TCPSession)
            except Exception:
                packets = rdpcap(file_path)
            
            # --- ANALYSIS MODULES ---
            malformed_rule_file = os.path.join(settings.BASE_DIR, 'pages', 'rules', 'rules_for_malformed.rules')
            malformed_alerts, malformed_pkts = analyze_pcap_for_malformed(packets, malformed_rule_file)
            malformed_count = len(malformed_alerts)
            malformed_pcap_path = save_malformed_packets(malformed_pkts)
            
            malicious_rule_file = os.path.join(settings.BASE_DIR, 'pages', 'rules', 'rules_for_malicious.rules')
            malicious_alerts, malicious_pkts = analyze_pcap_for_malicious(packets, malicious_rule_file)

            # WAF Alerts Merge
            waf_alerts = cache.get('current_waf_alerts', [])
            waf_counter = 1
            if waf_alerts:
                for waf in waf_alerts:
                    synthetic_alert = {
                        'msg': f"[WAF BLOCK] {waf.get('reason', 'Malicious Request')}",
                        'sid': f"WAF-{1000 + waf_counter}",
                        'payload': waf.get('threat', {}).get('payload', 'No Payload'),
                        'packet_num': "HTTPS",
                        'src': waf.get('src', 'WAF'),
                        'dst': waf.get('dst', 'Target'),
                        'proto': 'HTTPS',
                        'severity': 'HIGH'
                    }
                    malicious_alerts.append(synthetic_alert)
                    waf_counter += 1

            malicious_count = len(malicious_alerts)
            malicious_pcap_path = save_malicious_packets(malicious_pkts)

            # HTTP Objects
            web_objects = []
            try:
                http_objects_data = extract_http_objects_scapy(file_path)
                if not http_objects_data:
                    http_objects_data = extract_http_objects(file_path)
                for obj in http_objects_data:
                    web_objects.append(obj)
            except:
                web_objects = []

            # Stats & protocols
            protocol_data = protocol_distribution(packets)
            credentials = extract_credentials(packets)
            geo_location_data, all_ips_list = get_geo_data(packets)

            # AbuseIPDB Check
            all_ips_for_abuse = []
            for pkt in packets:
                if IP in pkt:
                    all_ips_for_abuse.extend([pkt[IP].src, pkt[IP].dst])
            abuse_data = check_abuseipdb(all_ips_for_abuse)

            # Open Ports
            open_ports_data = detect_open_ports(packets)

            # =================================================================
            # HTTP HEADERS EXTRACTION (NEW - FIX FOR OFFLINE PCAP)
            # =================================================================
            http_headers_list = []
            
            print("[HTTP Headers] Extracting HTTP headers from offline PCAP...")
            
            for pkt in packets:
                if pkt.haslayer(TCP):
                    try:
                        # CRITICAL FIX: Use bytes(pkt[TCP].payload) to get the full raw 
                        # content (Headers + Body) bypassing Scapy's automatic HTTP dissection
                        payload = bytes(pkt[TCP].payload)
                        
                        if not payload or len(payload) < 10:
                            continue
                        
                        # A. HTTP Requests (GET, POST, etc.)
                        if payload.startswith((b'GET ', b'POST ', b'PUT ', b'HEAD ', b'DELETE ', b'PATCH ', b'OPTIONS ')):
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
                                    elif not line:
                                        break
                                
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
                            except Exception as e:
                                pass
                        
                        # B. HTTP Responses (HTTP/1.1 200 OK, etc.)
                        elif payload.startswith(b'HTTP/'):
                            try:
                                text = payload.decode('utf-8', 'ignore')
                                lines = text.split('\r\n')
                                status_line = lines[0].split(' ')
                                status_code = status_line[1] if len(status_line) > 1 else '0'
                                
                                headers = {}
                                for line in lines[1:]:
                                    if ': ' in line:
                                        k, v = line.split(': ', 1)
                                        headers[k] = v
                                    elif not line:
                                        break
                                
                                ts = dt.fromtimestamp(float(pkt.time)).strftime('%H:%M:%S')
                                
                                # Determine which host from headers
                                host = get_header(headers, 'Server') or get_header(headers, 'Host') or '-'
                                
                                http_headers_list.append({
                                    'timestamp': ts,
                                    'type': 'HTTP Response',
                                    'method': status_code,
                                    'host': host,
                                    'url': '-',
                                    'user_agent': '-',
                                    'full_headers': headers
                                })
                            except Exception as e:
                                pass
                            
                    except Exception as e:
                        pass
            
            print(f"[HTTP Headers] Extracted {len(http_headers_list)} header entries from offline PCAP")
            # =================================================================

            # TLS Analysis
            tls_ja3_data = []
            tls_aggregation = {}
            ip_to_sni = {}
            
            for packet in packets:
                ja3 = get_ja3_fingerprint(packet)
                if ja3:
                    tls_ja3_data.append(ja3)
                    if ja3.get('sni') and ja3['sni'] != "Unknown":
                        if ja3.get('dest_ip') and ja3['dest_ip'] != "Unknown":
                            ip_to_sni[ja3['dest_ip']] = ja3['sni']
                
                srv_res = analyze_tls_server(packet)
                if srv_res:
                    for res in srv_res:
                        s_ip = res.get('server_ip')
                        if s_ip not in tls_aggregation:
                            tls_aggregation[s_ip] = {
                                'server_ip': s_ip, 'server_name': "-", 'subject': "Unknown Service",
                                'issuer': "-", 'not_valid_before': "-", 'not_valid_after': "-",
                                'is_expired': False, 'is_self_signed': False, 'protocol_version': ""
                            }
                        if res['type'] == 'ServerHello':
                            clean_ver = res['subject'].replace("Handshake: ", "")
                            tls_aggregation[s_ip]['protocol_version'] = clean_ver
                            tls_aggregation[s_ip]['issuer'] = res['issuer']
                            if tls_aggregation[s_ip]['subject'] == "Unknown Service":
                                tls_aggregation[s_ip]['subject'] = f"Service ({clean_ver})"
                            if res['is_expired']:
                                tls_aggregation[s_ip]['is_expired'] = True
                        elif res['type'] == 'Certificate':
                            cn = extract_cn_from_subject(res['subject'])
                            tls_aggregation[s_ip].update({
                                'server_name': cn, 'subject': res['subject'], 'issuer': res['issuer'],
                                'not_valid_before': res['not_valid_before'], 'not_valid_after': res['not_valid_after'],
                                'is_self_signed': res['is_self_signed']
                            })
                            if res['is_expired']:
                                tls_aggregation[s_ip]['is_expired'] = True

            # Active Enrichment for missing cert data
            for s_ip, data in tls_aggregation.items():
                if data['not_valid_before'] == "-" or "TLS 1.3" in data.get('protocol_version', ''):
                    try:
                        active = fetch_active_cert(s_ip)
                        if active:
                            cn = extract_cn_from_subject(active['subject'])
                            data.update({
                                'server_name': cn, 'subject': active['subject'], 'issuer': active['issuer'],
                                'not_valid_before': active['not_valid_before'], 'not_valid_after': active['not_valid_after'],
                                'is_expired': active['is_expired'], 'is_self_signed': active['is_self_signed']
                            })
                    except:
                        pass
            
            tls_certs_final = list(tls_aggregation.values())

            # Flowchart & Hosts
            flowchart_data = create_flow_diagram(file_path, packets)
            sessions_data = analyze_hosts(packets)
            
            hosts_data_result = analyze_ip_pairs(packets)
            ip_pairs_v4 = hosts_data_result.get('ipv4_pairs', {})
            ip_pairs_v6 = hosts_data_result.get('ipv6_pairs', {})
            
            mac_data = get_mac_addresses(packets)

            # Reports
            report_paths = pdf_and_html_report_maker(
                packets, file_path, malicious_count=malicious_count, malformed_count=malformed_count
            )
            report_html_path = os.path.relpath(report_paths[1], settings.MEDIA_ROOT) if report_paths and len(report_paths) > 1 else ""

            # Analysis Data & Timeline
            analysis_data = analyze_pcap(malformed_alerts, packets, file_path)
            from pages.utils.analysis import analyze_pcap_for_stats
            stats_full = analyze_pcap_for_stats(packets)
            timeline_data = stats_full.get('timeline_data', {})

            # =================================================================
            # BUILD SESSION DATA (with http_headers included)
            # =================================================================
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
                    'http_headers': http_headers_list,  # ← ADDED HTTP HEADERS
                },
                'terminal_output': analysis_data['terminal_output']
            }
            
            request.session['pcap_results'] = session_data
            if os.path.exists(file_path):
                os.remove(file_path)
            
            return JsonResponse({'status': 'success', 'redirect_url': reverse('pcap_results')})
            
        except Exception as e:
            import traceback
            traceback.print_exc()
            if file_path and os.path.exists(file_path):
                os.remove(file_path)
            return JsonResponse({'status': 'error', 'message': str(e)}, status=400)
            
    return render(request, 'pages/upload.html')


def pcap_results(request):
    results_data = request.session.get('pcap_results', {})
    data = results_data.get('data', {})
    
    # 1. MAC Data
    mac_data = {
        'unique_src_macs': data.get('unique_src_macs', []),
        'unique_dst_macs': data.get('unique_dst_macs', []),
        'mac_pairs': data.get('mac_pairs', {}),
        'total_unique_macs': data.get('total_unique_macs', 0)
    }

    # 2. Protocol Distribution
    raw_proto_dist = data.get('protocol_distribution', {})
    sorted_chart_data = dict(sorted(raw_proto_dist.items(), key=lambda item: item[1], reverse=True))

    # 3. Connection Sessions
    def clean_pairs(raw_pairs):
        cleaned = {}
        if isinstance(raw_pairs, dict):
            for key, count in raw_pairs.items():
                if isinstance(key, (list, tuple)):
                    new_key = f"{key[0]} -> {key[1]}"
                    cleaned[new_key] = count
                else:
                    cleaned[key] = count
        return cleaned

    ip_pairs_v4 = clean_pairs(data.get('ip_pairs_v4', {}))
    ip_pairs_v6 = clean_pairs(data.get('ip_pairs_v6', {}))

    # 4. Alerts
    raw_alerts = data.get('alerts', [])
    parsed_alerts = []
    for alert in raw_alerts:
        match = re.search(r'\[Packet:\s*(\d+)\]', alert)
        if match:
            clean_msg = alert.replace(match.group(0), '').strip()
            parsed_alerts.append({'msg': clean_msg, 'packet_num': match.group(1)})
        else:
            parsed_alerts.append({'msg': alert, 'packet_num': '-'})

    # 5. Max Count for sessions
    all_counts = list(ip_pairs_v4.values()) + list(ip_pairs_v6.values())
    max_count = 1
    if all_counts:
        max_count = max(all_counts)

    return render(request, 'pages/pcap_results.html', {
        'data': data,
        'terminal_output': results_data.get('terminal_output', ''),
        'results': data,
        'protocol_distribution': sorted_chart_data,
        'credentials': data.get('credentials', []),
        'http_objects': data.get('http_objects', []),
        'flowchart_path': data.get('flowchart_path'),
        'report_path': data.get('report_path'),
        'alerts': parsed_alerts,
        'malformed_count': data.get('malformed_count', 0),
        'malicious_packets': data.get('malicious_packets', []),
        'malicious_count': data.get('malicious_count', 0),
        'sessions_data': data.get('sessions_data', {}),
        'hosts_data': data.get('hosts_data', {}),
        'ip_pairs_v4': ip_pairs_v4,
        'ip_pairs_v6': ip_pairs_v6,
        'ip_pairs': {**ip_pairs_v4, **ip_pairs_v6},
        'max_count': max_count,
        'mac_data': mac_data,
        'total_packets': data.get('total_packets', 0),
        'open_ports': data.get('open_ports', {}),
    })


def download_file(request):
    relative_path = request.GET.get('path', '')
    safe_path = os.path.join(settings.MEDIA_ROOT, os.path.normpath(relative_path))
    if os.path.exists(safe_path) and safe_path.startswith(settings.MEDIA_ROOT):
        return FileResponse(open(safe_path, 'rb'), as_attachment=True)
    return JsonResponse({'error': 'File not found'}, status=404)


def download_malicious_pcap(request):
    results_data = request.session.get('pcap_results', {}).get('data', {})
    rel_path = results_data.get('malicious_pcap_path', '')
    abs_path = os.path.join(settings.MEDIA_ROOT, os.path.normpath(rel_path))
    if os.path.exists(abs_path) and abs_path.startswith(settings.MEDIA_ROOT):
        return FileResponse(open(abs_path, 'rb'), as_attachment=True)
    return JsonResponse({'error': 'Malicious PCAP not found'}, status=404)


def download_malformed_pcap(request):
    results_data = request.session.get('pcap_results', {}).get('data', {})
    rel_path = results_data.get('malformed_pcap_path', '')
    abs_path = os.path.join(settings.MEDIA_ROOT, os.path.normpath(rel_path))
    if os.path.exists(abs_path) and abs_path.startswith(settings.MEDIA_ROOT):
        return FileResponse(open(abs_path, 'rb'), as_attachment=True, filename='malformed_packets.pcap')
    return JsonResponse({'error': 'Malformed PCAP not found'}, status=404)


def view_report(request):
    report_path = request.session.get('pcap_results', {}).get('data', {}).get('report_path')
    if report_path:
        full_path = os.path.join(settings.MEDIA_ROOT, report_path)
        if os.path.exists(full_path):
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    return HttpResponse(f.read(), content_type='text/html')
            except UnicodeDecodeError:
                with open(full_path, 'r', encoding='ascii', errors='replace') as f:
                    return HttpResponse(f.read(), content_type='text/html')
    return HttpResponseRedirect(reverse('pcap_results'))


def download_report(request):
    report_path = request.session.get('pcap_results', {}).get('data', {}).get('report_path')
    if report_path:
        pdf_path = report_path.replace('.html', '.pdf')
        full_path = os.path.join(settings.MEDIA_ROOT, pdf_path)
        if not os.path.exists(full_path):
            full_path = os.path.join(settings.MEDIA_ROOT, report_path)
        if os.path.exists(full_path):
            return FileResponse(open(full_path, 'rb'), as_attachment=True)
    return HttpResponseRedirect(reverse('pcap_results'))


# VirusTotal API integration
API_KEY = settings.VIRUSTOTAL_API_KEY
HEADERS = {
    'x-apikey': API_KEY,
}

def get_analysis_result(analysis_id):
    for _ in range(5):
        response = requests.get(
            f'https://www.virustotal.com/api/v3/analyses/{analysis_id}',
            headers=HEADERS
        )
        data = response.json()
        if data['data']['attributes']['status'] == 'completed':
            return data
        time.sleep(2)
    return None

def virus_total(request):
    if request.method == 'POST':
        url = request.POST.get('url')
        file = request.FILES.get('file')
        file_hash = request.POST.get('hash')

        result = None

        if url:
            url_response = requests.post(
                'https://www.virustotal.com/api/v3/urls',
                headers=HEADERS,
                data={'url': url}
            )
            analysis_id = url_response.json()['data']['id']
            result = get_analysis_result(analysis_id)

        elif file:
            files = {'file': (file.name, file.read())}
            file_response = requests.post(
                'https://www.virustotal.com/api/v3/files',
                headers=HEADERS,
                files=files
            )
            analysis_id = file_response.json()['data']['id']
            result = get_analysis_result(analysis_id)
            
        elif file_hash:
            hash_response = requests.get(
                f'https://www.virustotal.com/api/v3/files/{file_hash}',
                headers=HEADERS
            )
            if hash_response.status_code == 200:
                result = hash_response.json()
            else:
                result = {'error': 'Hash not found in VirusTotal database'}

        return render(request, 'pages/virustotal_result.html', {'result': result})

    return render(request, 'pages/virustotal.html')


def upload_progress(request):
    file_name = request.GET.get('file_name', '')
    
    def event_stream():
        for progress in range(0, 101, 10):
            time.sleep(0.5)
            
            if progress < 30:
                message = "Uploading file..."
            elif progress < 70:
                message = "Analyzing network traffic..."
            else:
                message = "Generating reports..."
            
            yield f"data: {json.dumps({'progress': progress, 'message': message})}\n\n"
        
        yield f"data: {json.dumps({'status': 'complete', 'progress': 100, 'redirect_url': reverse('pcap_results')})}\n\n"
    
    response = StreamingHttpResponse(event_stream(), content_type='text/event-stream')
    response['Cache-Control'] = 'no-cache'
    return response


def ip_analysis(request):
    """Render the network tools selection page"""
    return render(request, 'pages/ip_analysis.html')


# =============================================
# Email Analysis Views
# =============================================

import re
import json
import requests
import dns.resolver
from django.shortcuts import render
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views import View
import logging

logger = logging.getLogger(__name__)

class EmailAnalysisView(View):
    def get(self, request):
        return render(request, 'pages/email_analysis.html')


@csrf_exempt
def analyze_email_headers(request):
    if request.method == 'POST':
        try:
            if request.content_type == 'application/json':
                data = json.loads(request.body)
                email_headers = data.get('email_headers', '')
            else:
                email_headers = request.POST.get('email_headers', '')

            if not email_headers:
                return JsonResponse({'error': 'No email headers provided'}, status=400)

            parsed_data = parse_email_headers(email_headers)

            from_email = parsed_data.get('from_email')
            if from_email:
                domain = from_email.split('@')[-1]
                parsed_data['spf_status'] = check_spf(domain)
                parsed_data['dmarc_status'] = check_dmarc(domain)
                dkim_selector = extract_dkim_selector(email_headers)
                parsed_data['dkim_status'] = check_dkim(domain, dkim_selector)

            if parsed_data.get('sender_ip'):
                geo_data = get_ip_geolocation(parsed_data['sender_ip'])
                parsed_data['geolocation'] = geo_data

            return JsonResponse({'data': parsed_data})

        except Exception as e:
            logger.error(f"Error analyzing email headers: {str(e)}", exc_info=True)
            return JsonResponse({'error': f'Analysis failed: {str(e)}'}, status=500)

    return JsonResponse({'error': 'Method not allowed'}, status=405)


def parse_email_headers(headers_text):
    parsed = {
        'sender_ip': None,
        'from_email': None,
        'from_name': None,
        'subject': None,
        'date': None,
        'received_servers': [],
        'spf_status': None,
        'dkim_status': None,
        'dmarc_status': None,
        'reply_to': None,
        'return_path': None
    }

    combined_headers = []
    current_header = ""

    for line in headers_text.split('\n'):
        line = line.rstrip()
        if not line:
            continue

        if line.startswith((' ', '\t')):
            if current_header:
                current_header += ' ' + line.strip()
        else:
            if current_header:
                combined_headers.append(current_header)
            current_header = line

    if current_header:
        combined_headers.append(current_header)

    for header in combined_headers:
        header_lower = header.lower()

        if header_lower.startswith('from:'):
            from_value = header[5:].strip()
            parsed['from_email'] = extract_email(from_value)
            parsed['from_name'] = extract_name(from_value)

        elif header_lower.startswith('subject:'):
            parsed['subject'] = header[8:].strip()

        elif header_lower.startswith('date:'):
            parsed['date'] = header[5:].strip()

        elif header_lower.startswith('received:'):
            received_data = parse_received_header(header)
            if received_data:
                parsed['received_servers'].append(received_data)
                if received_data.get('from_ip') and not parsed['sender_ip']:
                    parsed['sender_ip'] = received_data['from_ip']

        elif header_lower.startswith('reply-to:'):
            parsed['reply_to'] = extract_email(header[9:].strip())

        elif header_lower.startswith('return-path:'):
            parsed['return_path'] = extract_email(header[12:].strip())

        elif header_lower.startswith('authentication-results:'):
            parse_auth_header(header, parsed)

        elif header_lower.startswith('arc-authentication-results:'):
            parse_auth_header(header, parsed)

        elif header_lower.startswith('received-spf:'):
            parse_received_spf_header(header, parsed)

    if not parsed['sender_ip'] and parsed['received_servers']:
        for server in parsed['received_servers']:
            if server.get('from_ip'):
                parsed['sender_ip'] = server['from_ip']
                break

    return parsed


def parse_auth_header(header, parsed):
    content = header.split(":", 1)[1].strip().lower()

    if not parsed['spf_status']:
        match = re.search(r"spf=(pass|fail|softfail|neutral|none|temperror|permerror)\b", content)
        if match:
            parsed['spf_status'] = {'status': match.group(1), 'color': 'green' if match.group(1) == 'pass' else 'red'}

    if not parsed['dkim_status']:
        match = re.search(r"dkim=(pass|fail|none)\b", content)
        if match:
            parsed['dkim_status'] = {'status': match.group(1), 'color': 'green' if match.group(1) == 'pass' else 'red'}

    if not parsed['dmarc_status']:
        match = re.search(r"dmarc=(pass|fail|bestguesspass|none)\b", content)
        if match:
            parsed['dmarc_status'] = {'status': match.group(1), 'color': 'green' if match.group(1) == 'pass' else 'red'}


def parse_received_spf_header(header, parsed):
    content = header.split(":", 1)[1].strip().lower()
    if parsed['spf_status']:
        return
    match = re.search(r"\b(pass|fail|softfail|neutral|none|temperror|permerror)\b", content)
    if match:
        parsed['spf_status'] = {'status': match.group(1), 'color': 'green' if match.group(1) == 'pass' else 'red'}


def parse_received_header(received_line):
    try:
        content = received_line[9:].strip()
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ip_match = re.search(ip_pattern, content)
        server_pattern = r'from\s+([^\s\]\[\(]+)'
        server_match = re.search(server_pattern, content, re.IGNORECASE)
        return {
            'raw': content,
            'from_server': server_match.group(1) if server_match else 'Unknown',
            'from_ip': ip_match.group() if ip_match else None
        }
    except Exception as e:
        logger.warning(f"Failed to parse received header: {e}")
        return None


def extract_email(text):
    if not text:
        return None
    match = re.search(r'<([^>]+)>', text)
    if match:
        return match.group(1)
    match2 = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', text)
    return match2.group() if match2 else text.strip()


def extract_name(text):
    if not text:
        return None
    name = re.sub(r'<[^>]+>', '', text).strip()
    name = re.sub(r'^["\']|["\']$', '', name).strip()
    return name if name and not re.search(r'@', name) else None


def get_ip_geolocation(ip_address):
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                return {
                    'ip': ip_address,
                    'city': data.get('city'),
                    'region': data.get('regionName'),
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'postal': data.get('zip'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'org': data.get('org'),
                    'asn': data.get('asn'),
                    'isp': data.get('isp')
                }
        response = requests.get(f'http://ipapi.co/{ip_address}/json/', timeout=5)
        if response.status_code == 200:
            data = response.json()
            return {
                'ip': ip_address,
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'country_code': data.get('country_code'),
                'postal': data.get('postal'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
                'timezone': data.get('timezone'),
                'org': data.get('org'),
                'asn': data.get('asn')
            }
    except Exception as e:
        logger.warning(f"Geolocation failed for {ip_address}: {e}")
    return {'ip': ip_address, 'error': 'Could not fetch geolocation data'}


def check_spf(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt_str = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
            if txt_str.lower().startswith('v=spf1'):
                return {'status': 'pass', 'color': 'green'}
        return {'status': 'fail', 'color': 'red'}
    except Exception as e:
        logger.warning(f"SPF lookup failed for {domain}: {e}")
        return {'status': 'fail', 'color': 'red'}


def check_dmarc(domain):
    try:
        dmarc_domain = f"_dmarc.{domain}"
        answers = dns.resolver.resolve(dmarc_domain, 'TXT')
        for rdata in answers:
            txt_str = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
            if txt_str.lower().startswith('v=dmarc1'):
                return {'status': 'pass', 'color': 'green'}
        return {'status': 'fail', 'color': 'red'}
    except Exception as e:
        logger.warning(f"DMARC lookup failed for {domain}: {e}")
        return {'status': 'fail', 'color': 'red'}


def check_dkim(domain, selector='default'):
    dkim_domain = f"{selector}._domainkey.{domain}"
    try:
        answers = dns.resolver.resolve(dkim_domain, 'TXT')
        for rdata in answers:
            txt_str = ''.join([s.decode() if isinstance(s, bytes) else s for s in rdata.strings])
            if 'v=DKIM1' in txt_str:
                return {'status': 'pass', 'color': 'green'}
        return {'status': 'fail', 'color': 'red'}
    except Exception as e:
        logger.warning(f"DKIM lookup failed for {domain} selector {selector}: {e}")
        return {'status': 'fail', 'color': 'red'}


def extract_dkim_selector(headers_text):
    match = re.search(r's=([\w\.\-]+);', headers_text)
    if match:
        return match.group(1)
    return 'default'


# =============================================
# Macro Identifier Views
# =============================================

from django.shortcuts import render
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json
import zipfile
import os
import olefile
from pathlib import Path
from oletools.olevba import VBA_Parser
import requests
from google import genai
from google.genai import types

GEMINI_API_KEY = settings.GEMINI_API_KEY

def generate_ai_report(scan_results):
    try:
        if not GEMINI_API_KEY:
            return "Configuration Error: Please set your GEMINI_API_KEY in the .env file"
             
        client = genai.Client(api_key=GEMINI_API_KEY)
        
        risk_level = scan_results.get('risk_level', 'Unknown')
        has_macros = 'Yes' if scan_results.get('has_macros') else 'No'
        threat_score = scan_results.get('threat_score', 0)
        vba_count = len(scan_results.get('vba_modules', []))
        
        threats_list = [t.get('pattern', 'Unknown') for t in scan_results.get('threats', [])]
        threats_text = ", ".join(threats_list) if threats_list else "None detected"
        
        details_list = scan_results.get('details', [])
        details_text = ", ".join(details_list) if details_list else "None"

        prompt = f"""
        You are a Cybersecurity Expert. Analyze these Office Macro Scan results and write a simplified security report for a non-technical user.

        FILE ANALYSIS DATA:
        - Risk Level: {risk_level}
        - Macros Detected: {has_macros}
        - Threat Score: {threat_score} (Scale 0-10+)
        - VBA Modules Found: {vba_count}
        - specific Threats Detected: {threats_text}
        - Technical Details: {details_text}

        INSTRUCTIONS:
        Please provide a concise, professional report in the following format:
        1. Executive Summary (2-3 sentences explaining if the file is dangerous).
        2. Key Findings (Bulleted list of what was found).
        3. Risk Assessment (Classify as Low, Medium, High, or Critical).
        4. Recommended Actions (What should the user do? Open it? Delete it?).
        5. Security Insights (Explain what the threats mean in simple language).

        Do NOT use Markdown formatting (like **bold** or # headers). Use plain text with newlines.
        """
        
        response = client.models.generate_content(
            model="gemini-2.5-flash",
            contents=prompt,
            config=types.GenerateContentConfig(
                temperature=0.7,
            )
        )
        
        if response.text:
            return response.text.strip()
        else:
            return "Error: AI generated empty response."
            
    except Exception as e:
        return f"Error generating report: {str(e)}"

@csrf_exempt
def generate_report_view(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            scan_results = data.get('scan_results', {})
            
            if not scan_results:
                return JsonResponse({'error': 'No scan results provided'}, status=400)
            
            report = generate_ai_report(scan_results)
            
            return JsonResponse({
                'success': True,
                'report': report
            })
            
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON data'}, status=400)
        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)

def macro_identifier(request):
    context = {
        'file_uploaded': False,
        'error': None,
        'results': None,
        'filename': None
    }
    
    if request.method == 'POST' and request.FILES.get('office_file'):
        uploaded_file = request.FILES['office_file']
        filename = uploaded_file.name
        
        allowed_extensions = ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt', '.docm', '.xlsm', '.pptm']
        file_ext = os.path.splitext(filename)[1].lower()
        
        if file_ext not in allowed_extensions:
            context['error'] = f"Invalid file type. Please upload an Office document ({', '.join(allowed_extensions)})"
            return render(request, 'pages/macro_identifier.html', context)
        
        file_path = default_storage.save(f'temp/{filename}', ContentFile(uploaded_file.read()))
        full_path = default_storage.path(file_path)
        
        try:
            macro_info = check_for_macros(full_path, file_ext)
            
            context.update({
                'file_uploaded': True,
                'filename': filename,
                'results': macro_info
            })
            
        except Exception as e:
            context['error'] = f"Error analyzing file: {str(e)}"
        
        finally:
            if default_storage.exists(file_path):
                default_storage.delete(file_path)
    
    return render(request, 'pages/macro_identifier.html', context)

def analyze_macro_for_threats(vba_code):
    threats = []
    unique_patterns = set()
    
    suspicious_patterns = {
        'Shell': {'severity': 3, 'description': 'Shell command execution detected'},
        'WScript.Shell': {'severity': 4, 'description': 'Windows Script Host Shell execution'},
        'CreateObject("WScript.Shell")': {'severity': 4, 'description': 'WScript Shell object creation'},
        'Environ': {'severity': 2, 'description': 'Environment variable access'},
        'AutoOpen': {'severity': 3, 'description': 'Auto-execution on document open (Word)'},
        'Auto_Open': {'severity': 3, 'description': 'Auto-execution on document open (Word)'},
        'Workbook_Open': {'severity': 3, 'description': 'Auto-execution on workbook open (Excel)'},
        'Document_Open': {'severity': 3, 'description': 'Auto-execution on document open'},
        'AutoExec': {'severity': 3, 'description': 'Auto-execution macro'},
        'CreateTextFile': {'severity': 2, 'description': 'File creation capability'},
        'ADODB.Stream': {'severity': 3, 'description': 'File stream operations (potential download)'},
        'SaveAs': {'severity': 2, 'description': 'File save operation'},
        'Open': {'severity': 1, 'description': 'File open operation'},
        'MSXML2.XMLHTTP': {'severity': 4, 'description': 'HTTP request capability (potential C2 communication)'},
        'ServerXMLHTTP': {'severity': 4, 'description': 'Server HTTP request (potential download)'},
        'URLDownloadToFile': {'severity': 5, 'description': 'Direct file download from URL'},
        'InternetExplorer.Application': {'severity': 3, 'description': 'IE automation (potential web interaction)'},
        'RegWrite': {'severity': 3, 'description': 'Registry write operation'},
        'RegRead': {'severity': 2, 'description': 'Registry read operation'},
        'CreateObject("WScript.Network")': {'severity': 2, 'description': 'Network object creation'},
        'Chr(': {'severity': 2, 'description': 'Character encoding (potential obfuscation)'},
        'StrReverse': {'severity': 2, 'description': 'String reversal (potential obfuscation)'},
        'Replace(': {'severity': 1, 'description': 'String replacement (potential deobfuscation)'},
        'CallByName': {'severity': 3, 'description': 'Dynamic function call'},
        'GetObject': {'severity': 2, 'description': 'Object retrieval'},
        'VirtualAlloc': {'severity': 5, 'description': 'Memory allocation (potential shellcode)'},
        'RtlMoveMemory': {'severity': 5, 'description': 'Memory manipulation'},
        'CreateThread': {'severity': 5, 'description': 'Thread creation (potential code injection)'},
    }
    
    code_lower = vba_code.lower()
    
    for pattern, info in suspicious_patterns.items():
        pattern_lower = pattern.lower()
        if pattern_lower in code_lower and pattern_lower not in unique_patterns:
            unique_patterns.add(pattern_lower)
            threats.append({
                'pattern': pattern,
                'description': info['description'],
                'severity': info['severity']
            })
    
    base64_chars = [c for c in vba_code if c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=']
    if 'base64' in code_lower or (len(vba_code) > 50 and len(base64_chars) > len(vba_code) * 0.7):
        if 'base64' not in unique_patterns:
            unique_patterns.add('base64')
            threats.append({
                'pattern': 'Base64 Encoding',
                'description': 'Possible base64 encoded payload',
                'severity': 3
            })
    
    severity_score = sum(threat['severity'] for threat in threats)
    
    return threats, severity_score


def check_for_macros(file_path, file_ext):
    results = {
        'has_macros': False,
        'macro_type': None,
        'vba_modules': [],
        'risk_level': 'Safe',
        'details': [],
        'macro_code': [],
        'threats': [],
        'threat_score': 0
    }
    
    try:
        vbaparser = VBA_Parser(file_path)
        
        if vbaparser.detect_vba_macros():
            results['has_macros'] = True
            results['macro_type'] = 'VBA Macros'
            results['details'].append('VBA macro project detected')
            
            all_threats = []
            total_threat_score = 0
            
            for (filename, stream_path, vba_filename, vba_code) in vbaparser.extract_macros():
                if vba_code:
                    threats, score = analyze_macro_for_threats(vba_code)
                    all_threats.extend(threats)
                    total_threat_score += score
                    
                    results['macro_code'].append({
                        'module_name': vba_filename,
                        'stream_path': stream_path,
                        'code': vba_code,
                        'threats': threats,
                        'threat_score': score
                    })
                    results['vba_modules'].append(vba_filename)
            
            results['threats'] = all_threats
            results['threat_score'] = total_threat_score
            
            if total_threat_score >= 10:
                results['risk_level'] = 'Critical'
                results['details'].append(f'CRITICAL: High threat score detected ({total_threat_score})')
            elif total_threat_score >= 5:
                results['risk_level'] = 'High'
                results['details'].append(f'HIGH RISK: Multiple suspicious patterns found ({total_threat_score})')
            elif total_threat_score >= 2:
                results['risk_level'] = 'Medium'
                results['details'].append(f'MEDIUM RISK: Some suspicious patterns detected ({total_threat_score})')
            elif total_threat_score > 0:
                results['risk_level'] = 'Low'
                results['details'].append(f'LOW RISK: Minor suspicious patterns found ({total_threat_score})')
            else:
                results['risk_level'] = 'Safe'
                results['details'].append('No suspicious patterns detected in macros')
            
            if 'word/' in file_path.lower() or file_ext in ['.doc', '.docx', '.docm']:
                results['details'].append('Word VBA macros found')
            elif 'xl/' in file_path.lower() or file_ext in ['.xls', '.xlsx', '.xlsm']:
                results['details'].append('Excel VBA macros found')
            elif 'ppt/' in file_path.lower() or file_ext in ['.ppt', '.pptx', '.pptm']:
                results['details'].append('PowerPoint VBA macros found')
                
        else:
            results['details'].append('No VBA macros detected')
            results['risk_level'] = 'Safe'
            
        vbaparser.close()
        
    except Exception as e:
        results['details'].append(f'Advanced analysis error: {str(e)}')
        
        if file_ext in ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm']:
            try:
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    file_list = zip_file.namelist()
                    
                    vba_files = [f for f in file_list if 'vbaProject.bin' in f]
                    
                    if vba_files:
                        results['has_macros'] = True
                        results['macro_type'] = 'VBA Macros'
                        results['vba_modules'] = vba_files
                        results['risk_level'] = 'High' if file_ext.endswith('m') else 'Medium'
                        results['details'].append('VBA macro project detected (code extraction failed)')
                    else:
                        results['details'].append('No VBA macros detected')
                        results['risk_level'] = 'Safe'
                        
            except zipfile.BadZipFile:
                results['details'].append('Unable to analyze file structure')
                
        elif file_ext in ['.doc', '.xls', '.ppt']:
            try:
                if olefile.isOleFile(file_path):
                    ole = olefile.OleFileIO(file_path)
                    
                    if ole.exists('Macros') or ole.exists('_VBA_PROJECT_CUR') or ole.exists('VBA'):
                        results['has_macros'] = True
                        results['macro_type'] = 'VBA Macros (Legacy)'
                        results['risk_level'] = 'High'
                        results['details'].append('VBA macros detected (code extraction failed)')
                    else:
                        results['details'].append('No macros detected')
                        results['risk_level'] = 'Safe'
                        
                    ole.close()
                else:
                    results['details'].append('Not a valid OLE file')
                    
            except Exception as e2:
                results['details'].append(f'Error analyzing legacy file: {str(e2)}')
    
    return results


# =============================================
# PowerShell Analyzer Views
# =============================================

import re
import base64
from django.shortcuts import render

def normalize_payload(code):
    norm = code.replace('`', '')
    norm = norm.lower()
    norm = re.sub(r'["\']\s*\+\s*["\']', '', norm)
    return norm

def analyze_powershell_code(code):
    normalized_code = normalize_payload(code)
    
    results = {
        'risk_level': 'Safe',
        'threat_score': 0,
        'threats': [],
        'details': [],
        'extracted_code': code[:2000] + ("..." if len(code) > 2000 else ""),
        'normalized_preview': normalized_code[:2000] + ("..." if len(normalized_code) > 2000 else ""),
        'statistics': {
            'obfuscation_indicators': 0
        }
    }

    unique_threats = set()
    found_severities = []

    patterns = [
        (r'\[regex\]::Matches.*RightToLeft', 10, 'CRITICAL: String Reversing (RightToLeft) detected', 'Obfuscation'),
        (r'-join\s*\'\'', 5, 'Suspicious: Join Operator used for string reconstruction', 'Obfuscation'),
        (r'\biex\b', 9, 'CRITICAL: "IEX" Alias (Invoke-Expression)', 'Execution'),
        (r'\biwr\b', 7, 'High: "iwr" Alias (Invoke-WebRequest)', 'Network'),
        (r'FromBase64String', 8, 'High: Base64 Decoding (FromBase64String)', 'Decoding'),
        (r'-e\s+', 6, 'Medium: Encoded Command Flag (-e)', 'Execution'),
        (r'Start-BitsTransfer', 9, 'CRITICAL: BITS Transfer (Malware Downloader)', 'Network'),
        (r'try\s*\{.*\}\s*catch', 5, 'Medium: Try-Catch block (Hiding execution errors)', 'Evasion'),
        (r'-w\s+1\b', 8, 'High: Hidden Window via Integer (-w 1)', 'Evasion'),
        (r'-windowstyle\s+1\b', 8, 'High: Hidden Window via Integer', 'Evasion'),
        (r'nEw-oB`jecT', 8, 'High: Backtick Obfuscation in "New-Object"', 'Obfuscation'),
        (r'for\s*\(\$i=1;\s*\$i\s*-le\s*[0-9]{4,}', 7, 'High: Large Loop detected (Sandbox Time Evasion)', 'Anti-Analysis'),
        (r'Net\.WebClient', 8, 'Critical: .NET WebClient (Downloader)', 'Network'),
        (r'DownloadFile', 8, 'Critical: DownloadFile method', 'Network'),
        (r'Reflect', 7, 'High: Reflection usage', 'Reflection'),
    ]

    for pattern, severity, desc, category in patterns:
        matches = list(re.finditer(pattern, normalized_code, re.IGNORECASE))
        if matches:
            if desc not in unique_threats:
                results['threats'].append({
                    'pattern': pattern,
                    'severity': severity,
                    'description': desc,
                    'category': category,
                    'count': len(matches)
                })
                found_severities.append(severity)
                unique_threats.add(desc)

    concat_count = code.count("'+'") + code.count('"+"') + code.lower().count('-join')
    if concat_count > 5:
        results['threats'].append({
            'pattern': '+ / -Join',
            'severity': 6,
            'description': f'Technique 1: Heavy String Concatenation ({concat_count} occurrences)',
            'category': 'Obfuscation',
            'count': concat_count
        })
        found_severities.append(6)

    backtick_count = code.count('`')
    if backtick_count > 4:
        results['threats'].append({
            'pattern': '`',
            'severity': 5,
            'description': f'Technique 7: Backtick Obfuscation ({backtick_count} detected)',
            'category': 'Obfuscation',
            'count': backtick_count
        })
        found_severities.append(5)

    keywords = ['new-object', 'powershell', 'invoke-expression', 'downloadstring']
    mixed_case_found = False
    for word in keywords:
        found = re.search(word, code, re.IGNORECASE)
        if found:
            matched_str = found.group(0)
            if not matched_str.islower() and not matched_str.isupper():
                mixed_case_found = True
                results['details'].append(f"Mixed Case detected: {matched_str}")
    
    if mixed_case_found:
        results['threats'].append({
            'pattern': 'Az-Z',
            'severity': 4,
            'description': 'Technique 8: Mixed Case Obfuscation (e.g., nEw-oBjecT)',
            'category': 'Obfuscation',
            'count': 1
        })
        found_severities.append(4)

    if found_severities:
        base_score = max(found_severities)
        bonus_score = min((len(found_severities)-1) * 0.5, 4)
        final_score = base_score + bonus_score
        results['threat_score'] = min(round(final_score, 1), 10)
    else:
        results['threat_score'] = 0

    score = results['threat_score']
    if score >= 9: results['risk_level'] = 'CRITICAL'
    elif score >= 7: results['risk_level'] = 'HIGH'
    elif score >= 4: results['risk_level'] = 'MEDIUM'
    else: results['risk_level'] = 'SAFE'

    results['threats'].sort(key=lambda x: x['severity'], reverse=True)
    return results

def powershell_analyzer_view(request):
    if request.method == 'POST':
        ps_file = request.FILES.get('ps_file')
        ps_code = request.POST.get('ps_code', '').strip()
        
        code = None
        filename = None
        
        if ps_file:
            try:
                code = ps_file.read().decode('utf-8', errors='replace')
                filename = ps_file.name
            except Exception as e:
                return render(request, 'pages/powershell_analyzer.html', {'error': f'Read Error: {str(e)}'})
        elif ps_code:
            code = ps_code
            filename = "Manual Input"
            
        if not code:
            return render(request, 'pages/powershell_analyzer.html', {'error': 'No code provided.'})
            
        results = analyze_powershell_code(code)
        
        return render(request, 'pages/powershell_analyzer.html', {
            'results': results,
            'filename': filename,
            'file_uploaded': True
        })

    return render(request, 'pages/powershell_analyzer.html', {'file_uploaded': False})
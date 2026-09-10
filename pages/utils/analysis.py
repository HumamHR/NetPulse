# pages/utils/analysis.py
from scapy.all import IP, TCP, UDP, ICMP, load_layer, bind_layers
from collections import defaultdict
from datetime import datetime

# Load TLS layers
load_layer("tls") 
from scapy.layers.tls.all import TLS, TLSClientHello, TLSCertificate

bind_layers(TCP, TLS, sport=443)
bind_layers(TCP, TLS, dport=443)

# Import helper
try:
    from pages.utils import tls_analyzer
except ImportError:
    tls_analyzer = None

def analyze_pcap_for_stats(packets):
    """ Reads a PCAP file, extracts network statistics, and TIMELINE data. """
    try:
        unique_src_ips = set()
        unique_dst_ips = set()
        sessions = set()
        protocol_count = defaultdict(int)
        ip_pair_sessions = defaultdict(set)

        # TLS Results
        tls_ja3_results = []
        tls_cert_results = []

        # --- NEW: TIMELINE DATA STORAGE ---
        # We will store packet counts per second
        # Key: Timestamp (epoch int), Value: Packet Count
        timeline_stats = defaultdict(int)
        start_ts = None
        # ----------------------------------

        print("--- Starting Packet Loop ---")

        for pkt in packets:
            # --- 1. Timeline Logic ---
            try:
                # Get packet timestamp
                ts = float(pkt.time)
                if start_ts is None:
                    start_ts = ts
                
                # Group by relative second (0, 1, 2, 3...) from start
                # or use absolute epochs if you prefer
                rel_second = int(ts - start_ts)
                if rel_second < 0: rel_second = 0 # Handle weird out-of-order packets
                
                timeline_stats[rel_second] += 1
            except:
                pass
            # -------------------------

            if IP in pkt:
                unique_src_ips.add(pkt[IP].src)
                unique_dst_ips.add(pkt[IP].dst)

                proto = pkt[IP].proto
                protocol_count[proto] += 1

                session_key = f"{pkt[IP].src} -> {pkt[IP].dst}"
                ip_pair_sessions[session_key].add(proto)

                if TCP in pkt:
                    # [Port Counting Logic - kept same]
                    if pkt[TCP].sport == 21 or pkt[TCP].dport == 21: protocol_count[21] += 1
                    elif pkt[TCP].sport == 20 or pkt[TCP].dport == 20: protocol_count[20] += 1
                    elif pkt[TCP].sport == 80 or pkt[TCP].dport == 80: protocol_count[80] += 1
                    elif pkt[TCP].sport == 443 or pkt[TCP].dport == 443: protocol_count[443] += 1
                    elif pkt[TCP].sport == 22 or pkt[TCP].dport == 22: protocol_count[22] += 1
                    elif pkt[TCP].sport == 23 or pkt[TCP].dport == 23: protocol_count[23] += 1
                    
                    sessions.add((pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport, "TCP"))
                    
                    # --- TLS ANALYSIS ---
                    if tls_analyzer:
                        try:
                            if pkt.haslayer(TLSClientHello):
                                ja3_data = tls_analyzer.get_ja3_fingerprint(pkt)
                                if ja3_data: tls_ja3_results.append(ja3_data)
                        except: pass

                        try:
                            if pkt.haslayer(TLS):
                                server_data = tls_analyzer.analyze_tls_server(pkt)
                                if server_data: tls_cert_results.extend(server_data)
                        except: pass

                elif UDP in pkt:
                    # [UDP Logic - kept same]
                    if pkt[UDP].sport == 53 or pkt[UDP].dport == 53: protocol_count[53] += 1
                    elif pkt[UDP].sport == 161 or pkt[UDP].dport == 161: protocol_count[161] += 1
                    elif pkt[UDP].sport == 162 or pkt[UDP].dport == 162: protocol_count[162] += 1
                    sessions.add((pkt[IP].src, pkt[IP].dst, pkt[UDP].sport, pkt[UDP].dport, "UDP"))

                elif ICMP in pkt:
                    protocol_count[1] += 1

        # --- FORMAT OUTPUT ---
        proto_map = {
            1: "ICMP", 6: "TCP", 17: "UDP", 20: "FTP Data", 21: "FTP Control", 
            22: "SSH", 23: "Telnet", 53: "DNS", 80: "HTTP", 443: "HTTPS"
        }

        named_protocol_distribution = {
            proto_map.get(k, f"Other ({k})"): v for k, v in protocol_count.items()
        }

        named_ip_pair_sessions = {
            k: [proto_map.get(p, f"Other ({p})") for p in v] for k, v in ip_pair_sessions.items()
        }

        # Sort timeline dictionary by second (0, 1, 2...)
        sorted_timeline = dict(sorted(timeline_stats.items()))

        return {
            'total_packets': len(packets),
            'unique_src_ips': list(unique_src_ips),
            'unique_dst_ips': list(unique_dst_ips),
            'total_unique_ips': len(unique_src_ips | unique_dst_ips),
            'total_sessions': len(sessions),
            'protocol_distribution': named_protocol_distribution,
            'ip_pair_sessions': named_ip_pair_sessions,
            'tls_ja3': tls_ja3_results,
            'tls_certs': tls_cert_results,
            # --- PASS TIMELINE DATA ---
            'timeline_data': sorted_timeline 
        }

    except Exception as e:
        print(f"Error reading PCAP file: {e}")
        import traceback
        traceback.print_exc()
        return {}
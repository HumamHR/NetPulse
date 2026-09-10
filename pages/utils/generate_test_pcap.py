import os
from scapy.all import *
from scapy.layers.tls.all import *
from scapy.layers.inet import IP, TCP, Ether

# Output file
OUTPUT_FILE = "test_sni_traffic_v2.pcap"

def create_tls_packet(sni_domain, src_ip, dst_ip, src_port, user_agent_type="browser"):
    """
    Creates a highly realistic TLS packet.
    """
    # 1. IP/TCP headers
    ip_layer = IP(src=src_ip, dst=dst_ip)
    tcp_layer = TCP(sport=src_port, dport=443, flags="PA", seq=1000, ack=1000)

    # 2. Configure Client Type
    extensions = []
    
    if user_agent_type == "browser":
        # Simulate Chrome: High cipher count + GREASE + TLS 1.3
        # 0x0a0a is GREASE
        ciphers = [0x0a0a, 0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035]
        
        # --- FIXED: Use 'val' instead of 'data' for Scapy TLS_Ext_Unknown ---
        # Add GREASE Extension (Type 0x0a0a / 2570)
        grease_ext = TLS_Ext_Unknown(type=0x0a0a, val=b"")
        extensions.append(grease_ext)
        
        # Add ALPN Extension (Type 16)
        alpn_ext = TLS_Ext_ALPN(protocols=["h2", "http/1.1"])
        extensions.append(alpn_ext)

    elif user_agent_type == "tool":
        # Simulate Curl/Python: Low cipher count, no GREASE
        ciphers = [0xc02f, 0xc02b, 0x009c] 
    
    else:
        # Unknown/Custom
        ciphers = [0xc02f, 0x0035]

    # 3. Always add SNI
    sni_ext = TLS_Ext_ServerName(servernames=[ServerName(servername=sni_domain)])
    extensions.append(sni_ext)
    
    # 4. Add Supported Groups (Standard)
    groups_ext = TLS_Ext_SupportedGroups(groups=[29, 23, 24])
    extensions.append(groups_ext)

    # 5. Build TLS Layer
    tls_layer = TLS(msg=[
        TLSClientHello(
            version=0x0303, # TLS 1.2 (Wire)
            ciphers=ciphers,
            ext=extensions
        )
    ])

    # 6. Combine
    packet = Ether() / ip_layer / tcp_layer / tls_layer
    return packet

def generate_pcap():
    print(f"[*] Generating {OUTPUT_FILE} with realistic Browser Headers...")
    packets = []

    # --- TEST 1: Google (Should be Chrome/Browser) ---
    print(" -> Adding: www.google.com (Chrome Simulation)")
    packets.append(create_tls_packet("www.google.com", "192.168.1.5", "142.250.1.1", 12345, "browser"))

    # --- TEST 2: Facebook (Should be Chrome/Browser) ---
    print(" -> Adding: facebook.com (Chrome Simulation)")
    packets.append(create_tls_packet("facebook.com", "192.168.1.5", "157.240.1.1", 12346, "browser"))

    # --- TEST 3: Python (Should be Tool) ---
    print(" -> Adding: files.pythonhosted.org (Tool Simulation)")
    packets.append(create_tls_packet("files.pythonhosted.org", "192.168.1.5", "151.101.1.1", 12347, "tool"))

    # --- TEST 4: Unknown Malware (Should be Unknown/Fallback) ---
    print(" -> Adding: evil-c2-server.xyz (Unknown)")
    packets.append(create_tls_packet("evil-c2-server.xyz", "192.168.1.100", "45.33.2.1", 4444, "unknown"))

    # Write to file
    wrpcap(OUTPUT_FILE, packets)
    print(f"[*] Done! File saved as {OUTPUT_FILE}")

if __name__ == "__main__":
    generate_pcap()
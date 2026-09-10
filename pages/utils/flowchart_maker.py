# pages/utils/flowchart_maker.py
import os
from scapy.all import IP, TCP, UDP
from collections import defaultdict

def create_flow_diagram(pcap_file, packets):
    """
    Analyzes packets and returns a JSON-serializable dictionary 
    representing the network graph (Nodes & Edges).
    """
    
    nodes = set()
    edges_tracker = defaultdict(int)
    
    # --- FIX: REMOVED LIMIT ---
    # We iterate through ALL packets now to ensure the graph matches the Hosts tab.
    # Note: If you upload a file with 10,000+ IPs, the browser graph might lag, 
    # but at least the data will be complete.
    
    for packet in packets:
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            
            # Add nodes
            nodes.add(src_ip)
            nodes.add(dst_ip)
            
            # Create a unique key for the edge so we can count weight
            # We sort them so A->B and B->A count towards the same link thickness
            pair = tuple(sorted((src_ip, dst_ip)))
            edges_tracker[pair] += 1
            
    # 1. Format Nodes for Vis.js
    node_list = []
    for node in nodes:
        # Simple logic to guess if it's a gateway (usually ends in .1 or .254)
        # You can expand this logic if needed
        group = 'host'
        if node.endswith('.1') or node.endswith('.254'):
            group = 'router'
            
        node_list.append({
            'id': node,
            'label': node,
            'group': group
        })

    # 2. Format Edges for Vis.js
    edge_list = []
    for (src, dst), weight in edges_tracker.items():
        edge_list.append({
            'from': src,
            'to': dst,
            'value': weight, # Thickness based on traffic volume
            'title': f"{weight} packets" # Tooltip
        })

    # Return the data structure directly
    return {
        'nodes': node_list,
        'edges': edge_list
    }
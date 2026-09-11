# NetPulse

> **Network Analysis & Threat Detection Platform**

NetPulse is a web-based cybersecurity platform designed to analyze network traffic, investigate PCAP files, identify potential threats, and provide actionable security insights through an intuitive interface.

The platform combines network analysis, threat intelligence, security rules, and automated reporting to support both **real-time monitoring** and **offline forensic investigation**.

---

## Key Features

### Live Network Analysis
- Capture and analyze network traffic in real time
- Inspect network flows and communication patterns
- Identify suspicious traffic and potential security threats
- Generate analysis reports

### Offline PCAP Analysis
- Analyze previously captured network traffic
- Extract and inspect HTTP objects
- Apply custom security rules
- Identify suspicious network activity
- Generate investigation reports

### IP Intelligence
- IP address information and geolocation
- ASN and ISP information
- Reputation analysis
- Blacklist and threat intelligence checks

### Port Scanning
- Scan commonly used TCP ports
- Identify potentially exposed services
- Support security assessment and reconnaissance activities

### Threat Detection
- Analyze IPs, URLs, and file hashes
- Integrate with external threat intelligence services
- Identify indicators associated with malicious activity

### Rule-Based IDS
- Detect suspicious patterns using custom detection rules
- Analyze network traffic against predefined security conditions
- Support extensible rule development

### Security Reports
- Generate structured analysis reports
- Summarize detected threats and network activity
- Provide useful findings for security investigation

---

## Architecture

```text
                ┌─────────────────────┐
                │      NetPulse       │
                │   Web Application   │
                └──────────┬──────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
   Live Analysis     PCAP Analysis    Threat Intelligence
          │                │                │
          ▼                ▼                ▼
      Traffic          Scapy/Rules     Threat Detection APIs
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                    Security Analysis
                           │
                           ▼
                      Reports & Alerts

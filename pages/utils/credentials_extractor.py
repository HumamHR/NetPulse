#pages/utils/credentials_extractor.py
from scapy.all import TCP, Raw, IP
import base64
import re
import urllib.parse
import json

def is_safe_string(s):
    """
    Checks if a string consists only of printable ASCII characters.
    Prevents binary garbage (like , Ñ, ä) from showing up.
    """
    if not s or len(s) > 100: 
        return False
    # Regex for printable ASCII (space through tilde)
    return bool(re.match(r'^[ -~]+$', s))

def extract_credentials(packets):
    """
    Robustly extracts credentials using keywords and context heuristics.
    """
    found_creds = set()
    
    # 1. Expanded Keyword Lists
    USER_FIELDS = [
        r'log', r'login', r'wpName', r'ahd_username', r'un', r'user', 
        r'user_name', r'username', r'email', r'mail', r'r_email', 
        r'account', r'userid', r'uid', r'id', r'u', r'name', r'alias', 
        r'signin', r'member', r'nick', r'handle'
    ]
    PASS_FIELDS = [
        r'pwd', r'pass', r'password', r'pass_word', r'passwd', 
        r'wpPassword', r'ahd_password', r'pword', r'secret', r'p',
        r'token', r'auth'
    ]
    
    # 2. Compile Regex patterns (Looser matching)
    # \b ensures we match "user=" but not "browser="
    # \s*=\s* handles "user = test"
    # ([^&;\s"]+) captures the value until a separator
    form_user_re = re.compile(r'(?i)\b(' + '|'.join(USER_FIELDS) + r')\s*=\s*([^&;\s"]+)')
    form_pass_re = re.compile(r'(?i)\b(' + '|'.join(PASS_FIELDS) + r')\s*=\s*([^&;\s"]+)')

    # JSON Data ("key": "value")
    json_user_re = re.compile(r'(?i)"(' + '|'.join(USER_FIELDS) + r')"\s*:\s*"([^"]+)"')
    json_pass_re = re.compile(r'(?i)"(' + '|'.join(PASS_FIELDS) + r')"\s*:\s*"([^"]+)"')

    print(f"[DEBUG] Scanning {len(packets)} packets for credentials...")

    for i, pkt in enumerate(packets):
        if pkt.haslayer(TCP) and pkt.haslayer(Raw):
            try:
                payload_bytes = pkt[Raw].load
                
                # --- Decoding Strategy ---
                try:
                    payload = payload_bytes.decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        payload = payload_bytes.decode('latin-1')
                    except:
                        continue 

                # Skip tiny packets
                if len(payload) < 5:
                    continue

                # --- 1. HTTP Basic Auth ---
                if "Authorization: Basic" in payload:
                    match = re.search(r'Authorization:\s*Basic\s*([a-zA-Z0-9+/=]+)', payload, re.IGNORECASE)
                    if match:
                        try:
                            decoded = base64.b64decode(match.group(1)).decode('utf-8', errors='ignore')
                            if ":" in decoded and is_safe_string(decoded):
                                found_creds.add(("HTTP", "Basic Auth", decoded))
                        except: pass

                # --- 2. HTTP Form & URL Parameters ---
                
                # Search for Passwords first (High confidence)
                p_matches = form_pass_re.findall(payload)
                u_matches = form_user_re.findall(payload)

                # Store direct username matches
                for key, val in u_matches:
                    val_decoded = urllib.parse.unquote(val)
                    if len(val_decoded) > 1 and is_safe_string(val_decoded): 
                        found_creds.add(("HTTP", "Username", val_decoded))

                # Store direct password matches
                for key, val in p_matches:
                    val_decoded = urllib.parse.unquote(val)
                    if len(val_decoded) > 1 and is_safe_string(val_decoded):
                        found_creds.add(("HTTP", "Password", val_decoded))
                        
                        # --- HEURISTIC: Proximity Search ---
                        # If we found a password but NO username in this packet so far,
                        # try to find ANY 'key=value' pair appearing just before the password.
                        if not u_matches:
                            try:
                                # Find where the password starts
                                pass_idx = payload.find(key + "=")
                                if pass_idx > 5:
                                    # Look at the 100 chars before the password
                                    context = payload[max(0, pass_idx-100):pass_idx]
                                    # Find the LAST 'key=value' pair before the password
                                    generic_pairs = re.findall(r'([a-zA-Z0-9_]+)=([^&;\s"]+)', context)
                                    if generic_pairs:
                                        # Assume the last param before password is the username
                                        possible_user_key, possible_user_val = generic_pairs[-1]
                                        decoded_user = urllib.parse.unquote(possible_user_val)
                                        
                                        # Filter out common junk like 'submit', 'action', 'view'
                                        if is_safe_string(decoded_user) and len(decoded_user) > 1:
                                            if "submit" not in possible_user_key.lower() and "action" not in possible_user_key.lower():
                                                found_creds.add(("HTTP", "Username (Inferred)", decoded_user))
                            except: pass

                # --- 3. JSON Payloads ---
                if "{" in payload and "}" in payload:
                    j_u_matches = json_user_re.findall(payload)
                    for key, val in j_u_matches:
                        if is_safe_string(val) and len(val) > 1:
                            found_creds.add(("HTTP", "Username (JSON)", val))
                    
                    j_p_matches = json_pass_re.findall(payload)
                    for key, val in j_p_matches:
                         if is_safe_string(val) and len(val) > 1:
                            found_creds.add(("HTTP", "Password (JSON)", val))

                # --- 4. FTP (Cleartext) ---
                if payload.startswith("USER "):
                    username = payload.strip().split(' ')[1]
                    if is_safe_string(username):
                        found_creds.add(("FTP", "Username", username))
                elif payload.startswith("PASS "):
                    password = payload.strip().split(' ')[1]
                    if is_safe_string(password):
                        found_creds.add(("FTP", "Password", password))

                # --- 5. POP3 / IMAP / SMTP ---
                if "LOGIN " in payload or "AUTH PLAIN" in payload:
                    clean_line = payload.strip().replace('\r', '').replace('\n', '')
                    if is_safe_string(clean_line):
                        found_creds.add(("Mail (POP3/IMAP)", "Login Command", clean_line))

                # --- 6. Telnet ---
                lower_load = payload.lower()
                if "login:" in lower_load or "username:" in lower_load:
                    found_creds.add(("Telnet", "Prompt", "Login prompt detected"))

            except Exception as e:
                continue

    # --- Deduplication & Formatting ---
    structured_creds = []
    seen_details = set()

    for protocol, c_type, details in found_creds:
        unique_key = f"{protocol}:{c_type}:{details}"
        
        # Filters
        if "anonymous" in details.lower(): continue 
        if len(details) > 50: continue # Passwords usually aren't sentences
        
        if unique_key not in seen_details:
            seen_details.add(unique_key)
            structured_creds.append({
                'protocol': protocol,
                'type': c_type,
                'details': details
            })

    # Sort results so Usernames appear before Passwords
    structured_creds.sort(key=lambda x: x['type'], reverse=True)
    
    print(f"[CREDENTIALS] Extraction complete. Found {len(structured_creds)} unique credentials.")
    return structured_creds
from flask import Flask, render_template, request, jsonify, send_file, make_response
import re
import io
import base64
import json
import csv
from collections import Counter
import pandas as pd
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib as mpl
from datetime import datetime
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT

mpl.rcParams.update({
    "axes.titlesize": 9,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7
})

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# ---------------- REGEX PATTERNS ----------------

# Web Access Logs (Apache/Nginx combined format)
WEB_PATTERN = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+.*?"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})'
)

# SSH Authentication Logs
SSH_PATTERN = re.compile(
    r'.*sshd.*(Failed password|Invalid user|Connection closed|Accepted password).*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

# FTP Logs (Common FTP server patterns)
FTP_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+\s+\S+)?.*?(?:ftp|vsftpd|proftpd).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<action>LOGIN|FAIL|UPLOAD|DOWNLOAD|CONNECT)',
    re.IGNORECASE
)

# Email/SMTP Logs (Failed auth, relay attempts)
SMTP_PATTERN = re.compile(
    r'.*?(?:postfix|sendmail|smtp|dovecot).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<action>reject|relay denied|authentication failed|login failed|disconnect)',
    re.IGNORECASE
)

# Database Logs (MySQL/PostgreSQL failed connections)
DB_PATTERN = re.compile(
    r'.*?(?:mysql|postgresql|mariadb|mongodb).*?(?P<ip>\d+\.\d+\.\d+\.\d+)?.*?(?P<action>Access denied|authentication failed|invalid password|connection refused|login failed)',
    re.IGNORECASE
)

# Windows Event Logs (Failed login attempts)
WINDOWS_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})?.*?(?:EventID|Event\s*ID|event)[:\s]*(?P<event_id>4625|4771|4776|4624|4634).*?(?P<ip>\d+\.\d+\.\d+\.\d+)?',
    re.IGNORECASE
)

# Firewall Logs (Blocked connections - iptables/pf/Windows Firewall)
FIREWALL_PATTERN = re.compile(
    r'.*?(?:DENY|DROP|REJECT|BLOCK|BLOCKED).*?(?:SRC=|src:|from\s+)(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?(?:DST=|dst:|to\s+)(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?(?:DPT=|dport:|port\s+)?(?P<port>\d+)?',
    re.IGNORECASE
)

# DNS Query Logs (Potentially malicious domains)
DNS_PATTERN = re.compile(
    r'.*?(?:named|dnsmasq|unbound|dns).*?(?:query|request).*?(?P<ip>\d+\.\d+\.\d+\.\d+)?.*?(?P<domain>[\w\-\.]+\.\w{2,})',
    re.IGNORECASE
)

# VPN Connection Logs
VPN_PATTERN = re.compile(
    r'.*?(?:openvpn|vpn|ipsec|wireguard|pptp).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<action>connected|disconnected|authentication failed|peer|established)',
    re.IGNORECASE
)

# API Access Logs (REST API pattern)
API_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<method>GET|POST|PUT|DELETE|PATCH)\s+/api/(?P<endpoint>[^\s"?]+).*?(?P<status>\d{3})',
    re.IGNORECASE
)

# Docker/Container Logs
DOCKER_PATTERN = re.compile(
    r'.*?(?:docker|containerd|container|kubernetes|k8s).*?(?P<container_id>[a-f0-9]{12})?.*?(?P<action>started|stopped|died|error|created|killed|oom)',
    re.IGNORECASE
)

# AWS CloudTrail / Azure / GCP Logs
CLOUD_PATTERN = re.compile(
    r'.*?(?:aws|cloudtrail|azure|gcp|iam).*?(?P<action>ConsoleLogin|AssumeRole|CreateUser|DeleteUser|unauthorized|AccessDenied).*?(?P<ip>\d+\.\d+\.\d+\.\d+)?',
    re.IGNORECASE
)

# ModSecurity / WAF Logs
MODSEC_PATTERN = re.compile(
    r'.*?(?:ModSecurity|modsec|waf).*?\[id\s*"?(?P<rule_id>\d+)"?\].*?(?P<ip>\d+\.\d+\.\d+\.\d+)?.*?(?P<action>Warning|Critical|Error|blocked)',
    re.IGNORECASE
)

# Syslog Generic Pattern
SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<process>\S+?)(?:\[\d+\])?:\s*(?P<message>.+)$'
)

# JSON Log Format (Common in modern apps)
JSON_LOG_PATTERN = re.compile(
    r'^\s*\{.*"(?:ip|client_ip|remote_addr|clientIP)":\s*"(?P<ip>\d+\.\d+\.\d+\.\d+)".*\}\s*$'
)

# Nginx Error Log
NGINX_ERROR_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\[(?P<level>\w+)\].*?client:\s*(?P<ip>\d+\.\d+\.\d+\.\d+)?.*?(?P<message>.*)'
)

# Apache Error Log
APACHE_ERROR_PATTERN = re.compile(
    r'\[(?P<timestamp>[^\]]+)\]\s+\[(?P<level>\w+)\].*?\[client\s+(?P<ip>\d+\.\d+\.\d+\.\d+)(?::\d+)?\].*?(?P<message>.*)'
)

# ---------------- ADVANCED ATTACK RULES ----------------

SQLI_PATTERNS = (
    "union", "select", "insert", "update", "delete",
    "drop", "sleep(", "benchmark", "information_schema",
    "' or '1'='1", "\" or \"1\"=\"1", "or 1=1"
)

XSS_PATTERNS = (
    "<script", "%3cscript", "javascript:",
    "onerror=", "onload=", "<img"
)

RCE_PATTERNS = (
    "cmd=", "exec", "system(", "shell_exec",
    "powershell", "bash", "sh;", "|sh", "wget", "curl"
)

LFI_PATTERNS = (
    "../", "..%2f", "%2e%2e%2f", "etc/passwd", "boot.ini"
)

SENSITIVE_FILES = (
    "/admin", "/wp-admin", "/phpmyadmin",
    "/config.php", "/.env", "/shell.php",
    "/backup", "/db.sql"
)

SCANNER_KEYWORDS = (
    "nikto", "sqlmap", "nmap", "masscan", "acunetix"
)

def classify_web_attack(endpoint, status, user_agent=""):
    ep = endpoint.lower()
    ua = user_agent.lower()

    if any(p in ep for p in LFI_PATTERNS):
        return "LFI / Path Traversal"

    if any(p in ep for p in SQLI_PATTERNS):
        return "SQL Injection"

    if any(p in ep for p in XSS_PATTERNS):
        return "XSS Attempt"

    if any(p in ep for p in RCE_PATTERNS):
        return "Remote Code Execution"

    if any(p in ep for p in SENSITIVE_FILES):
        return "Sensitive File Scan"

    if any(p in ua for p in SCANNER_KEYWORDS):
        return "Automated Scanner"

    if status in (401, 403):
        return "Auth Brute Force"
    
    if status >= 500:
        return "Server Error"
    
    if status == 404 and any(x in ep for x in ['.php', '.asp', '.jsp', '.cgi', 'admin', 'backup', 'config']):
        return "Probe / Scan"

    return "Normal"


# Attack severity mapping for reports
ATTACK_SEVERITY = {
    'SQL Injection': ('CRITICAL', 5),
    'Remote Code Execution': ('CRITICAL', 5),
    'LFI / Path Traversal': ('HIGH', 4),
    'XSS Attempt': ('HIGH', 4),
    'SSH Brute Force': ('MEDIUM', 3),
    'Auth Brute Force': ('MEDIUM', 3),
    'FTP Brute Force': ('MEDIUM', 3),
    'SMTP Attack': ('MEDIUM', 3),
    'Database Attack': ('HIGH', 4),
    'Windows Auth Failure': ('MEDIUM', 3),
    'VPN Auth Failure': ('MEDIUM', 3),
    'WAF Block': ('HIGH', 4),
    'Blocked Connection': ('LOW', 2),
    'Sensitive File Scan': ('MEDIUM', 3),
    'Automated Scanner': ('LOW', 2),
    'Suspicious DNS Query': ('MEDIUM', 3),
    'Cloud Security Event': ('HIGH', 4),
    'Container Error': ('MEDIUM', 3),
    'Server Error': ('LOW', 2),
    'Probe / Scan': ('LOW', 2),
}


def create_chart(data, chart_type, title):
    """Create a base64 encoded chart image with blue-to-green gradient"""
    import numpy as np
    from matplotlib.colors import LinearSegmentedColormap
    
    fig, ax = plt.subplots(figsize=(4.2, 3))
    
    # Create gradient from light blue to dark green
    # Higher values = darker green (more important)
    colors = ['#87CEEB', '#5FB8E0', '#37A2D4', '#0F8CC8', '#00766B', '#006657', '#005643']
    n_bins = 100
    cmap = LinearSegmentedColormap.from_list('blue_green', colors, N=n_bins)
    
    # Normalize values to get colors (higher value = darker/more important)
    values = data.iloc[:, 1].values
    norm_values = (values - values.min()) / (values.max() - values.min()) if values.max() > values.min() else np.ones_like(values)
    bar_colors = [cmap(val) for val in norm_values]
    
    if chart_type == 'horizontal_bar':
        ax.barh(data.iloc[:, 0], data.iloc[:, 1], height=0.45, color=bar_colors)
        ax.set_xlabel(data.columns[1], color='white')
        ax.set_ylabel("", color='white')
        ax.tick_params(axis='y', colors='white')
        ax.tick_params(axis='x', colors='white')
    elif chart_type == 'vertical_bar':
        ax.bar(data.iloc[:, 0], data.iloc[:, 1], width=0.55, color=bar_colors)
        ax.set_ylabel(data.columns[1], color='white')
        ax.tick_params(axis='x', colors='white')
        ax.tick_params(axis='y', colors='white')
    
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color('white')
    ax.spines["bottom"].set_color('white')
    fig.patch.set_facecolor('#000000')
    ax.set_facecolor('#000000')
    plt.tight_layout()
    
    # Convert to base64
    img = io.BytesIO()
    plt.savefig(img, format='png', dpi=100)
    img.seek(0)
    plt.close(fig)
    
    return base64.b64encode(img.getvalue()).decode()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # ---------------- STATS & COUNTERS ----------------
    stats = {
        "total": 0,
        "parsed": 0,
        "unparsed": 0,
        "attack_types": Counter(),
        "methods": Counter(),
        "log_types": Counter()
    }
    
    ip_activity = Counter()
    log_entries = []  # Store all parsed log entries
    
    # ---------------- PARSING ----------------
    content = file.read()
    lines = content.split(b"\n")
    
    for raw in lines:
        if not raw:
            continue
        
        line = raw.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        
        stats["total"] += 1
        parsed = False
        
        # ---- WEB ACCESS LOG ----
        if not parsed and (line[0].isdigit() or line.startswith('"')):
            m = WEB_PATTERN.match(line)
            if m:
                data = m.groupdict()
                ip = data["ip"]
                method = data["method"]
                endpoint = data["endpoint"]
                status = int(data["status"])
                
                stats["parsed"] += 1
                stats["log_types"]["Web Access Log"] += 1
                stats["methods"][method] += 1
                ip_activity[ip] += 1
                
                attack = classify_web_attack(endpoint, status)
                
                if attack != "Normal":
                    stats["attack_types"][attack] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': method,
                    'endpoint': endpoint,
                    'status': str(status),
                    'attack_type': attack,
                    'log_type': 'Web Access Log'
                })
                parsed = True
        
        # ---- API ACCESS LOG ----
        if not parsed:
            m = API_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data["ip"]
                method = data["method"]
                endpoint = f"/api/{data['endpoint']}"
                status = int(data["status"])
                
                stats["parsed"] += 1
                stats["log_types"]["API Log"] += 1
                stats["methods"][method] += 1
                ip_activity[ip] += 1
                
                attack = classify_web_attack(endpoint, status)
                if attack != "Normal":
                    stats["attack_types"][attack] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': method,
                    'endpoint': endpoint,
                    'status': str(status),
                    'attack_type': attack,
                    'log_type': 'API Log'
                })
                parsed = True
        
        # ---- SSH LOG ----
        if not parsed and 'ssh' in line.lower():
            m = SSH_PATTERN.search(line)
            if m:
                ip = m.group("ip")
                action = m.group(1) if m.lastindex >= 1 else "Unknown"
                
                stats["parsed"] += 1
                stats["log_types"]["SSH Log"] += 1
                ip_activity[ip] += 1
                
                # Determine if it's an attack or normal
                if 'Accepted' in line:
                    attack_type = "Normal"
                else:
                    attack_type = "SSH Brute Force"
                    stats["attack_types"]["SSH Brute Force"] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'SSH',
                    'endpoint': action,
                    'status': 'Failed' if 'Failed' in action or 'Invalid' in action else 'Success',
                    'attack_type': attack_type,
                    'log_type': 'SSH Log'
                })
                parsed = True
        
        # ---- FTP LOG ----
        if not parsed and ('ftp' in line.lower() or 'vsftpd' in line.lower() or 'proftpd' in line.lower()):
            m = FTP_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip", "Unknown")
                action = data.get("action", "Unknown")
                
                stats["parsed"] += 1
                stats["log_types"]["FTP Log"] += 1
                if ip != "Unknown":
                    ip_activity[ip] += 1
                
                attack_type = "FTP Brute Force" if 'FAIL' in action.upper() else "Normal"
                if attack_type != "Normal":
                    stats["attack_types"][attack_type] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'FTP',
                    'endpoint': action,
                    'status': 'Failed' if 'FAIL' in action.upper() else 'Success',
                    'attack_type': attack_type,
                    'log_type': 'FTP Log'
                })
                parsed = True
        
        # ---- SMTP/EMAIL LOG ----
        if not parsed and any(kw in line.lower() for kw in ['postfix', 'sendmail', 'smtp', 'dovecot', 'mail']):
            m = SMTP_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip", "Unknown")
                action = data.get("action", "Unknown")
                
                stats["parsed"] += 1
                stats["log_types"]["SMTP Log"] += 1
                if ip != "Unknown":
                    ip_activity[ip] += 1
                
                attack_type = "SMTP Attack" if any(x in action.lower() for x in ['reject', 'denied', 'failed']) else "Normal"
                if attack_type != "Normal":
                    stats["attack_types"][attack_type] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'SMTP',
                    'endpoint': action,
                    'status': 'Blocked' if attack_type != "Normal" else 'OK',
                    'attack_type': attack_type,
                    'log_type': 'SMTP Log'
                })
                parsed = True
        
        # ---- DATABASE LOG ----
        if not parsed and any(kw in line.lower() for kw in ['mysql', 'postgresql', 'mariadb', 'mongodb', 'database']):
            m = DB_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip") or "localhost"
                action = data.get("action", "Unknown")
                
                stats["parsed"] += 1
                stats["log_types"]["Database Log"] += 1
                if ip != "localhost":
                    ip_activity[ip] += 1
                
                attack_type = "Database Attack" if any(x in action.lower() for x in ['denied', 'failed', 'invalid', 'refused']) else "Normal"
                if attack_type != "Normal":
                    stats["attack_types"][attack_type] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'DB',
                    'endpoint': action,
                    'status': 'Failed' if attack_type != "Normal" else 'OK',
                    'attack_type': attack_type,
                    'log_type': 'Database Log'
                })
                parsed = True
        
        # ---- FIREWALL LOG ----
        if not parsed and any(kw in line.upper() for kw in ['DENY', 'DROP', 'REJECT', 'BLOCK', 'IPTABLES', 'FIREWALL']):
            m = FIREWALL_PATTERN.search(line)
            if m:
                data = m.groupdict()
                src_ip = data.get("src_ip", "Unknown")
                dst_ip = data.get("dst_ip", "Unknown")
                port = data.get("port", "N/A")
                
                stats["parsed"] += 1
                stats["log_types"]["Firewall Log"] += 1
                if src_ip != "Unknown":
                    ip_activity[src_ip] += 1
                
                stats["attack_types"]["Blocked Connection"] += 1
                
                log_entries.append({
                    'ip': src_ip,
                    'method': 'FIREWALL',
                    'endpoint': f'→ {dst_ip}:{port}',
                    'status': 'Blocked',
                    'attack_type': 'Blocked Connection',
                    'log_type': 'Firewall Log'
                })
                parsed = True
        
        # ---- WINDOWS EVENT LOG ----
        if not parsed and any(kw in line.lower() for kw in ['eventid', 'event id', 'windows', '4625', '4771', '4776', '4624']):
            m = WINDOWS_PATTERN.search(line)
            if m:
                data = m.groupdict()
                event_id = data.get("event_id", "Unknown")
                ip = data.get("ip") or "local"
                
                stats["parsed"] += 1
                stats["log_types"]["Windows Event Log"] += 1
                if ip != "local":
                    ip_activity[ip] += 1
                
                # Event IDs: 4625=Failed login, 4771=Kerberos pre-auth failed, 4776=NTLM auth failed
                attack_type = "Windows Auth Failure" if event_id in ['4625', '4771', '4776'] else "Normal"
                if attack_type != "Normal":
                    stats["attack_types"][attack_type] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'WINDOWS',
                    'endpoint': f'EventID:{event_id}',
                    'status': 'Failed' if attack_type != "Normal" else 'Success',
                    'attack_type': attack_type,
                    'log_type': 'Windows Event Log'
                })
                parsed = True
        
        # ---- VPN LOG ----
        if not parsed and any(kw in line.lower() for kw in ['openvpn', 'vpn', 'ipsec', 'wireguard']):
            m = VPN_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip", "Unknown")
                action = data.get("action", "Unknown")
                
                stats["parsed"] += 1
                stats["log_types"]["VPN Log"] += 1
                if ip != "Unknown":
                    ip_activity[ip] += 1
                
                attack_type = "VPN Auth Failure" if 'failed' in action.lower() else "Normal"
                if attack_type != "Normal":
                    stats["attack_types"][attack_type] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'VPN',
                    'endpoint': action,
                    'status': 'Failed' if 'failed' in action.lower() else 'Connected',
                    'attack_type': attack_type,
                    'log_type': 'VPN Log'
                })
                parsed = True
        
        # ---- DNS LOG ----
        if not parsed and any(kw in line.lower() for kw in ['named', 'dnsmasq', 'unbound', 'dns', 'query']):
            m = DNS_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip") or "Unknown"
                domain = data.get("domain", "Unknown")
                
                stats["parsed"] += 1
                stats["log_types"]["DNS Log"] += 1
                if ip != "Unknown":
                    ip_activity[ip] += 1
                
                # Check for suspicious domains
                suspicious_tlds = ['.xyz', '.top', '.click', '.loan', '.work', '.gq', '.ml', '.tk']
                attack_type = "Suspicious DNS Query" if any(domain.endswith(tld) for tld in suspicious_tlds) else "Normal"
                if attack_type != "Normal":
                    stats["attack_types"][attack_type] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'DNS',
                    'endpoint': domain,
                    'status': 'Query',
                    'attack_type': attack_type,
                    'log_type': 'DNS Log'
                })
                parsed = True
        
        # ---- DOCKER/CONTAINER LOG ----
        if not parsed and any(kw in line.lower() for kw in ['docker', 'containerd', 'container', 'kubernetes', 'k8s']):
            m = DOCKER_PATTERN.search(line)
            if m:
                data = m.groupdict()
                container_id = data.get("container_id") or "Unknown"
                action = data.get("action", "Unknown")
                
                stats["parsed"] += 1
                stats["log_types"]["Container Log"] += 1
                
                attack_type = "Container Error" if action.lower() in ['error', 'died', 'killed', 'oom'] else "Normal"
                if attack_type != "Normal":
                    stats["attack_types"][attack_type] += 1
                
                log_entries.append({
                    'ip': container_id[:12] if container_id != "Unknown" else "N/A",
                    'method': 'DOCKER',
                    'endpoint': action,
                    'status': action.upper(),
                    'attack_type': attack_type,
                    'log_type': 'Container Log'
                })
                parsed = True
        
        # ---- CLOUD LOG (AWS/Azure/GCP) ----
        if not parsed and any(kw in line.lower() for kw in ['aws', 'cloudtrail', 'azure', 'gcp', 'iam']):
            m = CLOUD_PATTERN.search(line)
            if m:
                data = m.groupdict()
                action = data.get("action", "Unknown")
                ip = data.get("ip") or "Cloud"
                
                stats["parsed"] += 1
                stats["log_types"]["Cloud Log"] += 1
                if ip != "Cloud":
                    ip_activity[ip] += 1
                
                attack_type = "Cloud Security Event" if any(x in action.lower() for x in ['unauthorized', 'denied', 'delete']) else "Normal"
                if attack_type != "Normal":
                    stats["attack_types"][attack_type] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'CLOUD',
                    'endpoint': action,
                    'status': 'Alert' if attack_type != "Normal" else 'OK',
                    'attack_type': attack_type,
                    'log_type': 'Cloud Log'
                })
                parsed = True
        
        # ---- MODSECURITY/WAF LOG ----
        if not parsed and any(kw in line.lower() for kw in ['modsecurity', 'modsec', 'waf']):
            m = MODSEC_PATTERN.search(line)
            if m:
                data = m.groupdict()
                rule_id = data.get("rule_id", "Unknown")
                ip = data.get("ip") or "Unknown"
                action = data.get("action", "Warning")
                
                stats["parsed"] += 1
                stats["log_types"]["WAF Log"] += 1
                if ip != "Unknown":
                    ip_activity[ip] += 1
                
                stats["attack_types"]["WAF Block"] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'WAF',
                    'endpoint': f'Rule:{rule_id}',
                    'status': action,
                    'attack_type': 'WAF Block',
                    'log_type': 'WAF Log'
                })
                parsed = True
        
        # ---- NGINX ERROR LOG ----
        if not parsed and 'nginx' in line.lower() and '[error]' in line.lower():
            m = NGINX_ERROR_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip") or "Unknown"
                level = data.get("level", "error")
                message = data.get("message", "")[:50]
                
                stats["parsed"] += 1
                stats["log_types"]["Nginx Error Log"] += 1
                if ip != "Unknown":
                    ip_activity[ip] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'NGINX',
                    'endpoint': message,
                    'status': level.upper(),
                    'attack_type': 'Server Error',
                    'log_type': 'Nginx Error Log'
                })
                stats["attack_types"]["Server Error"] += 1
                parsed = True
        
        # ---- APACHE ERROR LOG ----
        if not parsed and 'apache' in line.lower() or ('[error]' in line.lower() and '[client' in line.lower()):
            m = APACHE_ERROR_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip") or "Unknown"
                level = data.get("level", "error")
                message = data.get("message", "")[:50]
                
                stats["parsed"] += 1
                stats["log_types"]["Apache Error Log"] += 1
                if ip != "Unknown":
                    ip_activity[ip] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': 'APACHE',
                    'endpoint': message,
                    'status': level.upper(),
                    'attack_type': 'Server Error',
                    'log_type': 'Apache Error Log'
                })
                stats["attack_types"]["Server Error"] += 1
                parsed = True
        
        # ---- JSON LOG FORMAT ----
        if not parsed and line.strip().startswith('{') and line.strip().endswith('}'):
            try:
                json_data = json.loads(line)
                ip = json_data.get('ip') or json_data.get('client_ip') or json_data.get('remote_addr') or json_data.get('clientIP') or "Unknown"
                method = json_data.get('method') or json_data.get('http_method') or "GET"
                endpoint = json_data.get('path') or json_data.get('url') or json_data.get('uri') or "/"
                status = json_data.get('status') or json_data.get('status_code') or json_data.get('response_code') or 200
                
                stats["parsed"] += 1
                stats["log_types"]["JSON Log"] += 1
                stats["methods"][method] += 1
                if ip != "Unknown":
                    ip_activity[ip] += 1
                
                attack = classify_web_attack(endpoint, int(status))
                if attack != "Normal":
                    stats["attack_types"][attack] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': method,
                    'endpoint': endpoint,
                    'status': str(status),
                    'attack_type': attack,
                    'log_type': 'JSON Log'
                })
                parsed = True
            except json.JSONDecodeError:
                pass
        
        # ---- SYSLOG GENERIC ----
        if not parsed:
            m = SYSLOG_PATTERN.match(line)
            if m:
                data = m.groupdict()
                host = data.get("host", "Unknown")
                process = data.get("process", "Unknown")
                message = data.get("message", "")[:50]
                
                # Extract IP from message if present
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', message)
                ip = ip_match.group(1) if ip_match else host
                
                stats["parsed"] += 1
                stats["log_types"]["Syslog"] += 1
                if ip_match:
                    ip_activity[ip] += 1
                
                log_entries.append({
                    'ip': ip,
                    'method': process,
                    'endpoint': message,
                    'status': 'Info',
                    'attack_type': 'Normal',
                    'log_type': 'Syslog'
                })
                parsed = True
        
        # ---- UNKNOWN LOG ----
        if not parsed:
            stats["unparsed"] += 1
            stats["log_types"]["Unknown Log"] += 1
    
    # ---------------- CREATE CHARTS ----------------
    charts = {}
    
    # Attack Distribution Chart
    if stats["attack_types"]:
        df_attack = (
            pd.DataFrame(stats["attack_types"].items(), columns=["Attack Type", "Count"])
            .sort_values("Count", ascending=True)
        )
        charts['attack_distribution'] = create_chart(df_attack, 'horizontal_bar', 'Attack Distribution')
    
    # Most Active IPs Chart
    if ip_activity:
        df_ips = pd.DataFrame(
            ip_activity.most_common(8),
            columns=["IP Address", "Requests"]
        ).sort_values("Requests", ascending=True)
        charts['active_ips'] = create_chart(df_ips, 'horizontal_bar', 'Most Active IPs')
    
    # HTTP Methods Chart
    if stats["methods"]:
        df_methods = pd.DataFrame(
            stats["methods"].items(),
            columns=["Method", "Count"]
        ).sort_values("Count", ascending=False)
        charts['http_methods'] = create_chart(df_methods, 'vertical_bar', 'HTTP Methods')
    
    # Log Type Classification Chart
    df_logtypes = pd.DataFrame(
        stats["log_types"].items(),
        columns=["Log Type", "Count"]
    )
    charts['log_types'] = create_chart(df_logtypes, 'vertical_bar', 'Log Types')
    
    # ---------------- PREPARE RESPONSE ----------------
    response = {
        'metrics': {
            'total': stats['total'],
            'parsed': stats['parsed'],
            'unparsed': stats['unparsed'],
            'unique_ips': len(ip_activity),
            'threats': sum(stats['attack_types'].values())
        },
        'charts': charts,
        'attack_types': dict(stats['attack_types'].most_common()),
        'top_ips': dict(ip_activity.most_common(10)),
        'methods': dict(stats['methods'].most_common()),
        'log_types': dict(stats['log_types'].most_common()),
        'log_data': log_entries  # Include parsed log entries
    }
    
    return jsonify(response)


# ---------------- HISTORY ENDPOINTS ----------------
from pathlib import Path
import os

HISTORY_DIR = Path('history')
HISTORY_DIR.mkdir(exist_ok=True)

@app.route('/history', methods=['GET'])
def get_history():
    """Get list of all saved analyses"""
    try:
        files = sorted(HISTORY_DIR.glob('analysis_*.json'), reverse=True)
        history = []
        
        for f in files:
            try:
                with open(f, 'r') as fp:
                    data = json.load(fp)
                    history.append({
                        'id': f.stem,
                        'filename': data.get('filename', 'Unknown'),
                        'date': data.get('date', ''),
                        'metrics': data.get('metrics', {})
                    })
            except Exception as e:
                print(f"Error reading {f}: {e}")
                continue
        
        return jsonify(history)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history/<id>', methods=['GET'])
def get_history_item(id):
    """Get a specific analysis by ID"""
    try:
        filepath = HISTORY_DIR / f"{id}.json"
        if not filepath.exists():
            return jsonify({'error': 'Analysis not found'}), 404
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history/<id>', methods=['DELETE'])
def delete_history_item(id):
    """Delete a specific analysis"""
    try:
        filepath = HISTORY_DIR / f"{id}.json"
        if filepath.exists():
            filepath.unlink()
            return jsonify({'success': True})
        return jsonify({'error': 'Analysis not found'}), 404
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/history', methods=['POST'])
def save_history():
    """Save a new analysis to history"""
    try:
        data = request.json
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"analysis_{timestamp}.json"
        filepath = HISTORY_DIR / filename
        
        data['date'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
        
        return jsonify({'success': True, 'id': filepath.stem})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/export-csv', methods=['POST'])
def export_csv():
    data = request.json
    columns = data.get('columns', [])
    log_data = data.get('data', [])
    
    if not columns or not log_data:
        return jsonify({'error': 'No data to export'}), 400
    
    # Create CSV in memory
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=columns)
    writer.writeheader()
    
    for entry in log_data:
        row = {col: entry.get(col, 'N/A') for col in columns}
        writer.writerow(row)
    
    # Convert to bytes
    csv_bytes = io.BytesIO(output.getvalue().encode('utf-8'))
    csv_bytes.seek(0)
    
    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'DataSmith_Logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@app.route('/export-json', methods=['POST'])
def export_json():
    data = request.json
    columns = data.get('columns', [])
    log_data = data.get('data', [])
    
    if not columns or not log_data:
        return jsonify({'error': 'No data to export'}), 400
    
    # Filter data by selected columns
    filtered_data = [
        {col: entry.get(col, 'N/A') for col in columns}
        for entry in log_data
    ]
    
    # Create JSON in memory
    json_str = json.dumps(filtered_data, indent=2)
    json_bytes = io.BytesIO(json_str.encode('utf-8'))
    json_bytes.seek(0)
    
    return send_file(
        json_bytes,
        mimetype='application/json',
        as_attachment=True,
        download_name=f'DataSmith_Logs_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    )


@app.route('/generate-report', methods=['POST'])
def generate_report():
    """Generate a professional security analysis PDF report"""
    data = request.json
    metrics = data.get('metrics', {})
    attack_types = data.get('attack_types', {})
    top_ips = data.get('top_ips', {})
    charts = data.get('charts', {})
    
    # Create PDF buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.6*inch, bottomMargin=0.6*inch,
        leftMargin=0.7*inch, rightMargin=0.7*inch
    )
    
    # Color palette
    CYBER_GREEN = colors.HexColor('#00ff41')
    DARK_NAVY = colors.HexColor('#0a192f')
    LIGHT_NAVY = colors.HexColor('#172a45')
    SLATE = colors.HexColor('#8892b0')
    LIGHT_SLATE = colors.HexColor('#ccd6f6')
    WHITE = colors.white
    
    CRITICAL_RED = colors.HexColor('#ff4757')
    HIGH_ORANGE = colors.HexColor('#ffa502')
    MEDIUM_YELLOW = colors.HexColor('#ffdd59')
    LOW_BLUE = colors.HexColor('#70a1ff')
    SECURE_GREEN = colors.HexColor('#2ed573')
    
    styles = getSampleStyleSheet()
    
    # Styles
    def create_style(name, parent='Normal', **kwargs):
        return ParagraphStyle(name, parent=styles[parent], **kwargs)
    
    title_main = create_style('TitleMain', 'Heading1',
        fontSize=42, textColor=CYBER_GREEN, alignment=TA_CENTER,
        fontName='Helvetica-Bold', spaceAfter=10, leading=50)
    
    subtitle = create_style('Subtitle',
        fontSize=18, textColor=SLATE, alignment=TA_CENTER,
        fontName='Helvetica', spaceAfter=30)
    
    section_title = create_style('SectionTitle', 'Heading1',
        fontSize=22, textColor=CYBER_GREEN, fontName='Helvetica-Bold',
        spaceAfter=15, spaceBefore=10, leftIndent=0)
    
    subsection = create_style('Subsection', 'Heading2',
        fontSize=14, textColor=LOW_BLUE, fontName='Helvetica-Bold',
        spaceAfter=10, spaceBefore=15)
    
    body = create_style('Body',
        fontSize=11, textColor=colors.black, fontName='Helvetica',
        spaceAfter=8, leading=16)
    
    small_text = create_style('SmallText',
        fontSize=9, textColor=SLATE, fontName='Helvetica',
        alignment=TA_CENTER, spaceAfter=5)
    
    story = []
    
    # ═══════════════════════════════════════════════════════════════
    # COVER PAGE
    # ═══════════════════════════════════════════════════════════════
    story.append(Spacer(1, 1.2*inch))
    
    # Logo/Icon area
    logo_table = Table([['🛡️']], colWidths=[7*inch])
    logo_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTSIZE', (0, 0), (-1, -1), 80),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
    ]))
    story.append(logo_table)
    
    story.append(Paragraph("DATASMITH PRO", title_main))
    story.append(Paragraph("Security Intelligence Report", subtitle))
    
    story.append(Spacer(1, 0.3*inch))
    
    # Cover metrics box
    threat_count = metrics.get('threats', 0)
    total_logs = metrics.get('total', 0)
    unique_ips = metrics.get('unique_ips', 0)
    
    cover_data = [
        [f'{total_logs:,}', f'{threat_count:,}', f'{unique_ips:,}'],
        ['Logs Analyzed', 'Threats Found', 'Unique IPs']
    ]
    
    cover_table = Table(cover_data, colWidths=[2.2*inch, 2.2*inch, 2.2*inch])
    cover_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 32),
        ('FONTSIZE', (0, 1), (-1, 1), 10),
        ('TEXTCOLOR', (0, 0), (0, 0), CYBER_GREEN),
        ('TEXTCOLOR', (1, 0), (1, 0), CRITICAL_RED if threat_count > 0 else SECURE_GREEN),
        ('TEXTCOLOR', (2, 0), (2, 0), LOW_BLUE),
        ('TEXTCOLOR', (0, 1), (-1, 1), SLATE),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
        ('BOX', (0, 0), (-1, -1), 2, colors.HexColor('#e9ecef')),
    ]))
    story.append(cover_table)
    
    story.append(Spacer(1, 0.8*inch))
    
    # Report metadata
    report_id = datetime.now().strftime('%Y%m%d-%H%M%S')
    report_date = datetime.now().strftime('%B %d, %Y • %I:%M %p')
    
    meta_text = f"""<para alignment="center">
    <font color="#666666" size="10">
    Report ID: <b>{report_id}</b><br/>
    Generated: {report_date}<br/>
    Classification: <font color="#ff4757"><b>CONFIDENTIAL</b></font>
    </font>
    </para>"""
    story.append(Paragraph(meta_text, body))
    
    story.append(PageBreak())
    
    # ═══════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════
    story.append(Paragraph("📋 EXECUTIVE SUMMARY", section_title))
    
    # Summary paragraph
    parse_rate = (metrics.get('parsed', 0) / max(metrics.get('total', 1), 1)) * 100
    summary = f"""This security analysis processed <b>{metrics.get('total', 0):,}</b> log entries 
    with a <b>{parse_rate:.1f}%</b> parse success rate. The scan identified 
    <b>{metrics.get('unique_ips', 0):,}</b> unique IP addresses and detected 
    <b>{metrics.get('threats', 0):,}</b> potential security threats requiring attention."""
    story.append(Paragraph(summary, body))
    story.append(Spacer(1, 0.3*inch))
    
    # Metrics table
    metrics_rows = [
        ['Metric', 'Value', 'Status'],
        ['Total Logs Scanned', f"{metrics.get('total', 0):,}", '✓ Complete'],
        ['Successfully Parsed', f"{metrics.get('parsed', 0):,}", f'{parse_rate:.1f}%'],
        ['Parse Failures', f"{metrics.get('unparsed', 0):,}", '⚠ Review' if metrics.get('unparsed', 0) > 0 else '✓ OK'],
        ['Unique IP Addresses', f"{metrics.get('unique_ips', 0):,}", 'ℹ Info'],
        ['Threats Detected', f"{metrics.get('threats', 0):,}", '🔴 Alert' if metrics.get('threats', 0) > 0 else '✓ Clear'],
    ]
    
    metrics_tbl = Table(metrics_rows, colWidths=[2.8*inch, 1.8*inch, 1.6*inch])
    metrics_tbl.setStyle(TableStyle([
        # Header
        ('BACKGROUND', (0, 0), (-1, 0), DARK_NAVY),
        ('TEXTCOLOR', (0, 0), (-1, 0), CYBER_GREEN),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
        
        # Body
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 1), (-1, -1), 10),
        ('ALIGN', (1, 1), (1, -1), 'RIGHT'),
        ('ALIGN', (2, 1), (2, -1), 'CENTER'),
        
        # Styling
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, colors.HexColor('#f8f9fa')]),
        ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
        ('LINEBELOW', (0, 0), (-1, 0), 2, CYBER_GREEN),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
        ('LEFTPADDING', (0, 0), (-1, -1), 15),
        ('RIGHTPADDING', (0, 0), (-1, -1), 15),
    ]))
    story.append(metrics_tbl)
    story.append(Spacer(1, 0.4*inch))
    
    # Threat Level Indicator
    t = metrics.get('threats', 0)
    if t > 50:
        level, level_color, level_desc = 'CRITICAL', CRITICAL_RED, 'Immediate action required'
    elif t > 20:
        level, level_color, level_desc = 'HIGH', HIGH_ORANGE, 'Urgent attention needed'
    elif t > 5:
        level, level_color, level_desc = 'MEDIUM', MEDIUM_YELLOW, 'Review recommended'
    elif t > 0:
        level, level_color, level_desc = 'LOW', LOW_BLUE, 'Monitor situation'
    else:
        level, level_color, level_desc = 'SECURE', SECURE_GREEN, 'No threats detected'
    
    threat_box = Table(
        [[f'THREAT LEVEL: {level}'], [level_desc]],
        colWidths=[6.2*inch]
    )
    threat_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (0, 0), 24),
        ('FONTSIZE', (0, 1), (0, 1), 11),
        ('TEXTCOLOR', (0, 0), (0, 0), level_color),
        ('TEXTCOLOR', (0, 1), (0, 1), SLATE),
        ('TOPPADDING', (0, 0), (-1, -1), 20),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 20),
        ('BOX', (0, 0), (-1, -1), 3, level_color),
    ]))
    story.append(threat_box)
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK ANALYSIS
    # ═══════════════════════════════════════════════════════════════
    if attack_types:
        story.append(PageBreak())
        story.append(Paragraph("🎯 THREAT ANALYSIS", section_title))
        
        severity_config = {
            # Critical
            'SQL Injection': (CRITICAL_RED, 'CRITICAL', 5),
            'Remote Code Execution': (CRITICAL_RED, 'CRITICAL', 5),
            # High
            'LFI / Path Traversal': (HIGH_ORANGE, 'HIGH', 4),
            'XSS Attempt': (HIGH_ORANGE, 'HIGH', 4),
            'Database Attack': (HIGH_ORANGE, 'HIGH', 4),
            'WAF Block': (HIGH_ORANGE, 'HIGH', 4),
            'Cloud Security Event': (HIGH_ORANGE, 'HIGH', 4),
            # Medium
            'SSH Brute Force': (MEDIUM_YELLOW, 'MEDIUM', 3),
            'Auth Brute Force': (MEDIUM_YELLOW, 'MEDIUM', 3),
            'FTP Brute Force': (MEDIUM_YELLOW, 'MEDIUM', 3),
            'SMTP Attack': (MEDIUM_YELLOW, 'MEDIUM', 3),
            'Windows Auth Failure': (MEDIUM_YELLOW, 'MEDIUM', 3),
            'VPN Auth Failure': (MEDIUM_YELLOW, 'MEDIUM', 3),
            'Sensitive File Scan': (MEDIUM_YELLOW, 'MEDIUM', 3),
            'Suspicious DNS Query': (MEDIUM_YELLOW, 'MEDIUM', 3),
            'Container Error': (MEDIUM_YELLOW, 'MEDIUM', 3),
            # Low
            'Automated Scanner': (LOW_BLUE, 'LOW', 2),
            'Blocked Connection': (LOW_BLUE, 'LOW', 2),
            'Server Error': (LOW_BLUE, 'LOW', 2),
            'Probe / Scan': (LOW_BLUE, 'LOW', 2),
        }
        
        attack_rows = [['Attack Type', 'Count', 'Severity', 'Priority']]
        sorted_attacks = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)
        
        for attack, count in sorted_attacks:
            color, sev, pri = severity_config.get(attack, (SLATE, 'INFO', 1))
            attack_rows.append([attack, str(count), sev, '●' * pri])
        
        attack_tbl = Table(attack_rows, colWidths=[2.8*inch, 1*inch, 1.2*inch, 1.2*inch])
        
        tbl_style = [
            ('BACKGROUND', (0, 0), (-1, 0), DARK_NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), CYBER_GREEN),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (1, 1), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('LINEBELOW', (0, 0), (-1, 0), 2, CYBER_GREEN),
            ('TOPPADDING', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 12),
            ('RIGHTPADDING', (0, 0), (-1, -1), 12),
        ]
        
        # Color-code rows by severity
        for i, (attack, _) in enumerate(sorted_attacks, 1):
            color, _, _ = severity_config.get(attack, (SLATE, 'INFO', 1))
            if color == CRITICAL_RED:
                bg = colors.HexColor('#ffe8e8')
            elif color == HIGH_ORANGE:
                bg = colors.HexColor('#fff3e0')
            elif color == MEDIUM_YELLOW:
                bg = colors.HexColor('#fffde7')
            else:
                bg = colors.HexColor('#e3f2fd')
            tbl_style.append(('BACKGROUND', (0, i), (-1, i), bg))
            tbl_style.append(('TEXTCOLOR', (3, i), (3, i), color))
        
        attack_tbl.setStyle(TableStyle(tbl_style))
        story.append(attack_tbl)
        story.append(Spacer(1, 0.4*inch))
    
    # ═══════════════════════════════════════════════════════════════
    # TOP IPs
    # ═══════════════════════════════════════════════════════════════
    if top_ips:
        story.append(Paragraph("🔍 TOP SUSPICIOUS IPs", section_title))
        
        ip_rows = [['#', 'IP Address', 'Requests', 'Threat Level']]
        sorted_ips = list(top_ips.items())[:10]
        max_req = max([c for _, c in sorted_ips]) if sorted_ips else 1
        
        for i, (ip, count) in enumerate(sorted_ips, 1):
            pct = (count / max_req) * 100
            if pct >= 80:
                bar = '██████████   '
                color = CRITICAL_RED
            elif pct >= 60:
                bar = '████████░░'
                color = HIGH_ORANGE
            elif pct >= 40:
                bar = '██████░░░░'
                color = MEDIUM_YELLOW
            else:
                bar = '████░░░░░░'
                color = LOW_BLUE
            ip_rows.append([str(i), ip, str(count), bar])
        
        ip_tbl = Table(ip_rows, colWidths=[0.5*inch, 2.5*inch, 1.2*inch, 2*inch])
        
        ip_style = [
            ('BACKGROUND', (0, 0), (-1, 0), DARK_NAVY),
            ('TEXTCOLOR', (0, 0), (-1, 0), CYBER_GREEN),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 11),
            ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
            ('FONTNAME', (0, 1), (0, -1), 'Helvetica-Bold'),
            ('FONTNAME', (1, 1), (-1, -1), 'Courier'),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
            ('ALIGN', (0, 1), (0, -1), 'CENTER'),
            ('ALIGN', (2, 1), (2, -1), 'RIGHT'),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, colors.HexColor('#f8f9fa')]),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ('LINEBELOW', (0, 0), (-1, 0), 2, CYBER_GREEN),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]
        
        ip_tbl.setStyle(TableStyle(ip_style))
        story.append(ip_tbl)
    
    # ═══════════════════════════════════════════════════════════════
    # CHARTS
    # ═══════════════════════════════════════════════════════════════
    if charts:
        story.append(PageBreak())
        story.append(Paragraph("📊 VISUAL ANALYTICS", section_title))
        
        chart_info = [
            ('attack_distribution', 'Attack Type Distribution'),
            ('active_ips', 'Most Active IP Addresses'),
            ('http_methods', 'HTTP Methods Analysis'),
            ('log_types', 'Log Type Breakdown'),
        ]
        
        for key, title in chart_info:
            if key not in charts:
                continue
            
            story.append(Paragraph(title, subsection))
            
            try:
                img_data = base64.b64decode(charts[key])
                img_buf = io.BytesIO(img_data)
                img = Image(img_buf, width=5.5*inch, height=3.2*inch)
                
                img_wrapper = Table([[img]], colWidths=[5.8*inch])
                img_wrapper.setStyle(TableStyle([
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                    ('BACKGROUND', (0, 0), (-1, -1), WHITE),
                    ('TOPPADDING', (0, 0), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ]))
                story.append(img_wrapper)
                story.append(Spacer(1, 0.3*inch))
            except Exception as e:
                print(f"Chart error ({key}): {e}")
    
    # ═══════════════════════════════════════════════════════════════
    # RECOMMENDATIONS
    # ═══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("💡 RECOMMENDATIONS", section_title))
    
    if metrics.get('threats', 0) > 0:
        recs = [
            ('🔴 IMMEDIATE', CRITICAL_RED, [
                'Block identified malicious IP addresses at firewall level',
                'Review and patch vulnerable endpoints immediately',
                'Enable enhanced logging for affected systems'
            ]),
            ('🟠 HIGH PRIORITY', HIGH_ORANGE, [
                'Implement rate limiting on authentication endpoints',
                'Deploy Web Application Firewall (WAF) rules',
                'Set up real-time security alerts'
            ]),
            ('🟡 MEDIUM PRIORITY', MEDIUM_YELLOW, [
                'Conduct full security audit of exposed services',
                'Update all software to latest secure versions',
                'Review access control policies'
            ]),
            ('🟢 ONGOING', SECURE_GREEN, [
                'Schedule regular penetration testing',
                'Implement security awareness training',
                'Establish incident response procedures'
            ]),
        ]
    else:
        recs = [
            ('🟢 MAINTENANCE', SECURE_GREEN, [
                'Continue regular log monitoring',
                'Keep systems updated with security patches',
                'Conduct periodic security assessments',
                'Document and maintain security procedures'
            ]),
        ]
    
    for title, color, items in recs:
        story.append(Paragraph(title, create_style('RecTitle',
            fontSize=13, fontName='Helvetica-Bold', textColor=color,
            spaceBefore=15, spaceAfter=8)))
        for item in items:
            story.append(Paragraph(f'  • {item}', body))
    
    # ═══════════════════════════════════════════════════════════════
    # FOOTER
    # ═══════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.5*inch))
    
    footer_line = Table([['']], colWidths=[6.5*inch])
    footer_line.setStyle(TableStyle([
        ('LINEABOVE', (0, 0), (-1, -1), 2, CYBER_GREEN),
    ]))
    story.append(footer_line)
    story.append(Spacer(1, 0.15*inch))
    
    footer = f"""<para alignment="center" fontSize="8" textColor="#666666">
    <b>DATASMITH PRO</b> — Security Intelligence Platform<br/>
    Report #{report_id} | {report_date}<br/>
    This document is confidential. Unauthorized distribution is prohibited.<br/>
    © 2025 DataSmith Pro. All rights reserved.
    </para>"""
    story.append(Paragraph(footer, body))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=f'DataSmith_Report_{report_id}.pdf'
    )

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

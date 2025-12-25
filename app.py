from flask import Flask, render_template, request, jsonify, send_file, make_response
import re
import io
import base64
import json
import csv
import gc
import os
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
from flask_socketio import SocketIO, emit

mpl.rcParams.update({
    "axes.titlesize": 9,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7
})

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB max file size
app.config['SECRET_KEY'] = 'datasmith-secret-key-2025'

# Initialize SocketIO for real-time communication
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Initialize live monitor
from live_monitor import init_live_monitor, live_monitor
monitor = init_live_monitor(socketio)

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


# Global progress tracking for current analysis
analysis_progress = {
    'lines_processed': 0,
    'threats_found': 0,
    'current_stage': 'idle',
    'progress_percent': 0
}

@app.route('/analyze', methods=['POST'])
def analyze():
    global analysis_progress
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Reset progress
    analysis_progress = {
        'lines_processed': 0,
        'threats_found': 0,
        'current_stage': 'parsing',
        'progress_percent': 0
    }
    
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
    log_entries = []  # Store suspicious/attack log entries only (limited)
    
    # ---------------- CONFIGURATION FOR LARGE FILES ----------------
    MAX_LOG_ENTRIES = 10000  # Limit stored entries to prevent memory overflow
    PROGRESS_UPDATE_INTERVAL = 5000  # Emit progress every N lines
    
    # ---------------- STREAMING LINE-BY-LINE PARSING ----------------
    # Read file in streaming mode to handle large files efficiently
    file.seek(0)  # Ensure we're at the start
    
    for raw in file:
        if not raw:
            continue
        
        line = raw.decode("utf-8", errors="ignore").strip()
        if not line:
            continue
        
        stats["total"] += 1
        
        # Emit progress updates via WebSocket for real-time UI updates
        if stats["total"] % PROGRESS_UPDATE_INTERVAL == 0:
            analysis_progress['lines_processed'] = stats["total"]
            analysis_progress['threats_found'] = sum(stats["attack_types"].values())
            try:
                socketio.emit('analysis_progress', analysis_progress, namespace='/live')
            except:
                pass  # Don't fail if no clients connected
        
        # Garbage collection every 100K lines to free memory
        if stats["total"] % 100000 == 0:
            gc.collect()
        
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
                    # Only store suspicious entries to save memory
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                
                if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                
                if len(log_entries) < MAX_LOG_ENTRIES:
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
                
                stats["attack_types"]["Server Error"] += 1
                if len(log_entries) < MAX_LOG_ENTRIES:
                    log_entries.append({
                        'ip': ip,
                        'method': 'NGINX',
                        'endpoint': message,
                        'status': level.upper(),
                        'attack_type': 'Server Error',
                        'log_type': 'Nginx Error Log'
                    })
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
                
                stats["attack_types"]["Server Error"] += 1
                if len(log_entries) < MAX_LOG_ENTRIES:
                    log_entries.append({
                        'ip': ip,
                        'method': 'APACHE',
                        'endpoint': message,
                        'status': level.upper(),
                        'attack_type': 'Server Error',
                        'log_type': 'Apache Error Log'
                    })
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
                    if len(log_entries) < MAX_LOG_ENTRIES:
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
                
                # Syslog entries are generally normal - don't store to save memory
                parsed = True
        
        # ---- UNKNOWN LOG ----
        if not parsed:
            stats["unparsed"] += 1
            stats["log_types"]["Unknown Log"] += 1
    
    # Final garbage collection after processing
    gc.collect()
    
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
    # Final progress update
    analysis_progress['lines_processed'] = stats['total']
    analysis_progress['threats_found'] = sum(stats['attack_types'].values())
    analysis_progress['current_stage'] = 'complete'
    analysis_progress['progress_percent'] = 100
    
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


@app.route('/analysis-progress', methods=['GET'])
def get_analysis_progress():
    """Get real-time analysis progress for the pipeline UI"""
    global analysis_progress
    return jsonify(analysis_progress)


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


# ================== ATTACK-WISE REPORT GENERATION ==================

def create_attack_chart(attack_data, title, chart_type='bar'):
    """Create a chart for specific attack data"""
    import numpy as np
    from matplotlib.colors import LinearSegmentedColormap
    
    fig, ax = plt.subplots(figsize=(5, 3.5))
    
    if not attack_data:
        ax.text(0.5, 0.5, 'No Data', ha='center', va='center', fontsize=14, color='gray')
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
    else:
        labels = list(attack_data.keys())[:10]
        values = list(attack_data.values())[:10]
        
        # Color gradient based on severity
        colors_list = ['#ff4757', '#ffa502', '#ffdd59', '#70a1ff', '#2ed573']
        n_bars = len(labels)
        bar_colors = [colors_list[i % len(colors_list)] for i in range(n_bars)]
        
        if chart_type == 'horizontal_bar':
            ax.barh(labels, values, color=bar_colors, height=0.6)
            ax.set_xlabel('Count', color='#333')
        elif chart_type == 'pie':
            ax.pie(values, labels=labels, autopct='%1.1f%%', colors=bar_colors, startangle=90)
        else:
            ax.bar(labels, values, color=bar_colors, width=0.6)
            ax.set_ylabel('Count', color='#333')
            plt.xticks(rotation=45, ha='right')
    
    ax.set_title(title, fontsize=12, fontweight='bold', color='#0a192f')
    
    for spine in ax.spines.values():
        spine.set_color('#ccc')
    
    fig.patch.set_facecolor('white')
    ax.set_facecolor('#fafafa')
    plt.tight_layout()
    
    # Convert to base64
    img = io.BytesIO()
    plt.savefig(img, format='png', dpi=120, bbox_inches='tight')
    img.seek(0)
    plt.close(fig)
    
    return base64.b64encode(img.getvalue()).decode()


@app.route('/generate-attack-report', methods=['POST'])
def generate_attack_report():
    """Generate a PDF report filtered by selected attack types"""
    data = request.json
    
    # Get selections
    selected_attacks = data.get('selected_attacks', [])  # List of attack types to include
    metrics = data.get('metrics', {})
    attack_types = data.get('attack_types', {})
    top_ips = data.get('top_ips', {})
    log_data = data.get('log_data', [])
    include_charts = data.get('include_charts', True)
    include_details = data.get('include_details', True)
    
    if not selected_attacks:
        return jsonify({'error': 'No attack types selected'}), 400
    
    # Filter data by selected attacks
    filtered_attacks = {k: v for k, v in attack_types.items() if k in selected_attacks}
    filtered_logs = [log for log in log_data if log.get('attack_type') in selected_attacks]
    
    # Get IPs involved in selected attacks
    attack_ips = Counter()
    for log in filtered_logs:
        ip = log.get('ip')
        if ip and ip != 'Unknown':
            attack_ips[ip] += 1
    
    # Create PDF buffer
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer, pagesize=letter,
        topMargin=0.5*inch, bottomMargin=0.5*inch,
        leftMargin=0.6*inch, rightMargin=0.6*inch
    )
    
    # Professional Color palette
    CYBER_GREEN = colors.HexColor('#00ff41')
    DARK_NAVY = colors.HexColor('#0a192f')
    SLATE = colors.HexColor('#8892b0')
    CRITICAL_RED = colors.HexColor('#ff4757')
    HIGH_ORANGE = colors.HexColor('#ffa502')
    MEDIUM_YELLOW = colors.HexColor('#ffdd59')
    LOW_BLUE = colors.HexColor('#70a1ff')
    SECURE_GREEN = colors.HexColor('#2ed573')
    WHITE = colors.white
    
    # Attack severity configuration
    SEVERITY_CONFIG = {
        'SQL Injection': (CRITICAL_RED, 'CRITICAL', 5),
        'Remote Code Execution': (CRITICAL_RED, 'CRITICAL', 5),
        'LFI / Path Traversal': (CRITICAL_RED, 'CRITICAL', 5),
        'XSS Attempt': (HIGH_ORANGE, 'HIGH', 4),
        'Database Attack': (HIGH_ORANGE, 'HIGH', 4),
        'WAF Block': (HIGH_ORANGE, 'HIGH', 4),
        'Cloud Security Event': (HIGH_ORANGE, 'HIGH', 4),
        'SSH Brute Force': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'Auth Brute Force': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'FTP Brute Force': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'SMTP Attack': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'Windows Auth Failure': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'VPN Auth Failure': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'Sensitive File Scan': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'Suspicious DNS Query': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'Container Error': (MEDIUM_YELLOW, 'MEDIUM', 3),
        'Automated Scanner': (LOW_BLUE, 'LOW', 2),
        'Blocked Connection': (LOW_BLUE, 'LOW', 2),
        'Server Error': (LOW_BLUE, 'LOW', 2),
        'Probe / Scan': (LOW_BLUE, 'LOW', 2),
    }
    
    styles = getSampleStyleSheet()
    
    def create_style(name, **kwargs):
        return ParagraphStyle(name, parent=styles['Normal'], **kwargs)
    
    # Professional Custom styles
    title_main = create_style('TitleMain',
        fontSize=32, textColor=DARK_NAVY, alignment=TA_CENTER,
        fontName='Helvetica-Bold', spaceAfter=15, spaceBefore=10)
    
    subtitle = create_style('Subtitle',
        fontSize=14, textColor=CYBER_GREEN, alignment=TA_CENTER,
        fontName='Helvetica', spaceAfter=25, spaceBefore=5)
    
    section_title = create_style('SectionTitle',
        fontSize=18, textColor=CYBER_GREEN, fontName='Helvetica-Bold',
        spaceAfter=15, spaceBefore=20, leftIndent=0)
    
    body = create_style('Body',
        fontSize=11, textColor=colors.black, fontName='Helvetica',
        spaceAfter=8, leading=16)
    
    small_text = create_style('SmallText',
        fontSize=9, textColor=SLATE, fontName='Helvetica',
        alignment=TA_CENTER, spaceAfter=5)
    
    story = []
    
    # ═══════════════════════════════════════════════════════════════
    # COVER PAGE - Professional Design
    # ═══════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.8*inch))
    
    # Professional header box with shield icon
    header_box = Table(
        [['[ SECURITY REPORT ]']],
        colWidths=[6.5*inch]
    )
    header_box.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 14),
        ('TEXTCOLOR', (0, 0), (-1, -1), CYBER_GREEN),
        ('BACKGROUND', (0, 0), (-1, -1), DARK_NAVY),
        ('TOPPADDING', (0, 0), (-1, -1), 12),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
    ]))
    story.append(header_box)
    
    story.append(Spacer(1, 0.5*inch))
    
    # Main title
    story.append(Paragraph("ATTACK ANALYSIS", title_main))
    story.append(Spacer(1, 0.1*inch))
    story.append(Paragraph("Security Intelligence Report", subtitle))
    
    story.append(Spacer(1, 0.4*inch))
    
    # Cover metrics box - Professional styling
    total_threats = sum(filtered_attacks.values())
    unique_ips = len(attack_ips)
    attack_count = len(selected_attacks)
    
    cover_data = [
        [f'{total_threats:,}', f'{attack_count}', f'{unique_ips:,}'],
        ['Threats Found', 'Attack Types', 'Attacker IPs']
    ]
    
    cover_table = Table(cover_data, colWidths=[2.2*inch, 2.2*inch, 2.2*inch])
    cover_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 32),
        ('FONTSIZE', (0, 1), (-1, 1), 10),
        ('TEXTCOLOR', (0, 0), (0, 0), CRITICAL_RED),
        ('TEXTCOLOR', (1, 0), (1, 0), CYBER_GREEN),
        ('TEXTCOLOR', (2, 0), (2, 0), LOW_BLUE),
        ('TEXTCOLOR', (0, 1), (-1, 1), SLATE),
        ('TOPPADDING', (0, 0), (-1, -1), 15),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 15),
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
        ('BOX', (0, 0), (-1, -1), 2, colors.HexColor('#e9ecef')),
    ]))
    story.append(cover_table)
    
    story.append(Spacer(1, 0.5*inch))
    
    # Threat Level Indicator based on severity
    critical_count = sum(v for k, v in filtered_attacks.items() if SEVERITY_CONFIG.get(k, (SLATE, 'INFO', 1))[1] == 'CRITICAL')
    high_count = sum(v for k, v in filtered_attacks.items() if SEVERITY_CONFIG.get(k, (SLATE, 'INFO', 1))[1] == 'HIGH')
    
    if critical_count > 0:
        level, level_color, level_desc = 'CRITICAL', CRITICAL_RED, 'Immediate action required - Critical threats detected'
    elif high_count > 0:
        level, level_color, level_desc = 'HIGH', HIGH_ORANGE, 'Urgent attention needed - High severity threats'
    elif total_threats > 10:
        level, level_color, level_desc = 'MEDIUM', MEDIUM_YELLOW, 'Review recommended - Multiple threats detected'
    elif total_threats > 0:
        level, level_color, level_desc = 'LOW', LOW_BLUE, 'Monitor situation - Minor threats detected'
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
        ('FONTSIZE', (0, 0), (0, 0), 22),
        ('FONTSIZE', (0, 1), (0, 1), 11),
        ('TEXTCOLOR', (0, 0), (0, 0), level_color),
        ('TEXTCOLOR', (0, 1), (0, 1), SLATE),
        ('TOPPADDING', (0, 0), (-1, -1), 18),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 18),
        ('BOX', (0, 0), (-1, -1), 3, level_color),
    ]))
    story.append(threat_box)
    
    story.append(Spacer(1, 0.5*inch))
    
    # Report metadata
    report_id = datetime.now().strftime('%Y%m%d-%H%M%S')
    report_date = datetime.now().strftime('%B %d, %Y • %I:%M %p')
    
    meta_text = f"""<para alignment="center">
    <font color="#666666" size="10">
    Report ID: <b>ATK-{report_id}</b><br/>
    Generated: {report_date}<br/>
    Classification: <font color="#ff4757"><b>CONFIDENTIAL</b></font>
    </font>
    </para>"""
    story.append(Paragraph(meta_text, body))
    
    story.append(PageBreak())
    
    # ═══════════════════════════════════════════════════════════════
    # EXECUTIVE SUMMARY
    # ═══════════════════════════════════════════════════════════════
    story.append(Paragraph("[+] EXECUTIVE SUMMARY", section_title))
    
    # Summary paragraph
    summary = f"""This focused attack analysis report examines <b>{len(selected_attacks)}</b> specific attack types 
    selected for review. The analysis identified <b>{total_threats:,}</b> threat instances 
    originating from <b>{unique_ips:,}</b> unique IP addresses. 
    This report provides detailed breakdown and actionable recommendations."""
    story.append(Paragraph(summary, body))
    story.append(Spacer(1, 0.2*inch))
    
    # Selected attacks list
    attacks_text = ", ".join(selected_attacks)
    story.append(Paragraph(f"<b>Selected Attack Types:</b> {attacks_text}", body))
    story.append(Spacer(1, 0.3*inch))
    
    # ═══════════════════════════════════════════════════════════════
    # ATTACK METRICS TABLE - Professional styling
    # ═══════════════════════════════════════════════════════════════
    story.append(Paragraph("[!] THREAT OVERVIEW", section_title))
    
    # Attack types table with severity
    attack_rows = [['Attack Type', 'Count', 'Severity', 'Priority']]
    sorted_attacks = sorted(filtered_attacks.items(), key=lambda x: x[1], reverse=True)
    
    for attack, count in sorted_attacks:
        color, sev, pri = SEVERITY_CONFIG.get(attack, (SLATE, 'INFO', 1))
        attack_rows.append([attack, f'{count:,}', sev, '●' * pri])
    
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
        color, sev, _ = SEVERITY_CONFIG.get(attack, (SLATE, 'INFO', 1))
        if sev == 'CRITICAL':
            bg = colors.HexColor('#ffe8e8')
        elif sev == 'HIGH':
            bg = colors.HexColor('#fff3e0')
        elif sev == 'MEDIUM':
            bg = colors.HexColor('#fffde7')
        else:
            bg = colors.HexColor('#e3f2fd')
        tbl_style.append(('BACKGROUND', (0, i), (-1, i), bg))
        tbl_style.append(('TEXTCOLOR', (3, i), (3, i), color))
        tbl_style.append(('TEXTCOLOR', (2, i), (2, i), color))
    
    attack_tbl.setStyle(TableStyle(tbl_style))
    story.append(attack_tbl)
    story.append(Spacer(1, 0.4*inch))
    
    # ═══════════════════════════════════════════════════════════════
    # TOP ATTACKER IPs TABLE - Professional styling
    # ═══════════════════════════════════════════════════════════════
    if attack_ips:
        story.append(Paragraph("[>] TOP ATTACKER IPs", section_title))
        
        ip_rows = [['#', 'IP Address', 'Requests', 'Threat Level']]
        sorted_ips = attack_ips.most_common(10)
        max_req = max([c for _, c in sorted_ips]) if sorted_ips else 1
        
        for i, (ip, count) in enumerate(sorted_ips, 1):
            pct = (count / max_req) * 100
            if pct >= 80:
                bar = '██████████'
                ip_color = CRITICAL_RED
            elif pct >= 60:
                bar = '████████░░'
                ip_color = HIGH_ORANGE
            elif pct >= 40:
                bar = '██████░░░░'
                ip_color = MEDIUM_YELLOW
            else:
                bar = '████░░░░░░'
                ip_color = LOW_BLUE
            ip_rows.append([str(i), ip, f'{count:,}', bar])
        
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
        story.append(Spacer(1, 0.3*inch))
    
    # ═══════════════════════════════════════════════════════════════
    # VISUAL CHARTS SECTION
    # ═══════════════════════════════════════════════════════════════
    if include_charts and filtered_attacks:
        story.append(PageBreak())
        story.append(Paragraph("[#] VISUAL ANALYTICS", section_title))
        
        # Create professional chart container
        chart_intro = """The following charts provide visual representation of the attack patterns 
        and threat distribution identified in this analysis."""
        story.append(Paragraph(chart_intro, body))
        story.append(Spacer(1, 0.2*inch))
        
        # Attack distribution chart
        story.append(Paragraph("<b>Attack Type Distribution</b>", body))
        chart_b64 = create_attack_chart(filtered_attacks, 'Threats by Attack Type', 'horizontal_bar')
        chart_img = Image(io.BytesIO(base64.b64decode(chart_b64)), width=5.5*inch, height=3.2*inch)
        story.append(chart_img)
        story.append(Spacer(1, 0.3*inch))
        
        # Top attacker IPs chart
        if attack_ips:
            story.append(Paragraph("<b>Most Active Attacker IPs</b>", body))
            ip_chart_b64 = create_attack_chart(dict(attack_ips.most_common(8)), 'Attack Frequency by IP', 'horizontal_bar')
            ip_chart_img = Image(io.BytesIO(base64.b64decode(ip_chart_b64)), width=5.5*inch, height=3.2*inch)
            story.append(ip_chart_img)
    
    # ═══════════════════════════════════════════════════════════════
    # DETAILED ATTACK BREAKDOWN - Professional styling
    # ═══════════════════════════════════════════════════════════════
    if include_details:
        story.append(PageBreak())
        story.append(Paragraph("[*] DETAILED ATTACK ANALYSIS", section_title))
        
        detail_intro = """Each attack type is analyzed below with specific details, 
        source IP information, and sample log entries for forensic investigation."""
        story.append(Paragraph(detail_intro, body))
        story.append(Spacer(1, 0.2*inch))
        
        for attack_type in selected_attacks:
            count = filtered_attacks.get(attack_type, 0)
            if count == 0:
                continue
            
            # Get severity and color from config
            attack_color, severity, priority = SEVERITY_CONFIG.get(attack_type, (SLATE, 'INFO', 1))
            
            # Professional attack header box
            attack_header_data = [[f'[!] {attack_type.upper()}']]
            attack_header_tbl = Table(attack_header_data, colWidths=[6.5*inch])
            
            # Set background color based on severity
            if severity == 'CRITICAL':
                header_bg = colors.HexColor('#ffe8e8')
                border_color = CRITICAL_RED
            elif severity == 'HIGH':
                header_bg = colors.HexColor('#fff3e0')
                border_color = HIGH_ORANGE
            elif severity == 'MEDIUM':
                header_bg = colors.HexColor('#fffde7')
                border_color = MEDIUM_YELLOW
            else:
                header_bg = colors.HexColor('#e3f2fd')
                border_color = LOW_BLUE
            
            attack_header_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), header_bg),
                ('TEXTCOLOR', (0, 0), (-1, -1), attack_color),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 13),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 15),
                ('TOPPADDING', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
                ('BOX', (0, 0), (-1, -1), 2, border_color),
            ]))
            story.append(attack_header_tbl)
            
            # Attack info table - professional
            attack_logs = [log for log in filtered_logs if log.get('attack_type') == attack_type]
            attack_specific_ips = Counter(log.get('ip', 'Unknown') for log in attack_logs)
            
            info_data = [
                ['Severity', 'Occurrences', 'Unique Source IPs', 'Priority'],
                [severity, f'{count:,}', str(len(attack_specific_ips)), '●' * priority]
            ]
            
            info_table = Table(info_data, colWidths=[1.5*inch, 1.5*inch, 1.8*inch, 1.5*inch])
            info_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 9),
                ('FONTSIZE', (0, 1), (-1, 1), 11),
                ('TEXTCOLOR', (0, 0), (-1, 0), SLATE),
                ('TEXTCOLOR', (0, 1), (0, 1), attack_color),
                ('TEXTCOLOR', (3, 1), (3, 1), attack_color),
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(info_table)
            
            # Top IPs for this attack - styled
            if attack_specific_ips:
                top_ips_text = ', '.join([f'<font color="#0a192f"><b>{ip}</b></font> ({cnt})' 
                                          for ip, cnt in attack_specific_ips.most_common(5)])
                story.append(Spacer(1, 0.05*inch))
                story.append(Paragraph(f"<b>Top Source IPs:</b> {top_ips_text}", small_text))
            
            # Sample log entries table - professional styling
            if attack_logs:
                story.append(Spacer(1, 0.1*inch))
                
                sample_entries = attack_logs[:5]
                entry_data = [['IP Address', 'Method', 'Endpoint', 'Status']]
                for entry in sample_entries:
                    endpoint = entry.get('endpoint', 'N/A')
                    if len(endpoint) > 45:
                        endpoint = endpoint[:42] + '...'
                    entry_data.append([
                        entry.get('ip', 'N/A')[:15],
                        entry.get('method', 'N/A'),
                        endpoint,
                        str(entry.get('status', 'N/A'))
                    ])
                
                entry_table = Table(entry_data, colWidths=[1.3*inch, 0.7*inch, 3.5*inch, 0.8*inch])
                entry_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), DARK_NAVY),
                    ('TEXTCOLOR', (0, 0), (-1, 0), CYBER_GREEN),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 8),
                    ('FONTNAME', (0, 1), (-1, -1), 'Courier'),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('ROWBACKGROUNDS', (0, 1), (-1, -1), [WHITE, colors.HexColor('#f8f9fa')]),
                    ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
                    ('LINEBELOW', (0, 0), (-1, 0), 1, CYBER_GREEN),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('LEFTPADDING', (0, 0), (-1, -1), 5),
                    ('ALIGN', (1, 0), (1, -1), 'CENTER'),
                    ('ALIGN', (3, 0), (3, -1), 'CENTER'),
                ]))
                story.append(entry_table)
            
            story.append(Spacer(1, 0.25*inch))
    
    # ═══════════════════════════════════════════════════════════════
    # RECOMMENDATIONS - Professional styling
    # ═══════════════════════════════════════════════════════════════
    story.append(PageBreak())
    story.append(Paragraph("[i] SECURITY RECOMMENDATIONS", section_title))
    
    rec_intro = """Based on the attack patterns identified, the following remediation 
    steps are recommended to strengthen your security posture:"""
    story.append(Paragraph(rec_intro, body))
    story.append(Spacer(1, 0.2*inch))
    
    recommendations = {
        'SQL Injection': [
            'Use parameterized queries and prepared statements',
            'Implement input validation and sanitization',
            'Deploy a Web Application Firewall (WAF)',
            'Regular security audits of database queries'
        ],
        'Remote Code Execution': [
            'CRITICAL: Immediately patch vulnerable applications',
            'Disable dangerous functions (eval, exec, system)',
            'Implement strict input validation',
            'Use application sandboxing'
        ],
        'LFI / Path Traversal': [
            'Validate and sanitize file paths',
            'Use whitelists for allowed files',
            'Implement proper access controls',
            'Disable directory listing'
        ],
        'XSS Attempt': [
            'Encode output data properly',
            'Use Content Security Policy (CSP) headers',
            'Validate and sanitize user input',
            'Use HTTPOnly and Secure flags for cookies'
        ],
        'SSH Brute Force': [
            'Implement fail2ban or similar tools',
            'Use key-based authentication only',
            'Change default SSH port',
            'Limit SSH access by IP whitelist'
        ],
        'Auth Brute Force': [
            'Implement rate limiting',
            'Use CAPTCHA after failed attempts',
            'Enable account lockout policies',
            'Implement MFA/2FA'
        ],
        'FTP Brute Force': [
            'Disable FTP, use SFTP instead',
            'Implement IP-based access controls',
            'Enable account lockout after failed attempts',
            'Use strong authentication mechanisms'
        ],
        'SMTP Attack': [
            'Implement DMARC, DKIM, and SPF',
            'Use authenticated SMTP relay',
            'Rate limit outgoing emails',
            'Monitor for unusual email patterns'
        ],
        'Sensitive File Scan': [
            'Remove sensitive files from web root',
            'Configure proper file permissions',
            'Block access to sensitive paths in web server',
            'Monitor for unauthorized access attempts'
        ],
        'Database Attack': [
            'Restrict database network access',
            'Use least privilege principle for DB users',
            'Enable query logging and monitoring',
            'Regular patching of database software'
        ],
        'WAF Block': [
            'Review WAF rules for accuracy',
            'Analyze blocked patterns for false positives',
            'Update WAF signatures regularly',
            'Implement rate limiting'
        ],
        'Automated Scanner': [
            'Implement rate limiting on all endpoints',
            'Use CAPTCHA for sensitive operations',
            'Deploy honeypot pages',
            'Monitor and block scanner user agents'
        ],
        'Probe / Scan': [
            'Close unnecessary ports',
            'Implement network segmentation',
            'Deploy intrusion detection systems',
            'Regular vulnerability assessments'
        ],
    }
    
    rec_count = 0
    for attack_type in selected_attacks:
        if attack_type in recommendations:
            rec_count += 1
            
            # Get attack color
            attack_color, severity, _ = SEVERITY_CONFIG.get(attack_type, (SLATE, 'INFO', 1))
            
            # Styled recommendation header
            rec_header_data = [[f'>> {attack_type}']]
            rec_header_tbl = Table(rec_header_data, colWidths=[6.5*inch])
            rec_header_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), DARK_NAVY),
                ('TEXTCOLOR', (0, 0), (-1, -1), CYBER_GREEN),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 11),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 12),
                ('TOPPADDING', (0, 0), (-1, -1), 8),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ]))
            story.append(rec_header_tbl)
            
            # Recommendation items as styled list
            rec_items = recommendations[attack_type]
            rec_data = [[f'✓ {rec}'] for rec in rec_items]
            rec_tbl = Table(rec_data, colWidths=[6.5*inch])
            rec_tbl.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#f8f9fa')),
                ('TEXTCOLOR', (0, 0), (-1, -1), DARK_NAVY),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('LEFTPADDING', (0, 0), (-1, -1), 20),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('BOX', (0, 0), (-1, -1), 1, colors.HexColor('#dee2e6')),
            ]))
            story.append(rec_tbl)
            story.append(Spacer(1, 0.15*inch))
    
    # If no specific recommendations, add general ones
    if rec_count == 0:
        story.append(Paragraph("<b>General Security Recommendations:</b>", body))
        general_recs = [
            '• Keep all systems and software updated',
            '• Implement defense-in-depth strategies',
            '• Regular security audits and penetration testing',
            '• Employee security awareness training',
            '• Implement comprehensive logging and monitoring'
        ]
        for rec in general_recs:
            story.append(Paragraph(rec, body))
    
    # ═══════════════════════════════════════════════════════════════
    # PROFESSIONAL FOOTER
    # ═══════════════════════════════════════════════════════════════
    story.append(Spacer(1, 0.5*inch))
    
    # Footer line
    footer_line = Table([['']], colWidths=[6.5*inch])
    footer_line.setStyle(TableStyle([
        ('LINEABOVE', (0, 0), (-1, -1), 2, colors.HexColor('#e9ecef')),
    ]))
    story.append(footer_line)
    story.append(Spacer(1, 0.1*inch))
    
    footer_data = [
        ['DATASMITH PRO', 'Attack Analysis Report', f'ID: ATK-{report_id}'],
        ['Security Intelligence Platform', report_date, 'CONFIDENTIAL']
    ]
    footer_tbl = Table(footer_data, colWidths=[2.2*inch, 2.2*inch, 2.2*inch])
    footer_tbl.setStyle(TableStyle([
        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
        ('ALIGN', (1, 0), (1, -1), 'CENTER'),
        ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTNAME', (0, 1), (-1, 1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('TEXTCOLOR', (0, 0), (-1, -1), SLATE),
        ('TEXTCOLOR', (2, 1), (2, 1), CRITICAL_RED),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(footer_tbl)
    
    story.append(Spacer(1, 0.1*inch))
    disclaimer = """<para alignment="center"><font color="#8892b0" size="7">
    This report contains confidential security information. Unauthorized distribution is prohibited.
    © 2025 DataSmith Pro. All rights reserved.
    </font></para>"""
    story.append(Paragraph(disclaimer, body))
    
    # Build PDF
    doc.build(story)
    buffer.seek(0)
    
    # Generate filename based on attacks
    attack_names = '_'.join([a.replace(' ', '').replace('/', '')[:10] for a in selected_attacks[:3]])
    filename = f'DataSmith_Attack_Report_{attack_names}_{report_id}.pdf'
    
    return send_file(
        buffer,
        mimetype='application/pdf',
        as_attachment=True,
        download_name=filename
    )


@app.route('/available-attacks', methods=['GET'])
def get_available_attacks():
    """Get list of all available attack types for filtering"""
    attack_list = [
        {'name': 'SQL Injection', 'severity': 'CRITICAL', 'color': '#ff4757'},
        {'name': 'Remote Code Execution', 'severity': 'CRITICAL', 'color': '#ff4757'},
        {'name': 'LFI / Path Traversal', 'severity': 'CRITICAL', 'color': '#ff4757'},
        {'name': 'XSS Attempt', 'severity': 'HIGH', 'color': '#ffa502'},
        {'name': 'Database Attack', 'severity': 'HIGH', 'color': '#ffa502'},
        {'name': 'WAF Block', 'severity': 'HIGH', 'color': '#ffa502'},
        {'name': 'Cloud Security Event', 'severity': 'HIGH', 'color': '#ffa502'},
        {'name': 'SSH Brute Force', 'severity': 'MEDIUM', 'color': '#ffdd59'},
        {'name': 'Auth Brute Force', 'severity': 'MEDIUM', 'color': '#ffdd59'},
        {'name': 'FTP Brute Force', 'severity': 'MEDIUM', 'color': '#ffdd59'},
        {'name': 'SMTP Attack', 'severity': 'MEDIUM', 'color': '#ffdd59'},
        {'name': 'Windows Auth Failure', 'severity': 'MEDIUM', 'color': '#ffdd59'},
        {'name': 'VPN Auth Failure', 'severity': 'MEDIUM', 'color': '#ffdd59'},
        {'name': 'Sensitive File Scan', 'severity': 'LOW', 'color': '#70a1ff'},
        {'name': 'Automated Scanner', 'severity': 'LOW', 'color': '#70a1ff'},
        {'name': 'Probe / Scan', 'severity': 'LOW', 'color': '#70a1ff'},
        {'name': 'Suspicious DNS Query', 'severity': 'LOW', 'color': '#70a1ff'},
        {'name': 'Blocked Connection', 'severity': 'INFO', 'color': '#8892b0'},
        {'name': 'Server Error', 'severity': 'INFO', 'color': '#8892b0'},
        {'name': 'Container Error', 'severity': 'INFO', 'color': '#8892b0'},
    ]
    return jsonify(attack_list)


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


# ================== LIVE MONITORING ENDPOINTS ==================

@app.route('/live/start', methods=['POST'])
def start_live_monitoring():
    """Start watching a log file for real-time updates"""
    try:
        data = request.json
        filepath = data.get('filepath')
        
        if not filepath:
            return jsonify({'error': 'No filepath provided'}), 400
        
        # Resolve absolute path
        if not os.path.isabs(filepath):
            filepath = os.path.abspath(filepath)
        
        if not os.path.exists(filepath):
            return jsonify({'error': f'File not found: {filepath}'}), 404
        
        monitor.start_watching(filepath)
        
        return jsonify({
            'success': True,
            'message': f'Started monitoring: {filepath}',
            'filepath': filepath
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/live/stop', methods=['POST'])
def stop_live_monitoring():
    """Stop the current live monitoring session"""
    try:
        monitor.stop_watching()
        return jsonify({'success': True, 'message': 'Monitoring stopped'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/live/status', methods=['GET'])
def get_live_status():
    """Get current live monitoring status and stats"""
    try:
        return jsonify({
            'watching': monitor.is_watching(),
            'filepath': monitor.get_watch_path(),
            'stats': monitor.get_stats() if monitor.is_watching() else None
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/live/stats', methods=['GET'])
def get_live_stats():
    """Get current live statistics"""
    try:
        if not monitor.is_watching():
            return jsonify({'error': 'Not currently monitoring any file'}), 400
        
        return jsonify(monitor.get_stats())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ================== SOCKET.IO EVENTS ==================

@socketio.on('connect', namespace='/live')
def handle_connect():
    """Handle client connection"""
    print(f'Client connected to live feed')
    if monitor.is_watching():
        emit('stats_update', monitor.get_stats())


@socketio.on('disconnect', namespace='/live')
def handle_disconnect():
    """Handle client disconnection"""
    print(f'Client disconnected from live feed')


@socketio.on('request_stats', namespace='/live')
def handle_request_stats():
    """Handle client requesting current stats"""
    if monitor.is_watching():
        emit('stats_update', monitor.get_stats())


def get_local_ip():
    """Get the local IP address of this machine on the network"""
    import socket
    try:
        # Connect to an external address to determine local IP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"


if __name__ == '__main__':
    local_ip = get_local_ip()
    port = 5000
    
    print("\n" + "="*60)
    print("       DATASMITH ENGINE - Security Log Analyzer")
    print("="*60)
    print("\n[+] Server Starting...")
    print(f"[+] Local Access:   http://localhost:{port}")
    print(f"[+] Network Access: http://{local_ip}:{port}")
    print("\n[*] Share the Network URL with devices on your WiFi!")
    print("="*60)
    print("\n[API Endpoints]")
    print("   POST /live/start  - Start monitoring a log file")
    print("   POST /live/stop   - Stop monitoring")
    print("   GET  /live/status - Get monitoring status")
    print("   GET  /live/stats  - Get current statistics")
    print("="*60 + "\n")
    
    # Run on all network interfaces (0.0.0.0) to allow WiFi access
    socketio.run(app, debug=True, host='0.0.0.0', port=port)

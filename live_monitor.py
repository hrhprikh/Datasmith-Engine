"""
Live Log Monitor - Real-time log file monitoring with WebSocket
Watches a log file for changes and pushes updates to connected clients
"""

import os
import re
import time
import threading
from collections import Counter
from datetime import datetime
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# ---------------- REGEX PATTERNS (same as app.py) ----------------

WEB_PATTERN = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+.*?"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})'
)

SSH_PATTERN = re.compile(
    r'.*sshd.*(Failed password|Invalid user|Connection closed|Accepted password).*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

FTP_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+\s+\S+)?.*?(?:ftp|vsftpd|proftpd).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<action>LOGIN|FAIL|UPLOAD|DOWNLOAD|CONNECT)',
    re.IGNORECASE
)

SMTP_PATTERN = re.compile(
    r'.*?(?:postfix|sendmail|smtp|dovecot).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<action>reject|relay denied|authentication failed|login failed|disconnect)',
    re.IGNORECASE
)

FIREWALL_PATTERN = re.compile(
    r'.*?(?:DENY|DROP|REJECT|BLOCK|BLOCKED).*?(?:SRC=|src:|from\s+)(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?(?:DST=|dst:|to\s+)(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?(?:DPT=|dport:|port\s+)?(?P<port>\d+)?',
    re.IGNORECASE
)

# ---------------- ATTACK PATTERNS ----------------

SQLI_PATTERNS = ("union", "select", "insert", "update", "delete", "drop", "sleep(", "benchmark", "information_schema", "' or '1'='1", "\" or \"1\"=\"1", "or 1=1")
XSS_PATTERNS = ("<script", "%3cscript", "javascript:", "onerror=", "onload=", "<img")
RCE_PATTERNS = ("cmd=", "exec", "system(", "shell_exec", "powershell", "bash", "sh;", "|sh", "wget", "curl")
LFI_PATTERNS = ("../", "..%2f", "%2e%2e%2f", "etc/passwd", "boot.ini")
SENSITIVE_FILES = ("/admin", "/wp-admin", "/phpmyadmin", "/config.php", "/.env", "/shell.php", "/backup", "/db.sql")

# Attack severity for notifications
CRITICAL_ATTACKS = {'SQL Injection', 'Remote Code Execution', 'LFI / Path Traversal'}
HIGH_ATTACKS = {'XSS Attempt', 'Database Attack', 'WAF Block', 'Cloud Security Event'}

def classify_attack(endpoint, status, log_type="web"):
    """Classify the type of attack based on endpoint and status"""
    ep = endpoint.lower() if endpoint else ""
    
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
    if status in (401, 403):
        return "Auth Brute Force"
    if status >= 500:
        return "Server Error"
    if status == 404 and any(x in ep for x in ['.php', '.asp', '.jsp', '.cgi', 'admin', 'backup', 'config']):
        return "Probe / Scan"
    
    return "Normal"


class LiveStats:
    """Thread-safe statistics container for live monitoring"""
    
    def __init__(self):
        self.lock = threading.Lock()
        self.reset()
    
    def reset(self):
        with self.lock:
            self.total = 0
            self.parsed = 0
            self.threats = 0
            self.attack_types = Counter()
            self.ip_activity = Counter()
            self.methods = Counter()
            self.log_types = Counter()
            self.recent_entries = []  # Keep last 100 entries
            self.critical_alerts = []  # Critical alerts for notifications
    
    def add_entry(self, entry):
        """Add a parsed log entry and update stats"""
        with self.lock:
            self.total += 1
            self.parsed += 1
            
            # Update counters
            if entry.get('ip') and entry['ip'] != 'Unknown':
                self.ip_activity[entry['ip']] += 1
            if entry.get('method'):
                self.methods[entry['method']] += 1
            if entry.get('log_type'):
                self.log_types[entry['log_type']] += 1
            
            attack_type = entry.get('attack_type', 'Normal')
            if attack_type != 'Normal':
                self.threats += 1
                self.attack_types[attack_type] += 1
                
                # Check if critical
                if attack_type in CRITICAL_ATTACKS:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'CRITICAL',
                        'type': attack_type,
                        'ip': entry.get('ip', 'Unknown'),
                        'endpoint': entry.get('endpoint', ''),
                        'message': f"🚨 CRITICAL: {attack_type} detected from {entry.get('ip', 'Unknown')}"
                    }
                    self.critical_alerts.append(alert)
                    # Keep only last 50 alerts
                    self.critical_alerts = self.critical_alerts[-50:]
                    return alert  # Return alert for immediate notification
                
                elif attack_type in HIGH_ATTACKS:
                    alert = {
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'HIGH',
                        'type': attack_type,
                        'ip': entry.get('ip', 'Unknown'),
                        'endpoint': entry.get('endpoint', ''),
                        'message': f"⚠️ HIGH: {attack_type} detected from {entry.get('ip', 'Unknown')}"
                    }
                    self.critical_alerts.append(alert)
                    self.critical_alerts = self.critical_alerts[-50:]
                    return alert
            
            # Add to recent entries (keep attack entries only for table)
            if attack_type != 'Normal':
                self.recent_entries.append(entry)
                self.recent_entries = self.recent_entries[-100:]  # Keep last 100
            
            return None
    
    def increment_unparsed(self):
        with self.lock:
            self.total += 1
    
    def get_stats(self):
        """Get current statistics snapshot"""
        with self.lock:
            return {
                'metrics': {
                    'total': self.total,
                    'parsed': self.parsed,
                    'unparsed': self.total - self.parsed,
                    'unique_ips': len(self.ip_activity),
                    'threats': self.threats
                },
                'attack_types': dict(self.attack_types.most_common(10)),
                'top_ips': dict(self.ip_activity.most_common(10)),
                'methods': dict(self.methods.most_common()),
                'log_types': dict(self.log_types.most_common()),
                'recent_entries': list(self.recent_entries[-50:]),  # Last 50
                'alerts': list(self.critical_alerts[-20:])  # Last 20 alerts
            }
    
    def get_new_alerts(self, since_count):
        """Get alerts newer than the given count"""
        with self.lock:
            return self.critical_alerts[since_count:]


class LogFileHandler(FileSystemEventHandler):
    """Handles file system events for the watched log file"""
    
    def __init__(self, filepath, stats, socketio, namespace='/live'):
        self.filepath = filepath
        self.stats = stats
        self.socketio = socketio
        self.namespace = namespace
        self.last_position = 0
        self.last_inode = None
        
        # Initialize position to end of file
        if os.path.exists(filepath):
            self.last_position = os.path.getsize(filepath)
            try:
                self.last_inode = os.stat(filepath).st_ino
            except:
                self.last_inode = None
    
    def on_modified(self, event):
        """Called when the watched file is modified"""
        if event.src_path.replace('\\', '/') == self.filepath.replace('\\', '/'):
            self.process_new_lines()
    
    def on_created(self, event):
        """Handle log rotation - file recreated"""
        if event.src_path.replace('\\', '/') == self.filepath.replace('\\', '/'):
            self.last_position = 0
            self.process_new_lines()
    
    def process_new_lines(self):
        """Read and process new lines from the log file"""
        try:
            # Check for log rotation (inode change)
            try:
                current_inode = os.stat(self.filepath).st_ino
                if self.last_inode and current_inode != self.last_inode:
                    self.last_position = 0
                self.last_inode = current_inode
            except:
                pass
            
            current_size = os.path.getsize(self.filepath)
            
            # File was truncated (log rotation)
            if current_size < self.last_position:
                self.last_position = 0
            
            if current_size > self.last_position:
                with open(self.filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    f.seek(self.last_position)
                    new_lines = f.readlines()
                    self.last_position = f.tell()
                
                alerts_to_send = []
                entries_to_send = []
                
                for line in new_lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    entry = self.parse_line(line)
                    if entry:
                        alert = self.stats.add_entry(entry)
                        if alert:
                            alerts_to_send.append(alert)
                        if entry.get('attack_type') != 'Normal':
                            entries_to_send.append(entry)
                    else:
                        self.stats.increment_unparsed()
                
                # Emit updates via WebSocket
                if alerts_to_send or entries_to_send:
                    self.socketio.emit('stats_update', self.stats.get_stats(), namespace=self.namespace)
                    
                    # Send critical alerts immediately
                    for alert in alerts_to_send:
                        self.socketio.emit('critical_alert', alert, namespace=self.namespace)
                
        except Exception as e:
            print(f"Error processing log file: {e}")
    
    def parse_line(self, line):
        """Parse a single log line and return entry dict"""
        
        # Web Access Log
        if line and (line[0].isdigit() or line.startswith('"')):
            m = WEB_PATTERN.match(line)
            if m:
                data = m.groupdict()
                ip = data["ip"]
                method = data["method"]
                endpoint = data["endpoint"]
                status = int(data["status"])
                attack = classify_attack(endpoint, status)
                
                return {
                    'ip': ip,
                    'method': method,
                    'endpoint': endpoint[:100],  # Truncate long endpoints
                    'status': str(status),
                    'attack_type': attack,
                    'log_type': 'Web Access Log',
                    'timestamp': datetime.now().isoformat()
                }
        
        # SSH Log
        if 'ssh' in line.lower():
            m = SSH_PATTERN.search(line)
            if m:
                ip = m.group("ip")
                action = m.group(1) if m.lastindex >= 1 else "Unknown"
                attack_type = "Normal" if 'Accepted' in line else "SSH Brute Force"
                
                return {
                    'ip': ip,
                    'method': 'SSH',
                    'endpoint': action,
                    'status': 'Failed' if 'Failed' in action or 'Invalid' in action else 'Success',
                    'attack_type': attack_type,
                    'log_type': 'SSH Log',
                    'timestamp': datetime.now().isoformat()
                }
        
        # FTP Log
        if any(kw in line.lower() for kw in ['ftp', 'vsftpd', 'proftpd']):
            m = FTP_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip", "Unknown")
                action = data.get("action", "Unknown")
                attack_type = "FTP Brute Force" if 'FAIL' in action.upper() else "Normal"
                
                return {
                    'ip': ip,
                    'method': 'FTP',
                    'endpoint': action,
                    'status': 'Failed' if 'FAIL' in action.upper() else 'Success',
                    'attack_type': attack_type,
                    'log_type': 'FTP Log',
                    'timestamp': datetime.now().isoformat()
                }
        
        # SMTP Log
        if any(kw in line.lower() for kw in ['postfix', 'sendmail', 'smtp', 'dovecot']):
            m = SMTP_PATTERN.search(line)
            if m:
                data = m.groupdict()
                ip = data.get("ip", "Unknown")
                action = data.get("action", "Unknown")
                attack_type = "SMTP Attack" if any(x in action.lower() for x in ['reject', 'denied', 'failed']) else "Normal"
                
                return {
                    'ip': ip,
                    'method': 'SMTP',
                    'endpoint': action,
                    'status': 'Blocked' if attack_type != "Normal" else 'OK',
                    'attack_type': attack_type,
                    'log_type': 'SMTP Log',
                    'timestamp': datetime.now().isoformat()
                }
        
        # Firewall Log
        if any(kw in line.upper() for kw in ['DENY', 'DROP', 'REJECT', 'BLOCK']):
            m = FIREWALL_PATTERN.search(line)
            if m:
                data = m.groupdict()
                src_ip = data.get("src_ip", "Unknown")
                dst_ip = data.get("dst_ip", "Unknown")
                port = data.get("port", "N/A")
                
                return {
                    'ip': src_ip,
                    'method': 'FIREWALL',
                    'endpoint': f'→ {dst_ip}:{port}',
                    'status': 'Blocked',
                    'attack_type': 'Blocked Connection',
                    'log_type': 'Firewall Log',
                    'timestamp': datetime.now().isoformat()
                }
        
        return None


class LiveMonitor:
    """Main class to manage live log monitoring"""
    
    def __init__(self, socketio):
        self.socketio = socketio
        self.observer = None
        self.handler = None
        self.stats = LiveStats()
        self.watching = False
        self.watch_path = None
    
    def start_watching(self, filepath):
        """Start watching a log file"""
        if self.watching:
            self.stop_watching()
        
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"Log file not found: {filepath}")
        
        self.watch_path = filepath
        self.stats.reset()
        
        # Create handler and observer
        self.handler = LogFileHandler(filepath, self.stats, self.socketio)
        self.observer = Observer()
        
        # Watch the directory containing the file
        watch_dir = os.path.dirname(filepath) or '.'
        self.observer.schedule(self.handler, watch_dir, recursive=False)
        self.observer.start()
        self.watching = True
        
        print(f"📡 Started watching: {filepath}")
        return True
    
    def stop_watching(self):
        """Stop watching the current file"""
        if self.observer:
            self.observer.stop()
            self.observer.join(timeout=2)
            self.observer = None
        
        self.handler = None
        self.watching = False
        self.watch_path = None
        print("⏹️ Stopped watching")
    
    def get_stats(self):
        """Get current statistics"""
        return self.stats.get_stats()
    
    def is_watching(self):
        """Check if currently watching a file"""
        return self.watching
    
    def get_watch_path(self):
        """Get the currently watched file path"""
        return self.watch_path


# Global monitor instance (will be initialized in app.py)
live_monitor = None

def init_live_monitor(socketio):
    """Initialize the global live monitor"""
    global live_monitor
    live_monitor = LiveMonitor(socketio)
    return live_monitor

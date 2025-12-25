import random
import datetime
import os

print("Generating 10 lakh (1,000,000) sample web access log entries...")

# Sample data pools
ips = [f"{random.randint(1,255)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(0,255)}" for _ in range(500)]

# Add some "attacker" IPs that will appear frequently
attacker_ips = [
    "185.220.101.45", "192.168.1.100", "45.33.32.156", 
    "103.21.244.15", "91.240.118.172", "185.56.80.65",
    "194.26.29.120", "45.155.205.233", "89.248.167.131"
]
ips.extend(attacker_ips * 50)  # Make attackers appear more often

methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
method_weights = [70, 20, 3, 2, 3, 2]

endpoints = [
    "/", "/index.html", "/home", "/about", "/contact",
    "/api/users", "/api/login", "/api/data", "/api/products", "/api/orders",
    "/admin", "/admin/login", "/admin/dashboard", "/admin/users",
    "/wp-admin", "/wp-login.php", "/phpmyadmin", "/administrator",
    "/login", "/register", "/logout", "/profile", "/settings",
    "/images/logo.png", "/css/style.css", "/js/app.js", "/favicon.ico",
    "/search", "/products", "/cart", "/checkout", "/payment",
    "/.env", "/config.php", "/backup.sql", "/.git/config",
    "/api/v1/auth", "/api/v2/users", "/graphql", "/health",
]

# Suspicious endpoints (for attack simulation)
suspicious_endpoints = [
    "/wp-admin/admin-ajax.php", "/phpmyadmin/index.php",
    "/../../../etc/passwd", "/shell.php", "/cmd.exe",
    "/admin/config.php", "/.env", "/.git/HEAD",
    "/api/login?user=admin&pass=admin", "/xmlrpc.php",
]
endpoints.extend(suspicious_endpoints * 20)

status_codes = [200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 500, 502, 503]
status_weights = [60, 5, 2, 3, 3, 5, 3, 5, 4, 7, 1, 1, 1]

user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)",
    "sqlmap/1.7.2#stable (https://sqlmap.org)",
    "Nikto/2.1.6",
]

referrers = [
    "-", "https://www.google.com/", "https://www.bing.com/",
    "https://www.facebook.com/", "https://twitter.com/",
    "https://example.com/", "https://example.com/products",
]

# Generate logs
start_date = datetime.datetime(2025, 12, 1, 0, 0, 0)
output_file = "sample_web_logs.log"

total_rows = 1000000
batch_size = 50000

with open(output_file, 'w', encoding='utf-8') as f:
    for i in range(total_rows):
        # Progress indicator
        if i % 100000 == 0:
            print(f"Generated {i:,} / {total_rows:,} rows...")
        
        # Random timestamp within December 2025
        random_seconds = random.randint(0, 25 * 24 * 3600)  # 25 days
        timestamp = start_date + datetime.timedelta(seconds=random_seconds)
        formatted_time = timestamp.strftime("%d/%b/%Y:%H:%M:%S +0000")
        
        ip = random.choice(ips)
        method = random.choices(methods, weights=method_weights)[0]
        endpoint = random.choice(endpoints)
        status = random.choices(status_codes, weights=status_weights)[0]
        size = random.randint(100, 50000)
        referrer = random.choice(referrers)
        user_agent = random.choice(user_agents)
        
        # Apache/Nginx combined log format
        log_line = f'{ip} - - [{formatted_time}] "{method} {endpoint} HTTP/1.1" {status} {size} "{referrer}" "{user_agent}"\n'
        f.write(log_line)

print(f"\n✅ Done! Generated {total_rows:,} log entries")
print(f"📁 File saved: {output_file}")
print(f"📊 File size: {os.path.getsize(output_file) / (1024*1024):.2f} MB")

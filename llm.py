w# # ==========================================
# # DATASMITH PRO: WEB EDITION (RTX 4060 8GB) - OPTIMIZED
# # Run: streamlit run datasmith_app.py
# # ==========================================

# import streamlit as st
# import os, sys, re, json, torch, datetime
# from collections import Counter
# import matplotlib.pyplot as plt
# import pandas as pd
# from transformers import AutoTokenizer, AutoModelForCausalLM, BitsAndBytesConfig

# # -------------------------
# # 0) PAGE CONFIG + STYLE
# # -------------------------
# st.set_page_config(
#     page_title="DataSmith Pro (8GB Edition)",
#     page_icon="🛡️",
#     layout="wide",
#     initial_sidebar_state="expanded"
# )

# st.markdown("""
# <style>
#     .reportview-container { background: #0e1117; }
#     .main .block-container { padding-top: 2rem; }
#     h1 { color: #00ff41; font-family: 'Courier New'; }
#     h2, h3 { color: #e0e0e0; font-family: 'Courier New'; }
#     .stAlert { background-color: #262730; border: 1px solid #4e4e4e; }
#     div[data-testid="stMetricValue"] { font-family: 'Courier New'; color: #00ff41; }
# </style>
# """, unsafe_allow_html=True)

# # -------------------------
# # 1) DO NOT AUTO-INSTALL IN APP (VERY SLOW)
# # -------------------------
# # Put these in requirements.txt instead:
# # streamlit torch transformers bitsandbytes accelerate fpdf matplotlib pandas

# from fpdf import FPDF

# # -------------------------
# # 2) MODEL LOADING (CACHED)
# # -------------------------
# @st.cache_resource
# def load_granite_model():
#     MODEL_ID = "ibm-granite/granite-3.1-8b-instruct"

#     # RTX 4060 often benefits from fp16 more reliably than bf16
#     compute_dtype = torch.float16
#     if torch.cuda.is_available():
#         # Some builds support bf16; keep it safe
#         try:
#             if torch.cuda.is_bf16_supported():
#                 compute_dtype = torch.bfloat16
#         except Exception:
#             pass

#     bnb_config = BitsAndBytesConfig(
#         load_in_4bit=True,
#         bnb_4bit_compute_dtype=compute_dtype,
#         bnb_4bit_quant_type="nf4",
#         bnb_4bit_use_double_quant=True,
#     )

#     tokenizer = AutoTokenizer.from_pretrained(MODEL_ID, use_fast=True)

#     # Flash Attention may not exist in all environments; keep optional
#     model_kwargs = dict(
#         quantization_config=bnb_config,
#         device_map="auto",
#     )
#     try:
#         model_kwargs["attn_implementation"] = "flash_attention_2"
#     except Exception:
#         pass

#     model = AutoModelForCausalLM.from_pretrained(MODEL_ID, **model_kwargs)
#     model.eval()
#     return tokenizer, model

# # -------------------------
# # 3) FAST PARSING + ATTACK RULES
# # -------------------------
# WEB_PATTERN = re.compile(
#     r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+.*?"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})\b'
# )

# SSH_PATTERN = re.compile(
#     r'^(?P<timestamp>.{15})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<message>.*)$'
# )

# # cheap keyword sets (lowercased endpoint)
# SENSITIVE = ("/.env", "/wp-admin", "/phpmyadmin", "/config.php", "/shell.php", "/cgi-bin", "/admin")
# TRAVERSAL = ("../", "..%2f", "%2e%2e%2f", "etc/passwd", "passwd")
# SQLI = ("select", "union", "sleep(", "or%201=1", "'or'1'='1", "information_schema")
# RCE = ("cmd=", "powershell", "bash", "sh;", "eval(", "base64", "wget", "curl", ";rm", "|sh")

# def classify_web(endpoint: str, status: int) -> str:
#     ep = (endpoint or "").lower()

#     if any(x in ep for x in TRAVERSAL):
#         return "LFI/Path Traversal"
#     if any(x in ep for x in SENSITIVE):
#         return "Sensitive File/Panel Scan"
#     if any(x in ep for x in SQLI):
#         return "SQL Injection"
#     if any(x in ep for x in RCE):
#         return "RCE Attempt"
#     if status in (401, 403):
#         return "Auth Bypass/Unauthorized Access"
#     if status == 429:
#         return "Rate Limit/Abuse"
#     return "Normal"

# def analyze_web_line(line: str):
#     m = WEB_PATTERN.match(line)
#     if not m:
#         return None, None
#     d = m.groupdict()
#     status = int(d.get("status", "0"))
#     attack = classify_web(d.get("endpoint", ""), status)
#     return d, attack

# def analyze_ssh_line(line: str):
#     m = SSH_PATTERN.match(line)
#     if not m:
#         return None, None
#     d = m.groupdict()
#     msg = (d.get("message") or "").lower()

#     # try to extract IP cheaply (avoid heavy regex)
#     ip = "Unknown/Local"
#     # common sshd "from x.x.x.x"
#     idx = msg.rfind(" from ")
#     if idx != -1:
#         cand = msg[idx + 6:].split()[0]
#         if re.match(r'^\d+\.\d+\.\d+\.\d+$', cand):
#             ip = cand

#     attack = "Normal"
#     if "failed password" in msg:
#         attack = "SSH Brute Force"
#     elif "invalid user" in msg:
#         attack = "SSH Invalid User"

#     d2 = {
#         "ip": ip,
#         "method": "SSH",
#         "endpoint": f"SSH: {d.get('message','')[:60]}",
#         "status": "Auth"
#     }
#     return d2, attack

# def detect_line_type_and_parse(line: str):
#     # quick pre-check: web logs usually start with digit+dot
#     if line and line[0].isdigit():
#         d, a = analyze_web_line(line)
#         if d:
#             return d, a, "Web Access Log"
#     # else try ssh
#     d, a = analyze_ssh_line(line)
#     if d:
#         return d, a, "SSH System Log"
#     return None, None, None

# # -------------------------
# # 4) PDF
# # -------------------------
# class PDFReport(FPDF):
#     def header(self):
#         self.set_font('Arial', 'B', 16)
#         self.cell(0, 10, 'DataSmith Security Audit Report', 0, 1, 'C')
#         self.set_font('Arial', 'I', 10)
#         self.cell(0, 8, f'Generated: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}', 0, 1, 'C')
#         self.ln(4)

#     def chapter_title(self, title):
#         self.set_font('Arial', 'B', 12)
#         self.set_fill_color(200, 220, 255)
#         self.cell(0, 8, title, 0, 1, 'L', 1)
#         self.ln(2)

#     def chapter_body(self, body):
#         self.set_font('Arial', '', 10)
#         self.multi_cell(0, 5, body)
#         self.ln(1)

# # -------------------------
# # 5) UI
# # -------------------------
# st.sidebar.title("🛠️ Configuration")
# st.sidebar.markdown("Running on: **RTX 4060 (8GB)**")
# ai_enabled = st.sidebar.checkbox("Enable Granite AI Analysis", value=True)
# ai_sample_size = st.sidebar.slider("AI Sample Size", 5, 50, 10)

# st.title("🛡️ DataSmith Pro")
# st.markdown("### Intelligent Log Forensics & Reporting")

# uploaded_file = st.file_uploader("Upload Log File (Apache, Nginx, SSH, Syslog)", type=["log", "txt"])

# if uploaded_file is None:
#     st.info("👆 Please upload a log file to begin analysis.")
#     st.stop()

# # -------------------------
# # 6) STREAMING PARSE (FAST + LOW RAM)
# # -------------------------
# st.write("---")
# status_text = st.empty()
# progress_bar = st.progress(0)

# stats = {"total": 0, "parsed": 0, "attack_types": Counter()}
# ip_activity = Counter()
# suspicious_samples = []

# # Stream bytes -> text lines without loading entire file
# status_text.text("Parsing logs...")

# # For progress: we can’t know total lines without reading once.
# # We’ll show progress as “processed lines” instead of percentage.
# processed_metric = st.empty()

# # decode streaming
# for i, raw in enumerate(uploaded_file.getvalue().splitlines()):
#     # raw is bytes chunks already split by newline; fast enough + low memory
#     try:
#         line = raw.decode("utf-8", errors="ignore").strip()
#     except Exception:
#         continue

#     if not line:
#         continue

#     stats["total"] += 1

#     data, attack_type, log_type = detect_line_type_and_parse(line)
#     if data:
#         stats["parsed"] += 1
#         ip_activity[data.get("ip", "Unknown")] += 1

#         if attack_type != "Normal":
#             stats["attack_types"][attack_type] += 1
#             data["_log_type"] = log_type
#             if len(suspicious_samples) < ai_sample_size:
#                 suspicious_samples.append(data)

#     # Cheap UI updates every 200 lines
#     if (i + 1) % 200 == 0:
#         processed_metric.info(f"Processed lines: {stats['total']} | Parsed: {stats['parsed']}")
#         # progress bar as "pulse" (not real %)
#         progress_bar.progress(min(((i + 1) % 2000) / 2000, 1.0))

# progress_bar.progress(1.0)
# status_text.text("Parsing Complete.")

# # -------------------------
# # 7) DASHBOARD
# # -------------------------
# c1, c2, c3, c4 = st.columns(4)
# c1.metric("Total Logs", stats["total"])
# c2.metric("Parsed Successfully", stats["parsed"])
# c3.metric("Unique IPs", len(ip_activity))
# c4.metric("Threats Detected", sum(stats["attack_types"].values()), delta_color="inverse")

# st.subheader("📊 Attack Distribution")

# chart_path = "temp_chart.png"
# if stats["attack_types"]:
#     chart_data = (
#         pd.DataFrame(stats["attack_types"].items(), columns=["Attack Type", "Count"])
#         .sort_values("Count", ascending=False)
#     )
#     fig, ax = plt.subplots(figsize=(10, 4))
#     ax.barh(chart_data["Attack Type"], chart_data["Count"])
#     ax.invert_yaxis()
#     ax.set_title("Detected Attack Distribution")
#     ax.set_xlabel("Count")
#     st.pyplot(fig, clear_figure=True)

#     fig.savefig(chart_path, bbox_inches="tight")
# else:
#     st.info("No threats detected to graph.")

# # -------------------------
# # 8) AI ANALYSIS (FASTER + SAFER JSON)
# # -------------------------
# ai_results = []
# if ai_enabled and suspicious_samples:
#     st.subheader("🧠 Granite AI Analysis")
#     st.write(f"Analyzing {len(suspicious_samples)} suspicious entries...")

#     try:
#         with st.spinner("Loading Granite (runs once)..."):
#             tokenizer, model = load_granite_model()

#         SYSTEM_PROMPT = (
#             "You are a security classifier.\n"
#             "Return ONLY JSON with keys: classification, severity, reason, recommended_action.\n"
#             "classification: Normal|Suspicious|Malicious\n"
#             "severity: Low|Medium|High|Critical\n"
#             "No extra text."
#         )

#         progress_ai = st.progress(0)
#         for idx, sample in enumerate(suspicious_samples):
#             user_payload = json.dumps(sample, ensure_ascii=False)
#             prompt = f"{SYSTEM_PROMPT}\nINPUT={user_payload}\nOUTPUT="

#             inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=1024).to(model.device)

#             with torch.no_grad():
#                 ids = model.generate(
#                     **inputs,
#                     max_new_tokens=140,
#                     do_sample=False,
#                     temperature=0.0,
#                     eos_token_id=tokenizer.eos_token_id,
#                     pad_token_id=tokenizer.eos_token_id
#                 )

#             response = tokenizer.decode(ids[0][inputs.input_ids.shape[-1]:], skip_special_tokens=True).strip()

#             # harden JSON parsing: extract first {...}
#             jstart = response.find("{")
#             jend = response.rfind("}")
#             if jstart != -1 and jend != -1 and jend > jstart:
#                 response_json_text = response[jstart:jend+1]
#             else:
#                 response_json_text = response

#             try:
#                 res_json = json.loads(response_json_text)
#                 ai_results.append(res_json)
#                 with st.expander(f"{sample.get('endpoint','Unknown')}  |  {sample.get('ip','?')}"):
#                     st.json(res_json)
#             except Exception:
#                 ai_results.append({"error": "JSON parse failed", "raw": response})

#             progress_ai.progress((idx + 1) / len(suspicious_samples))

#     except Exception as e:
#         st.error(f"AI Engine Error: {e}")

# # -------------------------
# # 9) REPORTING
# # -------------------------
# st.write("---")
# st.subheader("📑 Reporting")

# col_pdf, col_raw = st.columns(2)

# with col_pdf:
#     if st.button("Generate PDF Report"):
#         pdf = PDFReport()
#         pdf.add_page()

#         pdf.chapter_title("1. Executive Summary")
#         summary_text = (
#             f"Source File: {uploaded_file.name}\n"
#             f"Total Logs Scanned: {stats['total']}\n"
#             f"Successfully Parsed: {stats['parsed']}\n"
#             f"Unique IPs Detected: {len(ip_activity)}\n"
#             f"Threats Detected: {sum(stats['attack_types'].values())}\n"
#         )
#         pdf.chapter_body(summary_text)

#         pdf.chapter_title("2. High Ranking Attack Types")
#         if stats["attack_types"]:
#             for atk, count in stats["attack_types"].most_common(8):
#                 pdf.cell(0, 7, f"- {atk}: {count} occurrences", 0, 1)
#         else:
#             pdf.cell(0, 7, "No distinct attack patterns detected.", 0, 1)

#         pdf.ln(3)
#         pdf.chapter_title("3. Visualizations")
#         if os.path.exists(chart_path):
#             pdf.image(chart_path, x=10, w=180)

#         if ai_results:
#             pdf.add_page()
#             pdf.chapter_title("4. Granite AI Forensics")
#             pdf.set_font("Courier", "", 8)
#             for res in ai_results[:50]:
#                 pdf.multi_cell(0, 4, json.dumps(res, indent=2))
#                 pdf.ln(1)

#         pdf_output_name = "Security_Audit_Report.pdf"
#         pdf.output(pdf_output_name)

#         with open(pdf_output_name, "rb") as f:
#             st.download_button(
#                 label="📥 Download PDF Report",
#                 data=f,
#                 file_name=pdf_output_name,
#                 mime="application/pdf"
#             )

#         st.success("Report Generated!")

# with col_raw:
#     if os.path.exists(chart_path):
#         with open(chart_path, "rb") as f:
#             st.download_button(
#                 label="📥 Download Graph (PNG)",
#                 data=f,
#                 file_name="attack_distribution.png",
#                 mime="image/png"
#             )
## first working

# ==========================================
# DATASMITH PRO — SINGLE FILE (ALL GRAPHS)
# Run: streamlit run datasmith_app.py
# ==========================================

import streamlit as st
import re
from collections import Counter
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib as mpl

mpl.rcParams.update({
    "axes.titlesize": 9,
    "axes.labelsize": 8,
    "xtick.labelsize": 7,
    "ytick.labelsize": 7
})


# ---------------- PAGE CONFIG ----------------
st.set_page_config(
    page_title="DataSmith Pro",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ DataSmith Pro")
st.markdown("### Intelligent Log Analysis (Web • SSH • Random Logs)")

# ---------------- REGEX PATTERNS ----------------

# Web Access Logs (Apache/Nginx combined format)
WEB_PATTERN = re.compile(
    r'^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+.*?"(?P<method>\S+)\s+(?P<endpoint>\S+)\s+HTTP/[^"]+"\s+(?P<status>\d{3})'
)

# SSH Authentication Logs
SSH_PATTERN = re.compile(
    r'.*sshd.*(Failed password|Invalid user|Connection closed).*from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)'
)

# FTP Logs (Common FTP server patterns)
FTP_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+\s+\S+).*?ftpd.*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<action>LOGIN|FAILED|UPLOAD|DOWNLOAD)',
    re.IGNORECASE
)

# Email/SMTP Logs (Failed auth, relay attempts)
SMTP_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+\s+\S+).*?(?:postfix|sendmail|smtp).*?from.*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<action>reject|relay denied|authentication failed)',
    re.IGNORECASE
)

# Database Logs (MySQL/PostgreSQL failed connections)
DB_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+).*?(?:mysql|postgresql|mariadb).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?:Access denied|authentication failed|invalid password)',
    re.IGNORECASE
)

# Windows Event Logs (Failed login attempts)
WINDOWS_PATTERN = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(?:EventID|Event\s+ID).*?(?P<event_id>4625|4771|4776).*?(?P<ip>\d+\.\d+\.\d+\.\d+)?',
    re.IGNORECASE
)

# Firewall Logs (Blocked connections)
FIREWALL_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+\s+\S+).*?(?:DENY|DROP|REJECT|BLOCK).*?SRC=(?P<src_ip>\d+\.\d+\.\d+\.\d+).*?DST=(?P<dst_ip>\d+\.\d+\.\d+\.\d+).*?(?:DPT|DPORT)=(?P<port>\d+)',
    re.IGNORECASE
)

# DNS Query Logs (Potentially malicious domains)
DNS_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+\s+\S+).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?query.*?(?P<domain>[\w\-\.]+\.\w+)',
    re.IGNORECASE
)

# VPN Connection Logs
VPN_PATTERN = re.compile(
    r'(?P<timestamp>\S+\s+\S+\s+\S+).*?(?:openvpn|vpn|ipsec).*?(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<action>connected|disconnected|authentication failed)',
    re.IGNORECASE
)

# API Access Logs (REST API pattern)
API_PATTERN = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+).*?(?P<method>GET|POST|PUT|DELETE|PATCH)\s+/api/(?P<endpoint>[^\s"?]+).*?(?P<status>\d{3})',
    re.IGNORECASE
)

# Docker/Container Logs
DOCKER_PATTERN = re.compile(
    r'(?P<timestamp>\S+).*?(?:docker|containerd).*?(?P<container_id>[a-f0-9]{12}).*?(?P<action>started|stopped|died|error)',
    re.IGNORECASE
)

# SQL Injection Detection Pattern (in URLs/queries)
SQLI_DETECT_PATTERN = re.compile(
    r'(?:union.*?select|select.*?from|insert.*?into|update.*?set|delete.*?from|exec\(|execute\(|sleep\(|waitfor|benchmark)',
    re.IGNORECASE
)

# XSS Detection Pattern
XSS_DETECT_PATTERN = re.compile(
    r'(?:<script[^>]*>|javascript:|onerror\s*=|onload\s*=|<iframe|eval\(|alert\()',
    re.IGNORECASE
)

# Command Injection Pattern
CMD_INJECT_PATTERN = re.compile(
    r'(?:;|\||&|`|\$\(|>\s*|<\s*)(?:bash|sh|cmd|powershell|wget|curl|nc|netcat|python|perl|ruby)',
    re.IGNOREORE
)

# ---------------- ADVANCED ATTACK RULES ----------------

SQLI_PATTERNS = (
    "union", "select", "insert", "update", "delete",
    "drop", "sleep(", "benchmark", "information_schema",
    "' or '1'='1", "\" or \"1\"=\"1", "or 1=1",
    "--", "/*", "*/", "xp_cmdshell", "exec(",
    "having", "waitfor delay", "char(", "concat("
)

XSS_PATTERNS = (
    "<script", "%3cscript", "javascript:",
    "onerror=", "onload=", "<img",
    "alert(", "prompt(", "confirm(",
    "document.cookie", "window.location",
    "<iframe", "<embed", "<object",
    "onfocus=", "onmouseover=", "onclick="
)

RCE_PATTERNS = (
    "cmd=", "exec", "system(", "shell_exec",
    "powershell", "bash", "sh;", "|sh", "wget", "curl",
    "nc -", "netcat", "/bin/sh", "/bin/bash",
    "python -c", "perl -e", "ruby -e",
    "eval(", "assert(", "passthru(",
    "proc_open", "popen(", "base64_decode"
)

LFI_PATTERNS = (
    "../", "..%2f", "%2e%2e%2f", "etc/passwd", "boot.ini",
    "win.ini", "/proc/self", "file://", "php://filter",
    "php://input", "data://", "expect://",
    "zip://", "..\\", "....//", "....//"
)

SENSITIVE_FILES = (
    "/admin", "/wp-admin", "/phpmyadmin",
    "/config.php", "/.env", "/shell.php",
    "/backup", "/db.sql", "/.git/",
    "/wp-config.php", "/.htaccess", "/web.config",
    "/credentials", "/secret", "/private",
    "/api/keys", "/token", "/password"
)

SCANNER_KEYWORDS = (
    "nikto", "sqlmap", "nmap", "masscan", "acunetix",
    "burp", "zaproxy", "wpscan", "dirbuster",
    "gobuster", "metasploit", "nessus", "openvas",
    "nuclei", "subfinder", "amass", "ffuf"
)

# Directory Traversal specific patterns
DIR_TRAVERSAL_PATTERNS = (
    "..%5c", "%2e%2e/", "..%255c", "..%c0%af",
    "..%c1%9c", "%252e%252e", "0x2e0x2e/", "..%00"
)

# XXE (XML External Entity) patterns
XXE_PATTERNS = (
    "<!DOCTYPE", "<!ENTITY", "SYSTEM", "PUBLIC",
    "file:///etc", "file:///c:", "php://expect"
)

# SSRF (Server-Side Request Forgery) patterns  
SSRF_PATTERNS = (
    "localhost", "127.0.0.1", "0.0.0.0", "[::]",
    "169.254.169.254", "metadata", "internal",
    "file://", "dict://", "gopher://", "ldap://"
)

# Deserialization attack patterns
DESERIAL_PATTERNS = (
    "__reduce__", "pickle", "marshal",
    "unserialize", "phpserialize", "ObjectInputStream",
    "readObject", "Serializable"
)

# Template Injection patterns
TEMPLATE_INJECT_PATTERNS = (
    "{{", "}}", "${", "<%", "%>",
    "#{", "#set", "freemarker", "velocity"
)

# NoSQL Injection patterns
NOSQL_PATTERNS = (
    "$ne", "$gt", "$lt", "$regex", "$where",
    "[$ne]", "[$gt]", "[$exists]", "{$gt:",
    "$or", "$and", "$nin", "$in"
)

# LDAP Injection patterns
LDAP_PATTERNS = (
    "*()|", "*)(uid=*", "*)|(&",
    "(|(objectclass=*))", "admin*", "*)(uid=*)(|"
)

# Log Poisoning patterns
LOG_POISON_PATTERNS = (
    "<?php", "<?=", "<% ", "%>",
    "proc/self/environ", "access.log",
    "error.log", "var/log"
)

def classify_web_attack(endpoint, status, user_agent=""):
    ep = endpoint.lower()
    ua = user_agent.lower()

    # LFI & Path Traversal Detection
    if any(p in ep for p in LFI_PATTERNS):
        return "LFI / Path Traversal"
    
    if any(p in ep for p in DIR_TRAVERSAL_PATTERNS):
        return "Directory Traversal"

    # SQL Injection Detection
    if any(p in ep for p in SQLI_PATTERNS):
        return "SQL Injection"
    
    # NoSQL Injection Detection
    if any(p in ep for p in NOSQL_PATTERNS):
        return "NoSQL Injection"

    # XSS Detection
    if any(p in ep for p in XSS_PATTERNS):
        return "XSS Attempt"

    # RCE Detection
    if any(p in ep for p in RCE_PATTERNS):
        return "Remote Code Execution"
    
    # XXE Detection
    if any(p in ep for p in XXE_PATTERNS):
        return "XXE Attack"
    
    # SSRF Detection
    if any(p in ep for p in SSRF_PATTERNS):
        return "SSRF Attempt"
    
    # Template Injection
    if any(p in ep for p in TEMPLATE_INJECT_PATTERNS):
        return "Template Injection"
    
    # Deserialization Attack
    if any(p in ep for p in DESERIAL_PATTERNS):
        return "Deserialization Attack"
    
    # LDAP Injection
    if any(p in ep for p in LDAP_PATTERNS):
        return "LDAP Injection"
    
    # Log Poisoning
    if any(p in ep for p in LOG_POISON_PATTERNS):
        return "Log Poisoning"

    # Sensitive File Scan
    if any(p in ep for p in SENSITIVE_FILES):
        return "Sensitive File Scan"

    # Automated Scanner
    if any(p in ua for p in SCANNER_KEYWORDS):
        return "Automated Scanner"

    # Authentication attacks
    if status in (401, 403):
        return "Auth Brute Force"
    
    # Rate limiting
    if status == 429:
        return "Rate Limit Abuse"
    
    # Server errors (potential exploitation)
    if status >= 500:
        return "Server Error (Potential Exploit)"

    return "Normal"


# ---------------- FILE UPLOAD ----------------
uploaded_file = st.file_uploader("Upload Log File", type=["log", "txt"])

if not uploaded_file:
    st.info("Upload a log file to begin analysis.")
    st.stop()

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

# ---------------- PARSING ----------------
lines = uploaded_file.getvalue().split(b"\n")

for raw in lines:
    if not raw:
        continue

    line = raw.decode("utf-8", errors="ignore").strip()
    if not line:
        continue

    stats["total"] += 1
    parsed = False

    # ---- WEB LOG ----
    if line[0].isdigit() and '"' in line:
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

            parsed = True

    # ---- SSH LOG ----
    if not parsed:
        m = SSH_PATTERN.search(line)
        if m:
            ip = m.group("ip")
            stats["parsed"] += 1
            stats["log_types"]["SSH Log"] += 1
            ip_activity[ip] += 1
            stats["attack_types"]["SSH Brute Force"] += 1
            parsed = True

    # ---- UNKNOWN LOG ----
    if not parsed:
        stats["unparsed"] += 1
        stats["log_types"]["Unknown Log"] += 1

# ---------------- METRICS ----------------
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Logs", stats["total"])
c2.metric("Parsed Logs", stats["parsed"])
c3.metric("Unparsed Logs", stats["unparsed"])
c4.metric("Unique IPs", len(ip_activity))
c5.metric("Threats Detected", sum(stats["attack_types"].values()))
# ================= ATTACK DISTRIBUTION =================
st.subheader("📊 Attack Distribution")

if stats["attack_types"]:
    df_attack = (
        pd.DataFrame(stats["attack_types"].items(), columns=["Attack Type", "Count"])
        .sort_values("Count", ascending=True)
    )

    h = max(1.8, min(3.0, 0.35 * len(df_attack)))  # dynamic height
    fig, ax = plt.subplots(figsize=(4.2, h))

    ax.barh(
        df_attack["Attack Type"],
        df_attack["Count"],
        height=0.45
    )

    ax.set_xlabel("Count")
    ax.set_ylabel("")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    st.pyplot(fig)
else:
    st.info("No attacks detected.")


# ================= MOST USED IPs =================
st.subheader("📡 Most Active IP Addresses")

if ip_activity:
    df_ips = pd.DataFrame(
        ip_activity.most_common(8),
        columns=["IP Address", "Requests"]
    ).sort_values("Requests", ascending=True)

    h = max(2.0, min(3.2, 0.3 * len(df_ips)))
    fig, ax = plt.subplots(figsize=(4.2, h))

    ax.barh(
        df_ips["IP Address"],
        df_ips["Requests"],
        height=0.45
    )

    ax.set_xlabel("Requests")
    ax.set_ylabel("")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    st.pyplot(fig)


# ================= HTTP METHODS =================
st.subheader("📨 HTTP Method Usage")

if stats["methods"]:
    df_methods = pd.DataFrame(
        stats["methods"].items(),
        columns=["Method", "Count"]
    ).sort_values("Count", ascending=False)

    fig, ax = plt.subplots(figsize=(3.6, 2.6))
    ax.bar(
        df_methods["Method"],
        df_methods["Count"],
        width=0.55
    )

    ax.set_ylabel("Count")
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    plt.tight_layout()
    st.pyplot(fig)


# ================= LOG TYPE CLASSIFICATION =================
st.subheader("🗂️ Log Type Classification")

df_logtypes = pd.DataFrame(
    stats["log_types"].items(),
    columns=["Log Type", "Count"]
)

fig, ax = plt.subplots(figsize=(3.6, 2.6))
ax.bar(
    df_logtypes["Log Type"],
    df_logtypes["Count"],
    width=0.55
)

ax.set_ylabel("Count")
ax.spines["top"].set_visible(False)
ax.spines["right"].set_visible(False)
plt.tight_layout()
st.pyplot(fig)

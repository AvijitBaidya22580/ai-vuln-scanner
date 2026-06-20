import socket
import ssl
import json
import re
import requests
import whois
import dns.resolver
import os
from datetime import datetime, timezone
from fastapi import FastAPI, HTTPException, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import ollama
from urllib.parse import urlparse

# --- CONFIGURATION ---
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "llama3.2")
OLLAMA_TIMEOUT = int(os.getenv("OLLAMA_TIMEOUT", "120"))

app = FastAPI(
    title="AI Assisted Vulnerability Scanner",
    description="AI-powered vulnerability scanner and reconnaissance tool",
    version="1.0.0"
)

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Mount static files ---
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def read_root():
    return RedirectResponse(url="/static/index.html")

# --- Health Check ---
@app.get("/api/health")
def health_check():
    ollama_status = "unknown"
    try:
        ollama.list()
        ollama_status = "connected"
    except Exception:
        ollama_status = "disconnected"
    return {
        "status": "healthy",
        "backend": "running",
        "ollama": ollama_status,
        "model": OLLAMA_MODEL,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# --- Request Models ---
class ReconRequest(BaseModel):
    target: str

class AnalyzeRequest(BaseModel):
    recon_data: dict

class ChatRequest(BaseModel):
    message: str
    context: str = ""

class ReportRequest(BaseModel):
    recon_data: dict
    analysis: str = ""

# --- RECON MODULES ---
PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Proxy",
    8443: "HTTPS-Alt", 8888: "HTTP-Alt", 9090: "WebConsole", 27017: "MongoDB"
}

def port_scan(target_ip: str, timeout: float = 0.5) -> List[dict]:
    results = []
    for port in PORT_SERVICE_MAP.keys():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            if sock.connect_ex((target_ip, port)) == 0:
                results.append({"port": port, "state": "open", "service": PORT_SERVICE_MAP.get(port, "Unknown")})
            sock.close()
        except Exception:
            pass
    return results

def dns_enumeration(domain: str) -> dict:
    records = {}
    for rtype in ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]:
        try:
            answers = dns.resolver.resolve(domain, rtype)
            records[rtype] = [str(r).rstrip('.') for r in answers]
        except Exception:
            records[rtype] = []
    return records

def whois_lookup(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        def safe_str(val):
            if val is None: return "N/A"
            if isinstance(val, list): return val[0] if val else "N/A"
            return str(val)
        return {
            "domain_name": safe_str(w.domain_name),
            "registrar": safe_str(w.registrar),
            "creation_date": safe_str(w.creation_date),
            "expiration_date": safe_str(w.expiration_date),
            "name_servers": w.name_servers or [],
            "org": safe_str(w.org),
            "country": safe_str(w.country),
        }
    except Exception as e:
        return {"error": str(e)}

def ssl_analysis(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(5)
            s.connect((domain, 443))
            cert = s.getpeercert()
            protocol = s.version()
        not_after_str = cert.get('notAfter', '')
        days_left = None
        if not_after_str:
            not_after = datetime.strptime(not_after_str, '%b %d %H:%M:%S %Y %Z')
            days_left = (not_after - datetime.now(timezone.utc).replace(tzinfo=None)).days
        return {
            "subject": dict(x[0] for x in cert.get('subject', []) if x),
            "issuer": dict(x[0] for x in cert.get('issuer', []) if x),
            "serial_number": cert.get('serialNumber', 'N/A'),
            "not_before": cert.get('notBefore', 'N/A'),
            "not_after": not_after_str or 'N/A',
            "days_until_expiry": days_left,
            "protocol": protocol,
            "san": [entry[1] for entry in cert.get('subjectAltName', []) if entry],
            "expired": days_left is not None and days_left < 0,
        }
    except Exception as e:
        return {"error": str(e), "ssl_available": False}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"severity": "High", "desc": "Enforces HTTPS (HSTS)"},
    "Content-Security-Policy": {"severity": "High", "desc": "Prevents XSS, injection"},
    "X-Frame-Options": {"severity": "Medium", "desc": "Prevents clickjacking"},
    "X-Content-Type-Options": {"severity": "Medium", "desc": "Prevents MIME sniffing"},
    "X-XSS-Protection": {"severity": "Low", "desc": "Legacy XSS filter"},
    "Referrer-Policy": {"severity": "Low", "desc": "Controls referrer leakage"},
    "Permissions-Policy": {"severity": "Medium", "desc": "Controls browser features"},
    "Cache-Control": {"severity": "Low", "desc": "Controls caching"},
}

def http_header_analysis(domain: str) -> dict:
    headers_raw, status_code, tested_url = {}, None, None
    for scheme in ["https", "http"]:
        try:
            r = requests.get(f"{scheme}://{domain}", timeout=8, verify=False, allow_redirects=True)
            headers_raw, status_code, tested_url = dict(r.headers), r.status_code, f"{scheme}://{domain}"
            break
        except Exception:
            continue
    if not tested_url:
        return {"error": "Could not connect", "headers": {}, "security_audit": [], "status_code": None}
    audit = []
    for header, info in SECURITY_HEADERS.items():
        present = any(h.lower() == header.lower() for h in headers_raw.keys())
        audit.append({
            "header": header, "present": present,
            "severity": info["severity"] if not present else "Info",
            "description": info["desc"],
            "status": "✅ Present" if present else f"❌ Missing ({info['severity']})"
        })
    return {"url_tested": tested_url, "status_code": status_code, "headers": headers_raw, "security_audit": audit}

def detect_technologies(domain: str) -> List[dict]:
    techs = []
    try:
        r = requests.get(f"https://{domain}", timeout=8, verify=False, allow_redirects=True)
        headers, body = r.headers, r.text[:10000].lower()
        if headers.get('Server'): techs.append({"category": "Web Server", "name": headers['Server']})
        if headers.get('X-Powered-By'): techs.append({"category": "Framework", "name": headers['X-Powered-By']})
        tech_sigs = {
            "WordPress": ["wp-content", "wp-includes"], "Joomla": ["joomla"], "Drupal": ["drupal"],
            "React": ["react", "__next"], "Angular": ["ng-app"], "Vue.js": ["vue.js"],
            "jQuery": ["jquery"], "Bootstrap": ["bootstrap"], "Laravel": ["laravel"],
            "ASP.NET": ["__viewstate"], "Django": ["csrfmiddlewaretoken"], "Cloudflare": ["cloudflare"],
        }
        for tech, sigs in tech_sigs.items():
            if any(sig in body for sig in sigs): techs.append({"category": "Technology", "name": tech})
        cookies = headers.get('Set-Cookie', '')
        if 'PHPSESSID' in cookies: techs.append({"category": "Language", "name": "PHP"})
        if 'JSESSIONID' in cookies: techs.append({"category": "Language", "name": "Java"})
    except Exception as e:
        techs.append({"category": "Error", "name": str(e)})
    return techs

COMMON_SUBDOMAINS = ["www", "mail", "ftp", "admin", "blog", "dev", "staging", "test", "api", "app", "cdn", "cloud"]

def subdomain_discovery(domain: str, limit: int = 20) -> List[dict]:
    found = []
    for sub in COMMON_SUBDOMAINS[:limit]:
        try:
            ip = socket.gethostbyname(f"{sub}.{domain}")
            found.append({"subdomain": f"{sub}.{domain}", "ip": ip})
        except socket.gaierror:
            pass
    return found

# --- MAIN RECON ENDPOINT ---
@app.post("/api/recon")
def perform_recon(req: ReconRequest):
    target = req.target.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target URL or domain is required")
    parsed = urlparse(target)
    domain = parsed.hostname or target.replace("http://", "").replace("https://", "").split("/")[0]
    if not re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain):
        raise HTTPException(status_code=400, detail=f"Invalid domain: {domain}")
    try:
        ip_addr = socket.gethostbyname(domain)
    except socket.gaierror:
        raise HTTPException(status_code=400, detail=f"Could not resolve: {domain}")
    return {
        "target": domain, "resolved_ip": ip_addr,
        "scan_time": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "port_scan": port_scan(ip_addr), "dns_records": dns_enumeration(domain),
        "whois_info": whois_lookup(domain), "ssl_tls": ssl_analysis(domain),
        "http_analysis": http_header_analysis(domain), "technologies": detect_technologies(domain),
        "subdomains": subdomain_discovery(domain),
    }

# --- AI ANALYSIS ENDPOINT ---
@app.post("/api/analyze")
def analyze_recon(req: AnalyzeRequest):
    data_str = json.dumps(req.recon_data, indent=2, default=str)
    
    prompt = f"""You are an expert penetration tester and cybersecurity educator.

Analyze this reconnaissance data:
1. Explain findings in simple terms
2. Identify potential vulnerabilities based on open ports, missing security headers, or outdated technologies.
3. Rate severity: Critical/High/Medium/Low/Info
4. Give actionable recommendations for remediation.

Use Markdown formatting. Be educational and thorough.

## Reconnaissance Data:
```json
{data_str}
```"""

    try:
        response = ollama.generate(
            model=OLLAMA_MODEL,
            prompt=prompt,
            options={'num_predict': 2000, 'temperature': 0.7}
        )
        analysis_text = response.get('response', '')
        if not analysis_text:
            raise Exception("Empty response from Ollama")
        return {"analysis": analysis_text}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI analysis failed: {str(e)}")

# --- REPORT ENDPOINT ---
@app.post("/api/report")
def generate_report(req: ReportRequest):
    data_str = json.dumps(req.recon_data, indent=2, default=str)
    analysis_section = f"\n## Previous AI Analysis:\n{req.analysis}" if req.analysis else ""
    
    prompt = f"""You are a senior penetration tester writing a professional report.

Using the reconnaissance data below, generate a COMPLETE vulnerability assessment report in Markdown.

## Reconnaissance Data:
```json
{data_str}
```{analysis_section}

## Report Structure:
1. Executive Summary
2. Scope & Methodology
3. Findings Summary (Table)
4. Detailed Findings (Severity, Description, Evidence, Risk, Recommendation)
5. Remediation Priority Matrix
6. Conclusion

Make it educational and professional.
"""
    
    try:
        response = ollama.generate(
            model=OLLAMA_MODEL,
            prompt=prompt,
            options={'num_predict': 3000, 'temperature': 0.3}
        )
        return {"report": response.get('response', 'Report generation failed.')}
    except Exception as e:
        return {"report": f"Error: {str(e)}"}

# --- CHAT ENDPOINT ---
@app.post("/api/chat")
def chat_with_assistant(req: ChatRequest):
    system_prompt = """You are a friendly, expert cybersecurity tutor.
Explain concepts clearly, focus on ethical hacking, and relate findings to security best practices.
Keep responses concise and use Markdown."""
    
    context_prompt = f"\n\n## Context:\n{req.context}" if req.context else ""
    full_prompt = f"{req.message}{context_prompt}"
    
    try:
        response = ollama.generate(
            model=OLLAMA_MODEL,
            prompt=full_prompt,
            system=system_prompt,
            options={'num_predict': 500, 'temperature': 0.7}
        )
        return {"reply": response.get('response', 'I could not generate a response.')}
    except Exception as e:
        return {"reply": f"Error: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

# 🛡️ AI Vulnerability Scanner

An AI-powered external reconnaissance and vulnerability assessment tool built with **FastAPI**, **Ollama (llama3.2)**, and a sleek dark-mode web UI.

![Security Dashboard](screenshots/01_dashboard_scan_results.png)

---

## ✨ Features

- 🔌 **Port Scanning** — Detects open ports and services (HTTP, HTTPS, SSH, FTP, RDP, etc.)
- 🌐 **DNS Enumeration** — A, AAAA, MX, NS, TXT, CNAME, SOA records
- 📋 **WHOIS Lookup** — Registrar, creation/expiry dates, nameservers, org info
- 🔒 **SSL/TLS Analysis** — Certificate subject, issuer, expiry, protocol version
- 🛡️ **HTTP Security Headers Audit** — HSTS, CSP, X-Frame-Options, and more
- ⚙️ **Technology Detection** — WordPress, React, Cloudflare, PHP, Django, etc.
- 🌍 **Subdomain Discovery** — Resolves common subdomains
- 🤖 **AI Analysis** — Ollama-powered vulnerability interpretation and recommendations
- 📄 **Report Generation** — Professional Markdown pentest report with remediation matrix
- 💬 **AI Chat Assistant** — Contextual cybersecurity tutor

---

## 🚀 Quick Start

### 1. Prerequisites
- Python 3.10+
- [Ollama](https://ollama.com) installed and running locally
- `llama3.2` model pulled: `ollama pull llama3.2`

### 2. Clone the repo
```bash
git clone https://github.com/<your-username>/ai-vuln-scanner.git
cd ai-vuln-scanner
```

### 3. Create a virtual environment & install dependencies
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/macOS
source venv/bin/activate

pip install -r requirements.txt
```

### 4. Run the server
```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Open in browser
```
http://localhost:8000
```

---

## 📁 Project Structure

```
ai-vuln-scanner/
├── app.py                  # FastAPI backend (all recon + AI endpoints)
├── generate_slides.py      # Slide generation utility
├── requirements.txt        # Python dependencies
├── static/                 # Frontend (HTML, CSS, JS)
│   └── index.html
└── screenshots/            # App screenshots
```

---

## 🔧 Configuration

| Environment Variable | Default     | Description                  |
|----------------------|-------------|------------------------------|
| `OLLAMA_MODEL`       | `llama3.2`  | Ollama model to use for AI   |
| `OLLAMA_TIMEOUT`     | `120`       | Timeout (seconds) for Ollama |

Set via a `.env` file or export before running.

---

## 📡 API Endpoints

| Method | Endpoint        | Description                      |
|--------|-----------------|----------------------------------|
| GET    | `/`             | Redirects to dashboard UI        |
| GET    | `/api/health`   | Health check + Ollama status     |
| POST   | `/api/recon`    | Run full reconnaissance scan     |
| POST   | `/api/analyze`  | AI vulnerability analysis        |
| POST   | `/api/report`   | Generate full pentest report     |
| POST   | `/api/chat`     | Chat with AI security assistant  |

---

## ⚠️ Disclaimer

This tool is for **educational and authorized security testing purposes only**.  
Do not scan systems you do not own or have explicit permission to test.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

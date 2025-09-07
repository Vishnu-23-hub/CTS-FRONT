# Recon Toolkit – Flask Web Dashboard (Cyber UI)

Run:
```bash
cd recon_flask
python3 -m venv .venv && source .venv/bin/activate
pip install flask
# optional: export SPIDERFOOT_URL=http://localhost:5001
export FLASK_APP=app.py
python app.py
```

Open http://localhost:8000

## Flow
- Landing → Scan Options
- Light Scan: shows SpiderFoot iframe if SPIDERFOOT_URL is set, otherwise a SpiderFoot-like table from uploaded JSON.
- Deep Scan: vertical cards. Each goes to a module page that renders JSON with collapsible viewer.
- Generate Report: downloads the currently loaded results as JSON.

## Upload JSON
Use the "Upload latest scan JSON" on Scan Options, Light, or Deep pages.
Expected keys (flexible):
- subdomains / subdomain_discovery
- ports / services / port_service_scanning / portscan
- public_data / osint / public_data_scraping / scrape
- vulnerabilities / vulns / vulnerability_assessment

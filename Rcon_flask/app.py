import json, os, io, datetime
from flask import (
    Flask,
    render_template,
    jsonify,
    send_file,
    request,
    redirect,
    url_for,
    flash,
    session, 
)
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = "dev-secret"

# --- Config ---
BACKEND_OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "backend", "output")
os.makedirs(BACKEND_OUTPUT_DIR, exist_ok=True)

# --- Module Keys ---
MODULE_KEYS = {
    "subdomain": ["subdomain", "subdomains", "alive"],
    "subdomain-discovery": ["subdomains", "alive", "subdomain_discovery"],
    "port-service-scanning": [
        "ports", "services", "port_service_scanning",
        "portscan", "shodan_nmap", "shodan"
    ],
    "public-data-scraping": [
        "emails", "phones", "usernames", "passwords",
        "secrets", "public_data_scraping", "scrapping"
    ],
    "vulnerability-assessment": [
        "vulnerabilities", "vulns", "vulnerability_assessment"
    ],
    "technology-profile-mapping": [
        "bucket", "Sbucket", "whois", "ip_ranges", 
        "s3_buckets", "cve_ids", "tech_stack", "shodan",
        "phishing_vectors",
        "spf","dmarc","dkim",       # ✅ Added
        "emailsecurity","emailsecurity",  
        "risk","clickjacking"             # ✅ Added
    ]
}



# --- Helpers ---
def load_results(scan_type="light"):
    filename = "light_scan.json" if scan_type == "light" else "deep_scan.json"
    filepath = os.path.join(BACKEND_OUTPUT_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def get_spiderfoot_url():
    """Read SpiderFoot URL from backend/output/spiderfoot_url.txt"""
    url_file = os.path.join(BACKEND_OUTPUT_DIR, "spiderfoot_url.txt")
    if os.path.exists(url_file):
        with open(url_file, "r") as f:
            return f.read().strip()
    return None

def extract_module(results: dict, module_slug: str):
    """Extract and merge module-specific data"""
    keys = MODULE_KEYS.get(module_slug, [])
    data = {}

    def merge_dict(target, source):
        for k, v in source.items():
            if k not in target:
                target[k] = v
            else:
                # merge lists
                if isinstance(v, list) and isinstance(target[k], list):
                    target[k].extend(v)
                # merge dicts
                elif isinstance(v, dict) and isinstance(target[k], dict):
                    merge_dict(target[k], v)

    # top-level keys
    for k in keys:
        if k in results:
            merge_dict(data, {k: results[k]})

    # nested dicts
    for _, v in results.items():
        if isinstance(v, dict):
            for kk in keys:
                if kk in v:
                    merge_dict(data, {kk: v[kk]})

    return data

def normalize_subdomain_data(module_data):
    if not isinstance(module_data, dict):
        return {"alive": [], "subdomains": [], "alive_count": 0, "subdomains_count": 0}

    alive = module_data.get("alive", [])
    subs = module_data.get("subdomains", [])

    if not isinstance(alive, list): alive = [alive]
    if not isinstance(subs, list): subs = [subs]

    return {
        "alive": alive,
        "subdomains": subs,
        "alive_count": len(alive),
        "subdomains_count": len(subs),
    }

from collections import defaultdict

def normalize_portscan_data(module_data):
    if not isinstance(module_data, dict):
        return {
            "all_results": [],
            "ports": [],
            "ports_with_vulns": [],
            "services": [],
            "ports_count": 0,
            "services_count": 0,
        }

    ports = []
    ports_with_vulns = []
    services = []
    all_results_raw = []

    # Direct ports/services from top-level module_data
    ports.extend(module_data.get("ports", []))
    services.extend(module_data.get("services", []))

    # --- Handle Shodan formats ---
    if "shodan" in module_data and isinstance(module_data["shodan"], dict):
        shodan_nmap = module_data["shodan"].get("shodan_nmap", [])
    elif "shodan_nmap" in module_data and isinstance(module_data["shodan_nmap"], list):
        shodan_nmap = module_data["shodan_nmap"]
    else:
        shodan_nmap = []

    # Flatten raw results
    for item in shodan_nmap:
        item_ports = item.get("ports", [])
        item_vulns = item.get("vulnerabilities", [])

        for port in item_ports:
            all_results_raw.append({
                "ip": item.get("ip"),
                "port": port,
                "org": item.get("org"),
                "hostnames": item.get("hostnames", []),
                "location": item.get("location", {}),
                "vulnerabilities": item_vulns,
            })
            ports.append(port)

        if item_vulns:
            ports_with_vulns.extend(item_ports)

    # --- Group results by IP with deduplication ---
    grouped = defaultdict(lambda: {"ip": "", "ports": [], "org": "", "hostnames": [], "location": {}, "vulnerabilities": []})

    for res in all_results_raw:
        ip = res.get("ip", "N/A")
        grouped[ip]["ip"] = ip
        grouped[ip]["ports"].append(res.get("port"))
        grouped[ip]["org"] = res.get("org") or grouped[ip]["org"]

        # Deduplicate hostnames
        grouped[ip]["hostnames"] = list(set(grouped[ip]["hostnames"] + res.get("hostnames", [])))

        # Location (keep the first one found)
        grouped[ip]["location"] = res.get("location") or grouped[ip]["location"]

        # Deduplicate vulnerabilities
        grouped[ip]["vulnerabilities"] = list(set(grouped[ip]["vulnerabilities"] + res.get("vulnerabilities", [])))

    all_results = list(grouped.values())

    return {
        "ports": ports,
        "ports_with_vulns": ports_with_vulns,
        "services": services,
        "all_results": all_results,
        "ports_count": len(ports),
        "services_count": len(services),
    }


def normalize_public_data(module_data):
    if not isinstance(module_data, dict):
        return {
            "emails": [], "phones": [], "usernames": [], "passwords": [], "secrets": [],
            "emails_count": 0, "phones_count": 0, "usernames_count": 0,
            "passwords_count": 0, "secrets_count": 0
        }

    emails = module_data.get("emails", [])
    phones = module_data.get("phones", [])
    usernames = module_data.get("usernames", [])
    passwords = module_data.get("passwords", [])
    secrets = module_data.get("secrets", [])

    return {
        "emails": emails,
        "phones": phones,
        "usernames": usernames,
        "passwords": passwords,
        "secrets": secrets,
        "emails_count": len(emails),
        "phones_count": len(phones),
        "usernames_count": len(usernames),
        "passwords_count": len(passwords),
        "secrets_count": len(secrets),
    }
def normalize_techprofile_data(module_data):
    if not isinstance(module_data, dict):
        return {}

    # --- IP Ranges ---
    ip_ranges = []
    for entry in module_data.get("whois", []):
        ip = entry.get("ip")
        netrange, cidr = None, None
        for line in entry.get("whois", []):
            if line.startswith("NetRange"):
                netrange = line.split(":", 1)[1].strip()
            elif line.startswith("CIDR"):
                cidr = line.split(":", 1)[1].strip()
        ip_ranges.append({"ip": ip, "netrange": netrange, "cidr": cidr})

    # --- S3 Buckets ---
    s3_buckets_raw = module_data.get("Sbucket", []) or module_data.get("s3_buckets", [])
    s3_buckets = []
    for sb in s3_buckets_raw:
        s3_buckets.append({
            "url": sb.get("url", ""),
            "bucket": sb.get("bucket", ""),
            "key": sb.get("key", ""),
            "read": sb.get("read", ""),
            "write": sb.get("write", ""),
        })

    # --- CVEs ---
    cve_ids = module_data.get("cve_ids", [])

    # --- Tech Stack ---
    tech_stack = module_data.get("tech_stack", [])

    # --- Phishing Vectors ---
    phishing_vectors = {
        "emailsecurity": {"spf": [], "dmarc": [], "dkim": []},
        "clickjacking": []
    }

    # Flatten nested emailsecurity
    emailsec = module_data.get("emailsecurity", {})
    while isinstance(emailsec, dict) and "emailsecurity" in emailsec:
        emailsec = emailsec["emailsecurity"]

    if isinstance(emailsec, dict):
        # --- SPF ---
        spf_list = []
        for x in emailsec.get("spf", []):
            if isinstance(x, dict):
                spf_list.append({
                    "status": x.get("status", ""),
                    "detail": x.get("detail", "")
                })
            elif isinstance(x, str):
                spf_list.append({"status": x, "detail": ""})
        phishing_vectors["emailsecurity"]["spf"] = spf_list

        # --- DMARC ---
        dmarc_list = []
        for x in emailsec.get("dmarc", []):
            if isinstance(x, dict):
                dmarc_list.append({
                    "status": x.get("status", ""),
                    "full_record": x.get("full_record", ""),
                    "main_policy": x.get("main_policy", ""),
                    "sub_policy": x.get("sub_policy", "")
                })
            elif isinstance(x, str):
                dmarc_list.append({
                    "status": x,
                    "full_record": "",
                    "main_policy": "",
                    "sub_policy": ""
                })
        phishing_vectors["emailsecurity"]["dmarc"] = dmarc_list

        # --- DKIM ---
        dkim_list = []
        for x in emailsec.get("dkim", []):
            if isinstance(x, dict):
                dkim_list.append({
                    "status": x.get("status", ""),
                    "selector": x.get("selector", ""),
                    "record": x.get("record", "")
                })
            elif isinstance(x, str):
                dkim_list.append({
                    "status": x,
                    "selector": "",
                    "record": ""
                })
        phishing_vectors["emailsecurity"]["dkim"] = dkim_list

    # --- Clickjacking ---
    risk = module_data.get("risk", {})
    phishing_vectors["clickjacking"] = risk.get("clickjacking", [])

    # --- Final normalized dict ---
    return {
        "ip_ranges": ip_ranges,
        "s3_buckets": s3_buckets,
        "cve_ids": cve_ids,
        "tech_stack": tech_stack,
        "phishing_vectors": phishing_vectors,
        "ip_ranges_count": len(ip_ranges),
        "s3_buckets_count": len(s3_buckets),
        "cve_ids_count": len(cve_ids),
        "tech_stack_count": len(tech_stack)
    }

# --- NEW FUNCTION ---
def get_module_data(slug):
    results = load_results("deep")  # always read from deep scan
    module_raw = extract_module(results, slug)

    # Normalize depending on module
    if slug in ["subdomain", "subdomain-discovery"]:
        return normalize_subdomain_data(module_raw)
    elif slug == "port-service-scanning":
        return normalize_portscan_data(module_raw)
    elif slug == "public-data-scraping":
        return normalize_public_data(module_raw)
    elif slug == "technology-profile-mapping":
        return normalize_techprofile_data(module_raw)
    else:
        # Default fallback (just raw dict)
        return module_raw


# --- Routes ---
@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/scan-options")
def scan_options():
    return render_template("scan_options.html")

@app.route("/light")
def light_scan():
    """Light Scan now shows only SpiderFoot URL (iframe)"""
    spiderfoot_url = get_spiderfoot_url()
    return render_template("light.html", spiderfoot_url=spiderfoot_url)

@app.route("/deep")
def deep_scan():
    results = load_results("deep")
    has_results = bool(results)
    return render_template("deep.html", has_results=has_results)

@app.route("/module/<slug>")
def module_page(slug):
    module_data = get_module_data(slug)

    if slug in ["subdomain", "subdomain-discovery"]:
        template = "subdomain.html"
    elif slug == "port-service-scanning":
        template = "portscan.html"
    elif slug == "public-data-scraping":
        template = "scrap.html"
    elif slug == "technology-profile-mapping":
        template = "tech.html"
    else:
        template = "fallback.html"

    return render_template(template, module_data=module_data, slug=slug)


@app.route("/api/results/<scan_type>")
def api_results(scan_type):
    return jsonify(load_results(scan_type))

@app.route("/api/spiderfoot-url")
def api_spiderfoot_url():
    url = get_spiderfoot_url()
    if url:
        return jsonify({"url": url})
    return jsonify({"error": "SpiderFoot URL not found"}), 404

@app.route("/spiderfoot")
def spiderfoot_ui():
    return render_template("spiderfoot.html")

@app.route("/report")
def report():
    results = load_results("deep")
    ts = datetime.datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    mem = io.BytesIO(json.dumps(results, indent=2).encode("utf-8"))
    mem.seek(0)
    return send_file(
        mem,
        as_attachment=True,
        download_name=f"recon_report_{ts}.json",
        mimetype="application/json",
    )

@app.route("/upload", methods=["POST"])
def upload():
    if "file" not in request.files:
        flash("No file part")
        return redirect(url_for("scan_options"))

    file = request.files["file"]
    if file.filename == "":
        flash("No selected file")
        return redirect(url_for("scan_options"))

    to = request.args.get("to", "deep")  # only "deep" supported
    if to == "light":
        flash("Upload is not available for Light Scan")
        return redirect(url_for("light_scan"))

    # Always overwrite deep_scan.json
    save_path = os.path.join(BACKEND_OUTPUT_DIR, "deep_scan.json")
    file.save(save_path)

    # Validate JSON
    try:
        with open(save_path, "r", encoding="utf-8") as f:
            json.load(f)
    except Exception as e:
        flash(f"Error parsing JSON: {e}")
        return redirect(url_for("deep_scan"))

    flash("File uploaded successfully! The latest scan will now be used.")
    return redirect(url_for("deep_scan"))

@app.route("/deep_scan")
def deep_scan_view():  # renamed function
    latest_file = session.get('latest_file')

    if not latest_file:
        flash("No scan file uploaded yet!")
        return render_template("deep_scan.html", module_data={"all_results": []})

    file_path = os.path.join(BACKEND_OUTPUT_DIR, latest_file)

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        module_data = normalize_portscan_data(data)
    except Exception as e:
        flash(f"Error loading scan file: {e}")
        module_data = {"all_results": []}

    return render_template("deep_scan.html", module_data=module_data)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8000)

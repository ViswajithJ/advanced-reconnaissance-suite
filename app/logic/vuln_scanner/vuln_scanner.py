import requests
from app.logic.vuln_scanner.scripts import *
vuln_dict = {
    "SSL Stripping": check_hsts,  # hsts
    "Cross-Site Scripting": check_xss,
    "MIME-Type Sniffing": check_mimetype_sniff,
    "Clickjacking": check_clickjacking,
    "Reflected Cross-Site Scripting": check_reflected_xss,
    "Infoleak via Referrer": check_infoleak_referrer,
    "Privilege Escalation via Permissions": check_permissions,
    "Certificate spoofing via MITM": check_cert_transparency,
    "Sensitive Info Caching": check_cache_control,
    "CORS vulnerability": check_cors,
    "Insecure Mixed Content": check_insecure_mixed_content 
}


def get_headers(domain):
    response = requests.get(f"https://{domain}/")
    headers = response.headers
    return headers


def vuln_scan(domain, vuln_list):
    vuln_result = {"Domain": domain}
    headers = get_headers(domain)
    for i in vuln_list:
        vuln_result[i] = vuln_dict[i](headers)
    return vuln_result

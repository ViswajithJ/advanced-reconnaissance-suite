import sys
import ssl
import socket


def check_clickjacking_vulnerability(headers):
    if "x-frame-options" not in headers or (
        headers["x-frame-options"] != "DENY"
        and headers["x-frame-options"] != "SAMEORIGIN"
    ):
        return {
            "name": "Clickjacking",
            "description": "Missing or misconfigured X-Frame-Options header.",
            "risk": "Medium",
            "evidence": "X-Frame-Options header is not set to DENY or SAMEORIGIN.",
        }
    return {
        "name": "Clickjacking",
        "description": "No Clickjacking vulnerability detected.",
        "risk": "None",
        "evidence": "X-Frame-Options header is properly configured.",
    }


def check_insecure_mixed_content(headers):
    if (
        "content-security-policy" in headers
        and "block-all-mixed-content" not in headers["content-security-policy"]
    ):
        return {
            "name": "Insecure Mixed Content",
            "description": "Missing or misconfigured Content-Security-Policy header to block all mixed content.",
            "risk": "Medium",
            "evidence": "Content-Security-Policy header does not contain block-all-mixed-content directive.",
        }
    return {
        "name": "Insecure Mixed Content",
        "description": "No Insecure Mixed Content vulnerability detected.",
        "risk": "None",
        "evidence": "Content-Security-Policy header is properly configured.",
    }


def check_cors_vulnerability(headers):
    if (
        "access-control-allow-origin" in headers
        and headers["access-control-allow-origin"] != "*"
    ):
        return {
            "name": "CORS",
            "description": "Potentially misconfigured Access-Control-Allow-Origin header.",
            "risk": "Medium",
            "evidence": "Access-Control-Allow-Origin header is set to a specific domain instead of wildcard.",
        }
    return {
        "name": "CORS",
        "description": "No CORS vulnerability detected.",
        "risk": "None",
        "evidence": "Access-Control-Allow-Origin header is properly configured.",
    }


def check_hsts_vulnerability(headers):
    if (
        "strict-transport-security" not in headers
        or "includeSubDomains" not in headers["strict-transport-security"]
    ):
        return {
            "name": "HSTS",
            "description": "Missing or misconfigured Strict-Transport-Security header with includeSubDomains directive.",
            "risk": "High",
            "evidence": "Strict-Transport-Security header does not include includeSubDomains directive.",
        }
    return {
        "name": "HSTS",
        "description": "No HSTS vulnerability detected.",
        "risk": "None",
        "evidence": "Strict-Transport-Security header is properly configured.",
    }


def check_reflected_xss_vulnerability(headers):
    if (
        "x-xss-protection" not in headers
        or headers["x-xss-protection"] != "1; mode=block"
    ):
        return {
            "name": "Reflected XSS",
            "description": "Missing or misconfigured X-XSS-Protection header.",
            "risk": "High",
            "evidence": "X-XSS-Protection header is not set to 1; mode=block.",
        }
    return {
        "name": "Reflected XSS",
        "description": "No Reflected XSS vulnerability detected.",
        "risk": "None",
        "evidence": "X-XSS-Protection header is properly configured.",
    }


def check_server_info_vulnerability(headers):
    if "server" in headers or "x-powered-by" in headers or "via" in headers:
        return {
            "name": "Server Information Leakage",
            "description": "Presence of Server, X-Powered-By, or Via headers.",
            "risk": "Low",
            "evidence": "Server, X-Powered-By, or Via headers are present in the response.",
        }
    return {
        "name": "Server Information Leakage",
        "description": "No Server Information Leakage vulnerability detected.",
        "risk": "None",
        "evidence": "Server, X-Powered-By, and Via headers are not present in the response.",
    }


def check_xss_vulnerability(headers):
    if "content-security-policy" in headers:
        csp_header = headers["content-security-policy"]
        if "script-src" not in csp_header:
            return {
                "name": "Cross-site Scripting (XSS)",
                "description": "Missing or misconfigured Content-Security-Policy header for script-src.",
                "risk": "High",
                "evidence": "Content-Security-Policy header does not contain script-src directive.",
            }
    return {
        "name": "Cross-site Scripting (XSS)",
        "description": "No XSS vulnerability detected.",
        "risk": "None",
        "evidence": "Content-Security-Policy header is properly configured.",
    }


def check_cache_control_vulnerability(headers):
    if "cache-control" not in headers or (
        "no-store" not in headers["cache-control"]
        and "no-cache" not in headers["cache-control"]
    ):
        return {
            "name": "Cache Control",
            "description": "Missing or misconfigured Cache-Control header with no-store or no-cache directives.",
            "risk": "Medium",
            "evidence": "Cache-Control header does not include no-store or no-cache directives.",
        }
    return {
        "name": "Cache Control",
        "description": "No Cache Control vulnerability detected.",
        "risk": "None",
        "evidence": "Cache-Control header is properly configured.",
    }


def check_cache_poisoning_vulnerability(headers):
    if "cache-control" in headers and "public" in headers["cache-control"]:
        return {
            "name": "Cache Poisoning",
            "description": "Potentially misconfigured Cache-Control header allowing public caching.",
            "risk": "High",
            "evidence": 'Cache-Control header includes "public" directive.',
        }
    return {
        "name": "Cache Poisoning",
        "description": "No Cache Poisoning vulnerability detected.",
        "risk": "None",
        "evidence": "Cache-Control header is properly configured.",
    }
################################################################
###################### CHECK BELOW #############################

# import requests

# # Risk Classification
# HIGH_RISK = "HIGH"
# MEDIUM_RISK = "MEDIUM"
# LOW_RISK = "LOW"

# def classify_risk(header_name, value):
#     """
#     Classifies the risk of missing or misconfigured headers.
#     """
#     if value is None:
#         return f"{header_name} Header Missing! - {HIGH_RISK}"

#     if header_name == "Strict-Transport-Security":
#         if "max-age" in value:
#             max_age = int(value.split('=')[1].split(';')[0])
#             if max_age < 31536000:
#                 return f"{header_name} - {MEDIUM_RISK}: Short max-age, consider a longer value (e.g., 1 year)."
#             return f"{header_name} - {LOW_RISK}: Max-age is well configured."
#         return f"{header_name} - {HIGH_RISK}: Missing max-age or misconfigured."

#     if header_name == "Content-Security-Policy":
#         # Basic check for missing directives
#         if "default-src" not in value:
#             return f"{header_name} - {HIGH_RISK}: Missing default-src directive."
#         if "unsafe-inline" in value:
#             return f"{header_name} - {HIGH_RISK}: Contains unsafe-inline in script-src, highly risky."
#         return f"{header_name} - {LOW_RISK}: CSP header is present and has safe configuration."

#     if header_name == "X-Content-Type-Options":
#         if value.lower() == "nosniff":
#             return f"{header_name} - {LOW_RISK}: Properly configured."
#         return f"{header_name} - {HIGH_RISK}: Not configured properly."

#     if header_name == "X-Frame-Options":
#         if value == "DENY":
#             return f"{header_name} - {LOW_RISK}: Properly configured."
#         if value == "SAMEORIGIN":
#             return f"{header_name} - {MEDIUM_RISK}: Same-origin is fine, but 'DENY' is more secure."
#         return f"{header_name} - {HIGH_RISK}: Not set or misconfigured."

#     if header_name == "X-XSS-Protection":
#         if value == "1; mode=block":
#             return f"{header_name} - {LOW_RISK}: Properly configured."
#         return f"{header_name} - {HIGH_RISK}: Not configured or set incorrectly."

#     if header_name == "Referrer-Policy":
#         if value == "no-referrer":
#             return f"{header_name} - {LOW_RISK}: Properly configured for privacy."
#         if "unsafe-url" in value:
#             return f"{header_name} - {HIGH_RISK}: unsafe-url is risky, could leak private information."
#         return f"{header_name} - {MEDIUM_RISK}: Referrer policy set, but needs review."

#     if header_name == "Permissions-Policy":
#         if value == "*":
#             return f"{header_name} - {HIGH_RISK}: Allowing all features is risky."
#         return f"{header_name} - {LOW_RISK}: Permissions-Policy is set."

#     if header_name == "Expect-CT":
#         if value:
#             return f"{header_name} - {LOW_RISK}: Properly configured."
#         return f"{header_name} - {HIGH_RISK}: Missing or misconfigured."

#     if header_name == "Cache-Control":
#         if "no-store" in value:
#             return f"{header_name} - {LOW_RISK}: Properly configured to avoid caching sensitive data."
#         return f"{header_name} - {MEDIUM_RISK}: Cache-Control is configured, but 'no-store' is recommended for sensitive data."

#     return f"{header_name} - {LOW_RISK}: Header is present, but no specific concerns."

# def check_hsts(url):
#     try:
#         response = requests.get(url)
#         hsts = response.headers.get('Strict-Transport-Security')
#         return classify_risk("Strict-Transport-Security", hsts)
#     except Exception as e:
#         return f"Error: {e}"

# def check_csp(url):
#     try:
#         response = requests.get(url)
#         csp = response.headers.get('Content-Security-Policy')
#         return classify_risk("Content-Security-Policy", csp)
#     except Exception as e:
#         return f"Error: {e}"

# def check_x_content_type_options(url):
#     try:
#         response = requests.get(url)
#         x_content_type = response.headers.get('X-Content-Type-Options')
#         return classify_risk("X-Content-Type-Options", x_content_type)
#     except Exception as e:
#         return f"Error: {e}"

# def check_x_frame_options(url):
#     try:
#         response = requests.get(url)
#         x_frame = response.headers.get('X-Frame-Options')
#         return classify_risk("X-Frame-Options", x_frame)
#     except Exception as e:
#         return f"Error: {e}"

# def check_x_xss_protection(url):
#     try:
#         response = requests.get(url)
#         x_xss = response.headers.get('X-XSS-Protection')
#         return classify_risk("X-XSS-Protection", x_xss)
#     except Exception as e:
#         return f"Error: {e}"

# def check_referrer_policy(url):
#     try:
#         response = requests.get(url)
#         referrer = response.headers.get('Referrer-Policy')
#         return classify_risk("Referrer-Policy", referrer)
#     except Exception as e:
#         return f"Error: {e}"

# def check_permissions_policy(url):
#     try:
#         response = requests.get(url)
#         permissions = response.headers.get('Permissions-Policy')
#         return classify_risk("Permissions-Policy", permissions)
#     except Exception as e:
#         return f"Error: {e}"

# def check_expect_ct(url):
#     try:
#         response = requests.get(url)
#         expect_ct = response.headers.get('Expect-CT')
#         return classify_risk("Expect-CT", expect_ct)
#     except Exception as e:
#         return f"Error: {e}"

# def check_cache_control(url):
#     try:
#         response = requests.get(url)
#         cache_control = response.headers.get('Cache-Control')
#         return classify_risk("Cache-Control", cache_control)
#     except Exception as e:
#         return f"Error: {e}"

# if __name__ == "__main__":
#     url = input("Enter the URL to check: ")
#     print(check_hsts(url))
#     print(check_csp(url))
#     print(check_x_content_type_options(url))
#     print(check_x_frame_options(url))
#     print(check_x_xss_protection(url))
#     print(check_referrer_policy(url))
#     print(check_permissions_policy(url))
#     print(check_expect_ct(url))
#     print(check_cache_control(url))

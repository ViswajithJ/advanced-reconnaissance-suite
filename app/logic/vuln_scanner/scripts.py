def no_header(header_name):
	return {
		"Risk Level": "HIGH RISK",
		"Info": f"{header_name} header is missing"
	}

def check_hsts(headers):
	header_name = "Strict-Transport-Security"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	# hsts_result_dict = {}
	if "max-age" in header:
		max_age = int(header.split('=')[1].split(';')[0])
		if max_age < 31536000:
			return {
				"Risk Level":"MEDIUM RISK",
				"Info": f"{header_name} is present. Short max-age, consider a longer value (e.g., 1 year)"
			}
			# return f"{header_name} - {MEDIUM_RISK}: Short max-age, consider a longer value (e.g., 1 year). Vulnerability: Insecure HTTP Response (SSL Stripping)."
		return {
			"Risk Level":"LOW RISK",
			"Info": f"{header_name} is present. Max-age is well configured."
		}
		# return f"{header_name} - {LOW_RISK}: Max-age is well configured. Vulnerability: Insecure HTTP Response (SSL Stripping)."
	return {
		"Risk Level":"HIGH RISK",
		"Info": f"{header_name} is present. But missing max-age or misconfigured."
	}
	# return f"{header_name} - {HIGH_RISK}: . Vulnerability: Insecure HTTP Response (SSL Stripping)."

def check_xss(headers):
	header_name = "Content-Security-Policy"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if "default-src" not in header:
		return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present. But missing default-src directive"
		}
		# return f"{header_name} - {HIGH_RISK}: . Vulnerability: Cross-Site Scripting (XSS)."
	if "unsafe-inline" in header:
		return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present. Contains unsafe-inline in script-src"
		}
		# return f"{header_name} - {HIGH_RISK}: Contains unsafe-inline in script-src, highly risky. Vulnerability: Cross-Site Scripting (XSS)."
	return {
		"Risk Level":"LOW RISK",
		"Info": f"{header_name} is present and has safe configurations."
	}
	# return f"{header_name} - {LOW_RISK}: CSP header is present and has safe configuration. Vulnerability: Cross-Site Scripting (XSS)."

def check_mimetype_sniff(headers):
	header_name = "X-Content-Type-Options"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if header.lower() == "nosniff":
		return {
			"Risk Level":"LOW RISK",
			"Info": f"{header_name} is present and has safe configurations."
		}
		# return f"{header_name} - {LOW_RISK}: Properly configured. Vulnerability: MIME-Type Sniffing Attack."
	return {
		"Risk Level":"HIGH RISK",
		"Info": f"{header_name} is present but not configured properly."
	}
	# return f"{header_name} - {HIGH_RISK}: Not configured properly. Vulnerability: MIME-Type Sniffing Attack."

def check_clickjacking(headers):
	header_name = "X-Frame-Options"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if header == "DENY":
		return {
			"Risk Level":"LOW RISK",
			"Info": f"{header_name} is present and has safe configurations."
		}
		# return f"{header_name} - {LOW_RISK}: Properly configured. Vulnerability: Clickjacking."
	if header == "SAMEORIGIN":
		return {
			"Risk Level":"MEDIUM RISK",
			"Info": f"{header_name} is present. SAMEORIGIN is fine but not as secure as DENY."
		}
		# return f"{header_name} - {MEDIUM_RISK}: Same-origin is fine, but 'DENY' is more secure. Vulnerability: Clickjacking."
	return {
		"Risk Level":"HIGH RISK",
		"Info": f"{header_name} is present but misconfigured."
	}
	# return f"{header_name} - {HIGH_RISK}: Not set or misconfigured. Vulnerability: Clickjacking."

def check_reflected_xss(headers):
	header_name = "X-XSS-Protection"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if header == "1; mode=block":
		return {
			"Risk Level":"LOW RISK",
			"Info": f"{header_name} is present and has safe configurations."
		}
			# return f"{header_name} - {LOW_RISK}: Properly configured. Vulnerability: Cross-Site Scripting (XSS)."
	return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present but not configured or set incorrectly."
		}
		# return f"{header_name} - {HIGH_RISK}: Not configured or set incorrectly. Vulnerability: Cross-Site Scripting (XSS)."


def check_infoleak_referrer(headers):
	header_name = "Referrer-Policy"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if header == "no-referrer":
		return {
			"Risk Level":"LOW RISK",
			"Info": f"{header_name} is present and has safe configurations."
		}
		# return f"{header_name} - {LOW_RISK}: Properly configured for privacy. Vulnerability: Information Leakage via Referrer Header."
	if "unsafe-url" in header:
		return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present but unsafe-url could leak private info."
		}
		# return f"{header_name} - {HIGH_RISK}: unsafe-url is risky, could leak private information. Vulnerability: Information Leakage via Referrer Header."
	return {
			"Risk Level":"MEDIUM RISK",
			"Info": f"{header_name} is present but needs review."
		}
	# return f"{header_name} - {MEDIUM_RISK}: Referrer policy set, but needs review. Vulnerability: Information Leakage via Referrer Header."


def check_permissions(headers):
	header_name = "Permissions-Policy"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if header == "*":
		return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present but allowing all permissions."
		}
		# 	return f"{header_name} - {HIGH_RISK}: Allowing all features is risky. Vulnerability: Privilege Escalation via Excessive Permissions."
	return {
		"Risk Level":"LOW RISK",
		"Info": f"{header_name} is present and has safe configurations."
	}
		# return f"{header_name} - {LOW_RISK}: Permissions-Policy is set. Vulnerability: Privilege Escalation via Excessive Permissions."


def check_cert_transparency(headers):
	header_name = "Expect-CT"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if header:
		return {
			"Risk Level":"LOW RISK",
			"Info": f"{header_name} is present and has safe configurations."
		}
	return {
		"Risk Level":"HIGH RISK",
		"Info": f"{header_name} is missing or misconfigured"
	}	
	# 	return f"{header_name} - {LOW_RISK}: Properly configured. Vulnerability: Certificate Spoofing (via man-in-the-middle attacks)."
	# return f"{header_name} - {HIGH_RISK}: Missing or misconfigured. Vulnerability: Certificate Spoofing (via man-in-the-middle attacks)."

def check_cache_control(headers):
	header_name = "Cache-Control"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if "no-store" in header:
		return {
			"Risk Level":"LOW RISK",
			"Info": f"{header_name} is present and avoids caching private data."
		}
	if "public" in header:
		return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present but set to public caching."
		}
			# return f"{header_name} - {LOW_RISK}: Properly configured to avoid caching sensitive data. Vulnerability: Caching of Sensitive Information."
	return {
		"Risk Level":"MEDIUM RISK",
		"Info": f"{header_name} is present and configured but no-store is recommended for sensitive data."
	}
		# return f"{header_name} - {MEDIUM_RISK}: Cache-Control is configured, but 'no-store' is recommended for sensitive data. Vulnerability: Caching of Sensitive Information."

def check_cors(headers):
	header_name = "Access-Control-Allow-Origin"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if header == "*":
		return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present but allow from all origins."
		}
	return {
		"Risk Level":"MEDIUM RISK",
		"Info": f"{header_name} is present but needs review of origins provided."
	}

def check_insecure_mixed_content(headers):
	header_name = "Content-Security-Policy"
	header = headers.get(header_name)
	if header is None:
		return no_header(header_name)
	if "block-all-mixed-content" not in header:
		return {
			"Risk Level":"MEDIUM RISK",
			"Info": f"{header_name} is present but doesn't block mixed content."
		}
	return {
		"Risk Level":"LOW RISK",
		"Info": f"{header_name} is present and blocks all mixed content."
	}





# def check_clickjacking_vulnerability(headers):
# 	if "x-frame-options" not in headers or (
# 		headers["x-frame-options"] != "DENY"
# 		and headers["x-frame-options"] != "SAMEORIGIN"
# 	):
# 		return {
# 			"name": "Clickjacking",
# 			"description": "Missing or misconfigured X-Frame-Options header.",
# 			"risk": "Medium",
# 			"evidence": "X-Frame-Options header is not set to DENY or SAMEORIGIN.",
# 		}
# 	return {
# 		"name": "Clickjacking",
# 		"description": "No Clickjacking vulnerability detected.",
# 		"risk": "None",
# 		"evidence": "X-Frame-Options header is properly configured.",
# 	}


# def check_insecure_mixed_content(headers):
# 	if (
# 		"content-security-policy" in headers
# 		and "block-all-mixed-content" not in headers["content-security-policy"]
# 	):
# 		return {
# 			"name": "Insecure Mixed Content",
# 			"description": "Missing or misconfigured Content-Security-Policy header to block all mixed content.",
# 			"risk": "Medium",
# 			"evidence": "Content-Security-Policy header does not contain block-all-mixed-content directive.",
# 		}
# 	return {
# 		"name": "Insecure Mixed Content",
# 		"description": "No Insecure Mixed Content vulnerability detected.",
# 		"risk": "None",
# 		"evidence": "Content-Security-Policy header is properly configured.",
# 	}


# def check_cors_vulnerability(headers):
# 	if (
# 		"access-control-allow-origin" in headers
# 		and headers["access-control-allow-origin"] != "*"
# 	):
# 		return {
# 			"name": "CORS",
# 			"description": "Potentially misconfigured Access-Control-Allow-Origin header.",
# 			"risk": "Medium",
# 			"evidence": "Access-Control-Allow-Origin header is set to a specific domain instead of wildcard.",
# 		}
# 	return {
# 		"name": "CORS",
# 		"description": "No CORS vulnerability detected.",
# 		"risk": "None",
# 		"evidence": "Access-Control-Allow-Origin header is properly configured.",
# 	}


# def check_hsts_vulnerability(headers):
# 	if (
# 		"strict-transport-security" not in headers
# 		or "includeSubDomains" not in headers["strict-transport-security"]
# 	):
# 		return {
# 			"name": "HSTS",
# 			"description": "Missing or misconfigured Strict-Transport-Security header with includeSubDomains directive.",
# 			"risk": "High",
# 			"evidence": "Strict-Transport-Security header does not include includeSubDomains directive.",
# 		}
# 	return {
# 		"name": "HSTS",
# 		"description": "No HSTS vulnerability detected.",
# 		"risk": "None",
# 		"evidence": "Strict-Transport-Security header is properly configured.",
# 	}


# def check_reflected_xss_vulnerability(headers):
# 	if (
# 		"x-xss-protection" not in headers
# 		or headers["x-xss-protection"] != "1; mode=block"
# 	):
# 		return {
# 			"name": "Reflected XSS",
# 			"description": "Missing or misconfigured X-XSS-Protection header.",
# 			"risk": "High",
# 			"evidence": "X-XSS-Protection header is not set to 1; mode=block.",
# 		}
# 	return {
# 		"name": "Reflected XSS",
# 		"description": "No Reflected XSS vulnerability detected.",
# 		"risk": "None",
# 		"evidence": "X-XSS-Protection header is properly configured.",
# 	}


# def check_server_info_vulnerability(headers):
# 	if "server" in headers or "x-powered-by" in headers or "via" in headers:
# 		return {
# 			"name": "Server Information Leakage",
# 			"description": "Presence of Server, X-Powered-By, or Via headers.",
# 			"risk": "Low",
# 			"evidence": "Server, X-Powered-By, or Via headers are present in the response.",
# 		}
# 	return {
# 		"name": "Server Information Leakage",
# 		"description": "No Server Information Leakage vulnerability detected.",
# 		"risk": "None",
# 		"evidence": "Server, X-Powered-By, and Via headers are not present in the response.",
# 	}


# def check_xss_vulnerability(headers):
# 	if "content-security-policy" in headers:
# 		csp_header = headers["content-security-policy"]
# 		if "script-src" not in csp_header:
# 			return {
# 				"name": "Cross-site Scripting (XSS)",
# 				"description": "Missing or misconfigured Content-Security-Policy header for script-src.",
# 				"risk": "High",
# 				"evidence": "Content-Security-Policy header does not contain script-src directive.",
# 			}
# 	return {
# 		"name": "Cross-site Scripting (XSS)",
# 		"description": "No XSS vulnerability detected.",
# 		"risk": "None",
# 		"evidence": "Content-Security-Policy header is properly configured.",
# 	}


# def check_cache_control_vulnerability(headers):
# 	if "cache-control" not in headers or (
# 		"no-store" not in headers["cache-control"]
# 		and "no-cache" not in headers["cache-control"]
# 	):
# 		return {
# 			"name": "Cache Control",
# 			"description": "Missing or misconfigured Cache-Control header with no-store or no-cache directives.",
# 			"risk": "Medium",
# 			"evidence": "Cache-Control header does not include no-store or no-cache directives.",
# 		}
# 	return {
# 		"name": "Cache Control",
# 		"description": "No Cache Control vulnerability detected.",
# 		"risk": "None",
# 		"evidence": "Cache-Control header is properly configured.",
# 	}


# def check_cache_poisoning_vulnerability(headers):
	# if "cache-control" in headers and "public" in headers["cache-control"]:
	# 	return {
	# 		"name": "Cache Poisoning",
	# 		"description": "Potentially misconfigured Cache-Control header allowing public caching.",
	# 		"risk": "High",
	# 		"evidence": 'Cache-Control header includes "public" directive.',
	# 	}
	# return {
	# 	"name": "Cache Poisoning",
	# 	"description": "No Cache Poisoning vulnerability detected.",
	# 	"risk": "None",
	# 	"evidence": "Cache-Control header is properly configured.",
	# }


# # Risk Classification Constants
# HIGH_RISK = "HIGH"
# MEDIUM_RISK = "MEDIUM"
# LOW_RISK = "LOW"

# def classify_risk(header_name, value, vulnerability):
# 
# 
# 	# If the header is missing entirely
# 	if value is None:
# 		return f"{header_name} Header Missing! - {HIGH_RISK}. Vulnerability: {vulnerability}"

# 	# Checks for specific headers and configurations
# 	if header_name == "Strict-Transport-Security":
# 		if "max-age" in value:
# 			max_age = int(value.split('=')[1].split(';')[0])
# 			if max_age < 31536000:
# 				return f"{header_name} - {MEDIUM_RISK}: Short max-age, consider a longer value (e.g., 1 year). Vulnerability: Insecure HTTP Response (SSL Stripping)."
# 			return f"{header_name} - {LOW_RISK}: Max-age is well configured. Vulnerability: Insecure HTTP Response (SSL Stripping)."
# 		return f"{header_name} - {HIGH_RISK}: Missing max-age or misconfigured. Vulnerability: Insecure HTTP Response (SSL Stripping)."

# 	if header_name == "Content-Security-Policy":
# 		# Basic check for missing directives
# 		if "default-src" not in value:
# 			return f"{header_name} - {HIGH_RISK}: Missing default-src directive. Vulnerability: Cross-Site Scripting (XSS)."
# 		if "unsafe-inline" in value:
# 			return f"{header_name} - {HIGH_RISK}: Contains unsafe-inline in script-src, highly risky. Vulnerability: Cross-Site Scripting (XSS)."
# 		return f"{header_name} - {LOW_RISK}: CSP header is present and has safe configuration. Vulnerability: Cross-Site Scripting (XSS)."

# 	if header_name == "X-Content-Type-Options":
# 		if value.lower() == "nosniff":
# 			return f"{header_name} - {LOW_RISK}: Properly configured. Vulnerability: MIME-Type Sniffing Attack."
# 		return f"{header_name} - {HIGH_RISK}: Not configured properly. Vulnerability: MIME-Type Sniffing Attack."

# 	if header_name == "X-Frame-Options":
# 		if value == "DENY":
# 			return f"{header_name} - {LOW_RISK}: Properly configured. Vulnerability: Clickjacking."
# 		if value == "SAMEORIGIN":
# 			return f"{header_name} - {MEDIUM_RISK}: Same-origin is fine, but 'DENY' is more secure. Vulnerability: Clickjacking."
# 		return f"{header_name} - {HIGH_RISK}: Not set or misconfigured. Vulnerability: Clickjacking."

# 	if header_name == "X-XSS-Protection":
# 		if value == "1; mode=block":
# 			return f"{header_name} - {LOW_RISK}: Properly configured. Vulnerability: Cross-Site Scripting (XSS)."
# 		return f"{header_name} - {HIGH_RISK}: Not configured or set incorrectly. Vulnerability: Cross-Site Scripting (XSS)."

# 	if header_name == "Referrer-Policy":
# 		if value == "no-referrer":
# 			return f"{header_name} - {LOW_RISK}: Properly configured for privacy. Vulnerability: Information Leakage via Referrer Header."
# 		if "unsafe-url" in value:
# 			return f"{header_name} - {HIGH_RISK}: unsafe-url is risky, could leak private information. Vulnerability: Information Leakage via Referrer Header."
# 		return f"{header_name} - {MEDIUM_RISK}: Referrer policy set, but needs review. Vulnerability: Information Leakage via Referrer Header."

# 	if header_name == "Permissions-Policy":
# 		if value == "*":
# 			return f"{header_name} - {HIGH_RISK}: Allowing all features is risky. Vulnerability: Privilege Escalation via Excessive Permissions."
# 		return f"{header_name} - {LOW_RISK}: Permissions-Policy is set. Vulnerability: Privilege Escalation via Excessive Permissions."

# 	if header_name == "Expect-CT":
# 		if value:
# 			return f"{header_name} - {LOW_RISK}: Properly configured. Vulnerability: Certificate Spoofing (via man-in-the-middle attacks)."
# 		return f"{header_name} - {HIGH_RISK}: Missing or misconfigured. Vulnerability: Certificate Spoofing (via man-in-the-middle attacks)."

# 	if header_name == "Cache-Control":
# 		if "no-store" in value:
# 			return f"{header_name} - {LOW_RISK}: Properly configured to avoid caching sensitive data. Vulnerability: Caching of Sensitive Information."
# 		return f"{header_name} - {MEDIUM_RISK}: Cache-Control is configured, but 'no-store' is recommended for sensitive data. Vulnerability: Caching of Sensitive Information."
# 	return f"{header_name} - {LOW_RISK}: Header is present, but no specific concerns. Vulnerability: {vulnerability}"

# def check_hsts(url):
# 	try:
# 		hsts = response.headers.get('Strict-Transport-Security')
# 		return classify_risk("Strict-Transport-Security", hsts, "Insecure HTTP Response (SSL Stripping)")
# 	except Exception as e:
# 		return f"Error: {e}"

# def check_csp(url):
# 	try:
# 		csp = response.headers.get('Content-Security-Policy')
# 		return classify_risk("Content-Security-Policy", csp, "Cross-Site Scripting (XSS)")
# 	except Exception as e:
# 		return f"Error: {e}"

# def check_x_content_type_options(url):
# 	try:
# 		x_content_type = response.headers.get('X-Content-Type-Options')
# 		return classify_risk("X-Content-Type-Options", x_content_type, "MIME-Type Sniffing Attack")
# 	except Exception as e:
# 		return f"Error: {e}"

# def check_x_frame_options(url):
# 	try:
# 		x_frame = response.headers.get('X-Frame-Options')
# 		return classify_risk("X-Frame-Options", x_frame, "Clickjacking")
# 	except Exception as e:
# 		return f"Error: {e}"

# def check_x_xss_protection(url):
# 	try:
# 		x_xss = response.headers.get('X-XSS-Protection')
# 		return classify_risk("X-XSS-Protection", x_xss, "Cross-Site Scripting (XSS)")
# 	except Exception as e:
# 		return f"Error: {e}"

# def check_referrer_policy(url):
# 	try:
# 		referrer = response.headers.get('Referrer-Policy')
# 		return classify_risk("Referrer-Policy", referrer, "Information Leakage via Referrer Header")
# 	except Exception as e:
# 		return f"Error: {e}"

# def check_permissions_policy(url):
# 	try:
# 		permissions = response.headers.get('Permissions-Policy')
# 		return classify_risk("Permissions-Policy", permissions, "Privilege Escalation via Excessive Permissions")
# 	except Exception as e:
# 		return f"Error: {e}"

# def check_expect_ct(url):
# 	try:
# 		expect_ct = response.headers.get('Expect-CT')
# 		return classify_risk("Expect-CT", expect_ct, "Certificate Spoofing (via man-in-the-middle attacks)")
# 	except Exception as e:
# 		return f"Error: {e}"

# def check_cache_control(url):
# 	try:
# 		cache_control = response.headers.get('Cache-Control')
# 		return classify_risk("Cache-Control", cache_control, "Caching of Sensitive Information")
# 	except Exception as e:
# 		return f"Error: {e}"

# if __name__ == "__main__":
# 	url = input("Enter the URL to check: ")
# 	print(check_hsts(url))
# 	print(check_csp(url))
# 	print(check_x_content_type_options(url))
# 	print(check_x_frame_options(url))
# 	print(check_x_xss_protection(url))
# 	print(check_referrer_policy(url))
# 	print(check_permissions_policy(url))
# 	print(check_expect_ct(url))
# 	print(check_cache_control(url))
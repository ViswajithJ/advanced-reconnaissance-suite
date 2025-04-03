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
	if "max-age" in header:
		max_age = int(header.split('=')[1].split(';')[0])
		if max_age < 31536000:
			return {
				"Risk Level":"MEDIUM RISK",
				"Info": f"{header_name} is present. Short max-age, consider a longer value (e.g., 1 year)"
			}
		return {
			"Risk Level":"LOW RISK",
			"Info": f"{header_name} is present. Max-age is well configured."
		}
	return {
		"Risk Level":"HIGH RISK",
		"Info": f"{header_name} is present. But missing max-age or misconfigured."
	}

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
	if "unsafe-inline" in header:
		return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present. Contains unsafe-inline in script-src"
		}
	return {
		"Risk Level":"LOW RISK",
		"Info": f"{header_name} is present and has safe configurations."
	}

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
	return {
		"Risk Level":"HIGH RISK",
		"Info": f"{header_name} is present but not configured properly."
	}

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
	if header == "SAMEORIGIN":
		return {
			"Risk Level":"MEDIUM RISK",
			"Info": f"{header_name} is present. SAMEORIGIN is fine but not as secure as DENY."
		}
	return {
		"Risk Level":"HIGH RISK",
		"Info": f"{header_name} is present but misconfigured."
	}

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
	return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present but not configured or set incorrectly."
		}


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
	if "unsafe-url" in header:
		return {
			"Risk Level":"HIGH RISK",
			"Info": f"{header_name} is present but unsafe-url could leak private info."
		}
	return {
			"Risk Level":"MEDIUM RISK",
			"Info": f"{header_name} is present but needs review."
		}


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
	return {
		"Risk Level":"LOW RISK",
		"Info": f"{header_name} is present and has safe configurations."
	}


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
	return {
		"Risk Level":"MEDIUM RISK",
		"Info": f"{header_name} is present and configured but no-store is recommended for sensitive data."
	}

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


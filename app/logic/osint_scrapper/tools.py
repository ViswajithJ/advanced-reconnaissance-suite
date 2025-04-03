import requests
import socket
import whois
import ssl
import datetime


def get_server_status(domain):
	res = requests.get(f"https://{domain}/")
	if res.status_code == 200:
		return "Server is Up"
	else:
		return "Server is Down"


def get_ip(domain):

	ip = socket.gethostbyname(domain)
	return ip


def get_location(domain):

	ip = get_ip(domain)
	response = requests.get(f"https://ipapi.co/{ip}/json/").json()
	location_dict = {
		"City": response.get("city"),
		"Region": response.get("region"),
		"Country": response.get("country_name"),
		"PIN": response.get("postal"),
		"Latitude": response.get("latitude"),
		"Longitude": response.get("longitude"),
	}
	return location_dict

def get_whois(domain):

	whois_data = whois.whois(domain)
	whois_dict = {
		"Domain Registrar": whois_data.registrar,
		"Creation Date": whois_data.creation_date[0].strftime("%Y-%m-%d %H:%M:%S %Z") if isinstance(whois_data.creation_date, list) else whois_data.creation_date.strftime("%Y-%m-%d %H:%M:%S %Z"),
		"Expiration Date": whois_data.expiration_date[0].strftime("%Y-%m-%d %H:%M:%S %Z") if isinstance(whois_data.expiration_date, list) else whois_data.expiration_date.strftime("%Y-%m-%d %H:%M:%S %Z"),
		"Name Servers": whois_data.name_servers,
		"Emails": whois_data.emails,
		"Address": [whois_data.address, whois_data.city, whois_data.country],
	}
	
	return whois_dict


def get_cookies(domain):

	response = requests.get(f"https://{domain}/")
	cookies = response.cookies

	# print("\nCookie Details\n")
	cookie_dict = {}
	for cookie in cookies:
		cookie_dict[cookie.name] = cookie.value
	return cookie_dict


def get_headers(domain):

	response = requests.get(f"https://{domain}/")
	headers = response.headers
	headers_dict = {}
	for i in headers:
		headers_dict[i] = headers[i]
	return headers_dict


def get_ssl_certificate_info(host, port=443):
	try:
		context = ssl.create_default_context()
		with socket.create_connection((host, port)) as sock:
			with context.wrap_socket(sock, server_hostname=host) as ssock:
				cert = ssock.getpeercert()

	except Exception as e:
		print(
			"""
			"Issuer": "N/A",
			"Subject": "N/A",
			"Expiry Date": "N/A",
		"""
		)
	ssl_cert_dict = {}
	ssl_cert_dict["Issuer"] = dict(x[0] for x in cert.get("issuer"))

	ssl_cert_dict["Subject"] = dict(x[0] for x in cert.get("subject"))
	ssl_cert_dict["Expiry Date"] = cert.get("notAfter")
	return ssl_cert_dict


def get_firewall_info(domain):

	try:
		headers = requests.get(f"https://{domain}/").headers

		firewall_dict = {}
		if headers.get("Server"):
			if "cloudflare" in headers.get("Server"):
				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "CloudFlare"
			if "akamaighost" in headers.get("Server"):

				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "Akamai"
			if "sucuri" in headers.get("Server"):
				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "Sucuri"
			if "barracudawaf" in headers.get("Server"):
				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "Barracuda WAF"
			if "f5 big-ip" in headers.get("Server") or "big-ip" in headers.get(
				"Server"
			):
				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "F5 BIG-IP"
			if "imperva" in headers.get("Server"):
				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "Imperva SecureSphere WAF"
			if "fortiweb" in headers.get("Server"):

				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "Fortinet FortiWeb WAF"
			if "yundun" in headers.get("Server"):

				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "Yundun WAF"
			if "safe3waf" in headers.get("Server"):

				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "Safe3 Web Application Firewall"
			if "naxsi" in headers.get("Server"):

				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "NAXSI WAF"
			if "qrator" in headers.get("Server"):

				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "QRATOR WAF"
			if "ddos-guard" in headers.get("Server"):

				firewall_dict["Status"] = "Yes"
				firewall_dict["Provider"] = "DDoS-Guard WAF"

		if headers.get("x-powered-by") and "aws lambda" in headers.get("x-powered-by"):
			firewall_dict["Status"] = "Yes"
			firewall_dict["Provider"] = "AWS WAF"
		if headers.get("x-protected-by") and "sqreen" in headers.get("x-protected-by"):
			firewall_dict["Status"] = "Yes"
			firewall_dict["Provider"] = "Sqreen WAF"

		if headers.get("x-sucuri-id") or headers.get("x-sucuri-cache"):
			firewall_dict["Status"] = "Yes"
			firewall_dict["Provider"] = "Sucuri CloudProxy WAF"

		if headers.get("x-waf-event-info"):
			firewall_dict["Status"] = "Yes"
			firewall_dict["Provider"] = "Reblaze WAF"

		if headers.get("set-cookie") and "_citrix_ns_id" in headers.get("set-cookie"):
			firewall_dict["Status"] = "Yes"
			firewall_dict["Provider"] = "Citrix NetScaler WAF"

		if headers.get("x-webcoment"):
			firewall_dict["Status"] = "Yes"
			firewall_dict["Provider"] = "Webcoment Firewall"

		if headers.get("x-yd-waf-info") or headers.get("x-yd-info"):
			firewall_dict["Status"] = "Yes"
			firewall_dict["Provider"] = "Yundun WAF"

		if headers.get("x-datapower-transactionid"):
			firewall_dict["Status"] = "Yes"
			firewall_dict["Provider"] = "IBM WebSphere DataPower"
	except Exception as e:
		print(e)
	finally:
		return firewall_dict

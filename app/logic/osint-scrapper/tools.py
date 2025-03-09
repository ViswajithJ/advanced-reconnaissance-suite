import requests
import socket
import whois
import ssl


def get_ip(domain):

    ip = socket.gethostbyname(domain)
    return ip


def get_location(domain):

    ip = get_ip(domain)
    response = requests.get(f"https://ipapi.co/{ip}/json/").json()
    # print("\nServer Location Details\n")
    # print(
    #     "ip : ",
    #     ip,
    #     "\ncity : ",
    #     response.get("city"),
    #     "\nregion : ",
    #     response.get("region"),
    #     "\ncountry : ",
    #     response.get("country_name"),
    #     "\npin : ",
    #     response.get("postal"),
    #     "\nlatitude : ",
    #     response.get("latitude"),
    #     "\nlongitude : ",
    #     response.get("longitude"),
    # ) use just these data from the returned json, at frontend


def get_whois(domain):

    whois_data = whois.whois(domain)
    # whois_info = {
    #     "domain_name": whois_data.domain_name,
    #     "registrar": whois_data.registrar,
    #     "creation_date": whois_data.creation_date,
    #     "expiration_date": whois_data.expiration_date,
    #     "name_servers": whois_data.name_servers,
    #     "emails": whois_data.emails,
    #     "address": whois_data.address
    #     + " "
    #     + whois_data.city
    #     + " "
    #     + whois_data.country,
    # }
    # print("\nDomain Details\n")

    # print(
    #     "domain_name : ",
    #     whois_data.domain_name,
    #     "\nregistrar : ",
    #     whois_data.registrar,
    #     "\ncreation_date : ",
    #     whois_data.creation_date,
    #     "\nexpiration_date : ",
    #     whois_data.expiration_date,
    #     "\nname_servers : ",
    #     whois_data.name_servers,
    #     "\nemails : ",
    #     whois_data.emails,
    #     "\naddress : ",
    #     whois_data.address,
    #     ", ",
    #     whois_data.city,
    #     ", ",
    #     whois_data.country,
    # ) use just these data from the returned json, at frontend
    print(type(whois_data))

get_whois('google.com')
def get_cookies(domain):

    response = requests.get(f"https://{domain}/")
    cookies = response.cookies

    # print("\nCookie Details\n")
    for cookie in cookies:
        print(cookie.name, " : ", cookie.value)


def get_headers(domain):

    response = requests.get(f"https://{domain}/")
    # print(response)
    # print("\nBasic Http Headers\n")
    for i in list(response.headers):
        print(i, "\t\t: ", response.headers[i])


def get_ssl_certificate_info(host, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port)) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                print(
                    f"""
					"Issuer": {cert.get("issuer")},
					"Subject": {cert.get("subject")},
					"Expiry Date": {cert.get("notAfter")},
				"""
                )
    except Exception as e:
        print(
            """
			"Issuer": "N/A",
			"Subject": "N/A",
			"Expiry Date": "N/A",
		"""
        )


def get_firewall_info(domain):
    headers = requests.get(f"https://{domain}/").headers

    if headers.get("Server"):
        if "cloudflare" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: CloudFlare")
        if "akamaighost" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: Akamai")
        if "sucuri" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: Sucuri")
        if "barracudawaf" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: Barracuda WAF")
        if "f5 big-ip" in headers.get("Server") or "big-ip" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: F5 BIG-IP")
        if "imperva" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: Imperva SecureSphere WAF")
        if "fortiweb" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: Fortinet FortiWeb WAF")
        if "yundun" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: Yundun WAF")
        if "safe3waf" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: Safe3 Web Application Firewall")
        if "naxsi" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: NAXSI WAF")
        if "qrator" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: QRATOR WAF")
        if "ddos-guard" in headers.get("Server"):
            print("Firewall: Yes")
            print("Provider: DDoS-Guard WAF")

    if headers.get("x-powered-by") and "aws lambda" in headers.get("x-powered-by"):
        print("Firewall: Yes")
        print("Provider: AWS WAF")
    if headers.get("x-protected-by") and "sqreen" in headers.get("x-protected-by"):
        print("Firewall: Yes")
        print("Provider: Sqreen WAF")

    if headers.get("x-sucuri-id") or headers.get("x-sucuri-cache"):
        print("Firewall: Yes")
        print("Provider: Sucuri CloudProxy WAF")

    if headers.get("x-waf-event-info"):
        print("Firewall: Yes")
        print("Provider: Reblaze WAF")

    if headers.get("set-cookie") and "_citrix_ns_id" in headers.get("set-cookie"):
        print("Firewall: Yes")
        print("Provider: Citrix NetScaler WAF")

    if headers.get("x-webcoment"):
        print("Firewall: Yes")
        print("Provider: Webcoment Firewall")

    if headers.get("x-yd-waf-info") or headers.get("x-yd-info"):
        print("Firewall: Yes")
        print("Provider: Yundun WAF")

    if headers.get("x-datapower-transactionid"):
        print("Firewall: Yes")
        print("Provider: IBM WebSphere DataPower")

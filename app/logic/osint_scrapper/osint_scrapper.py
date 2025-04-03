from app.logic.osint_scrapper.tools import *

options_dict = {
    "Server Status": get_server_status,
    "IP": get_ip,
    "Server Location": get_location,
    "Domain Registration Info": get_whois,
    "Cookies": get_cookies,
    "SSL Certificate Info": get_ssl_certificate_info,
    "Firewall Status": get_firewall_info,
}


def osint_scrape(domain, option_list):
    osint_result = {"Domain": domain}
    for i in option_list:
        osint_result[i] = options_dict[i](domain)
    return osint_result

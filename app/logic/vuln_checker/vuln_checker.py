import requests
from scripts import check_cache_control_vulnerability


def get_headers(domain):

	response = requests.get(f"https://{domain}/")
	# print(response)
	# print("\nBasic Http Headers\n")
	# for i in list(response.headers):
	# 	print(i, "\t\t: ", response.headers[i])
	headers = response.headers
	headers_dict = {}
	for i in headers:
		headers_dict[i.lower()] = headers[i]
	return headers_dict


def vuln_check(domain):
	headers = get_headers(domain)
	print(headers)
	 

domain = input('enter domain: ')
vuln_check(domain)
print(check_cache_control_vulnerability(domain))
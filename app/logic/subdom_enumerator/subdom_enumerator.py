import os
import asyncio
import aiohttp


counter = 1  # Global counter for numbering

async def load_wordlist(wordlist_size):
	try:
		print(wordlist_size)
		cwd=os.getcwd()
		file_path = os.path.join(cwd, f"app/logic/subdom_enumerator/{wordlist_size}.txt")
		print(file_path)
		with open(file_path, 'r') as file:
			return [line.strip() for line in file]
	except FileNotFoundError:
		return []

async def check_subdomain(session, domain, subdomain):
    try:
        url = f"http://{subdomain}.{domain}"
        async with session.head(url, allow_redirects=False, timeout=5) as response:
            return response.status < 400
    except (asyncio.TimeoutError, aiohttp.ClientError):
        return False

async def enumerate_subdomains(domain, wordlist_size):
    wordlist = await load_wordlist(wordlist_size)
    print(wordlist)
    if not wordlist:
        return []

    discovered = set()
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(check_subdomain(session, domain, sub)) for sub in wordlist]
        results = await asyncio.gather(*tasks)

        for subdomain, is_active in zip(wordlist, results):
            if is_active:
                discovered.add(f"{subdomain}.{domain}")

    return list(discovered)

async def enumerate_recursive_subdomains(domain, wordlist_size, parent_sub, depth, max_depth):
    if depth >= max_depth:
        return []
    
    wordlist = await load_wordlist(wordlist_size)
    if not wordlist:
        return []

    sub_list = []
    async with aiohttp.ClientSession() as session:
        tasks = [asyncio.create_task(check_subdomain(session, domain, f"{sub}.{parent_sub}")) for sub in wordlist]
        results = await asyncio.gather(*tasks)

        valid_subs = set(f"{sub}.{parent_sub}" for sub, is_active in zip(wordlist, results) if is_active)
        
        sub_dict = {}
        for sub in valid_subs:
            deeper_subs = await enumerate_recursive_subdomains(domain, wordlist_size, sub, depth + 1, max_depth)
            if deeper_subs:
                sub_dict[sub] = deeper_subs
            else:
                sub_list.append(sub)
        
        if sub_dict:
            sub_list.append(sub_dict)
    
    return sub_list

async def run_subdomain_scan(domain, wordlist_size, show_recursive=False, max_depth=1):
    subdomains = await enumerate_subdomains(domain, wordlist_size)
    output_file = "output.json"
    
    if not subdomains:
        # with open(output_file, "w") as file:
        #     json.dump([], file, indent=4)
        return []
    
    if show_recursive:
        recursive_results = []
        for sub in subdomains:
            recursive_subs = await enumerate_recursive_subdomains(domain, wordlist_size, sub, 0, max_depth)
            if recursive_subs:
                recursive_results.append({sub: recursive_subs})
            else:
                recursive_results.append(sub)
    
        # with open(output_file, "w") as file:
        #     json.dump(recursive_results, file, indent=4)
        return recursive_results
    else:
        # with open(output_file, "w") as file:
        #     json.dump(subdomains, file, indent=4)
        return subdomains

# async def main():
#     domain = input("Enter domain (e.g., example.com): ").strip()
#     wordlist_size = input("Choose difficulty level (easy, medium, difficult): ").strip().lower()
    
#     option = input("Enter option (1: subdomains only, 2: Recursive subdomains with depth): ").strip()
    
#     if option == "2":
#         depth = input("Enter recursive depth (default is 1): ").strip()
#         max_depth = int(depth) if depth.isdigit() else 1
#         await run_subdomain_scan(domain, wordlist_size, show_recursive=True, max_depth=max_depth)
#     else:
#         await run_subdomain_scan(domain, wordlist_size, show_recursive=False)

# if __name__ == "__main__":
#     asyncio.run(main())

##################################


async def main(domain, wordlist_size):
	result = await run_subdomain_scan(domain, wordlist_size, show_recursive=False)
	return result



def subdom_enum(domain, wordlist_size):
	print(domain, wordlist_size)
	result = asyncio.run(main(domain, wordlist_size))
	print(result)
	return result
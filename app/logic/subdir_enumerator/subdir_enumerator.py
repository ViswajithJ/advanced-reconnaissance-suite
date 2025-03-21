
# import asyncio
# import aiohttp
# import os
# import json

# counter = 1  # Global counter for numbering

# async def load_wordlist(wordlist_size):
# 	try:
# 		print(wordlist_size)
# 		print(os.getcwd())
# 		cwd=os.getcwd()
# 		file_path = os.path.join(cwd, f"app/logic/subdir_enumerator/{wordlist_size}.txt")
# 		print(file_path)
# 		with open(file_path, 'r') as file:
# 			return [line.strip() for line in file]
# 	except FileNotFoundError:
# 		return []

# async def check_subdirectory(session, domain, subdirectory):
# 	try:
# 		async with session.head(f"http://{domain}/{subdirectory}", timeout=2) as response:
# 			return response.status < 400
# 	except (asyncio.TimeoutError, aiohttp.ClientError):
# 		return False

# async def enumerate_subdirectories(domain, wordlist_size):
# 	"""Enumerates only top-level subdirectories."""
# 	wordlist = await load_wordlist(wordlist_size)
# 	print(wordlist)
# 	if not wordlist:
# 		return []

# 	discovered = []
# 	async with aiohttp.ClientSession() as session:
# 		tasks = [asyncio.create_task(check_subdirectory(session, domain, sub)) for sub in wordlist]
# 		results = await asyncio.gather(*tasks)

# 		for subdirectory, is_active in zip(wordlist, results):
# 			if is_active:
# 				discovered.append(f"{domain}/{subdirectory}")

# 	return discovered

# async def enumerate_recursive_subdirectories(domain, wordlist_size, parent_dir, depth, max_depth):
# 	"""Enumerates recursive subdirectories up to a given depth."""
# 	if depth >= max_depth:
# 		return []
	
# 	wordlist = await load_wordlist(wordlist_size)
# 	if not wordlist:
# 		return []

# 	sub_list = []
# 	async with aiohttp.ClientSession() as session:
# 		tasks = [asyncio.create_task(check_subdirectory(session, parent_dir, sub)) for sub in wordlist]
# 		results = await asyncio.gather(*tasks)

# 		valid_subs = [f"{parent_dir}/{subdirectory}" for subdirectory, is_active in zip(wordlist, results) if is_active]
		
# 		sub_dict = {}
# 		for sub in valid_subs:
# 			deeper_subs = await enumerate_recursive_subdirectories(domain, wordlist_size, sub, depth + 1, max_depth)
# 			if deeper_subs:
# 				sub_dict[sub] = deeper_subs
# 			else:
# 				sub_list.append(sub)
		
# 		if sub_dict:
# 			sub_list.append(sub_dict)
	
# 	return sub_list

# async def run_subdirectory_scan(domain, wordlist_size, show_recursive=False, max_depth=1):
# 	"""Handles both modes: (1) Only top-level subdirectories (2) Recursive subdirectories with depth."""
# 	subdirectories = await enumerate_subdirectories(domain, wordlist_size)
	
# 	if not subdirectories:
# 		return []
	
# 	if show_recursive:
# 		recursive_results = []
# 		for sub in subdirectories:
# 			recursive_subs = await enumerate_recursive_subdirectories(domain, wordlist_size, sub, 0, max_depth)
# 			if recursive_subs:
# 				recursive_results.append({sub: recursive_subs})
# 			else:
# 				recursive_results.append(sub)
	
# 		return recursive_results
# 	else:
# 		return subdirectories

# async def main(domain, wordlist_size):
# 	# domain = input("Enter domain (e.g., example.com): ").strip()
# 	# wordlist_size = input("Choose difficulty level (easy, medium, difficult): ").strip().lower()
	
# 	# option = input("Enter option (1: Subdirectories only, 2: Recursive subdirectories with depth): ").strip()
	
# 	# if option == "2":
# 	#     depth = input("Enter recursive depth (default is 1): ").strip()
# 	#     max_depth = int(depth) if depth.isdigit() else 1
# 	#     result = await run_subdirectory_scan(domain, wordlist_size, show_recursive=True, max_depth=max_depth)
# 	# else:
# 	result = await run_subdirectory_scan(domain, wordlist_size, show_recursive=False)
# 	return result
	

# def subdir_enum(domain, wordlist_size):
# 	print(domain, wordlist_size)
# 	result = asyncio.run(main(domain, wordlist_size))
# 	print(result)
# 	return result

# # domain = input("Enter domain (e.g., example.com): ").strip()
# # wordlist_size = input("Choose difficulty level (easy, medium, difficult): ").strip().lower()
# # subdir_enum("google.com", "small")


######################## NEW #################################

import asyncio
import aiohttp
import os
import json

counter = 1  # Global counter for numbering

async def load_wordlist(wordlist_size):
	try:
		print(wordlist_size)
		cwd=os.getcwd()
		file_path = os.path.join(cwd, f"app/logic/subdir_enumerator/{wordlist_size}.txt")
		print(file_path)
		with open(file_path, 'r') as file:
			return [line.strip() for line in file]
	except FileNotFoundError:
		return []


async def check_subdirectory(session, domain, subdirectory):
	try:
		async with session.head(f"http://{domain}/{subdirectory}", timeout=2) as response:
			return response.status < 400
	except (asyncio.TimeoutError, aiohttp.ClientError):
		return False
# async def check_subdirectory(session, domain, subdirectory):
#     headers = {"User-Agent": "Mozilla/5.0"}  # Adding a user-agent header
#     url = f"http://{domain}/{subdirectory}"
#     try:
#         async with session.get(url, headers=headers, allow_redirects=False, timeout=5) as response:
#             if response.status < 400 :  # Only count actual existing subdirectories
#                 return True  
#         return False
#         return False

async def enumerate_subdirectories(domain, wordlist_size):
	"""Enumerates only top-level subdirectories."""
	wordlist = await load_wordlist(wordlist_size)
	print(wordlist)
	if not wordlist:
		return []

	discovered = set()  # Use a set to avoid duplicates
	async with aiohttp.ClientSession() as session:
		tasks = [asyncio.create_task(check_subdirectory(session, domain, sub)) for sub in wordlist]
		results = await asyncio.gather(*tasks)

		for subdirectory, is_active in zip(wordlist, results):
			if is_active:
				discovered.add(f"{domain}/{subdirectory}")

	return list(discovered)

async def enumerate_recursive_subdirectories(domain, wordlist_size, parent_dir, depth, max_depth):
	"""Enumerates recursive subdirectories up to a given depth, avoiding redirects."""
	if depth >= max_depth:
		return []
	
	wordlist = await load_wordlist(wordlist_size)
	if not wordlist:
		return []

	sub_list = []
	async with aiohttp.ClientSession() as session:
		tasks = [asyncio.create_task(check_subdirectory(session, parent_dir, sub)) for sub in wordlist]
		results = await asyncio.gather(*tasks)

		valid_subs = set(f"{parent_dir}/{subdirectory}" for subdirectory, is_active in zip(wordlist, results) if is_active)
		
		sub_dict = {}
		for sub in valid_subs:
			deeper_subs = await enumerate_recursive_subdirectories(domain, wordlist_size, sub, depth + 1, max_depth)
			if deeper_subs:
				sub_dict[sub] = deeper_subs
			else:
				sub_list.append(sub)
		
		if sub_dict:
			sub_list.append(sub_dict)
	
	return sub_list

async def run_subdirectory_scan(domain, wordlist_size, show_recursive=False, max_depth=1):
	"""Handles both modes: (1) Only top-level subdirectories (2) Recursive subdirectories with depth."""
	subdirectories = await enumerate_subdirectories(domain, wordlist_size)
	output_file = "output.json"
	
	if not subdirectories:
		# with open(output_file, "w") as file:
		# 	json.dump([], file, indent=4)
		return []
	
	if show_recursive:
		recursive_results = []
		for sub in subdirectories:
			recursive_subs = await enumerate_recursive_subdirectories(domain, wordlist_size, sub, 0, max_depth)
			if recursive_subs:
				recursive_results.append({sub: recursive_subs})
			else:
				recursive_results.append(sub)
	
		# with open(output_file, "w") as file:
		# 	json.dump(recursive_results, file, indent=4)
		return recursive_results
	else:
		# with open(output_file, "w") as file:
		# 	json.dump(subdirectories, file, indent=4)
		return subdirectories

async def main(domain, wordlist_size):
	# domain = input("Enter domain (e.g., example.com): ").strip()
	# wordlist_size = input("Choose difficulty level (easy, medium, difficult): ").strip().lower()
	
	# option = input("Enter option (1: Subdirectories only, 2: Recursive subdirectories with depth): ").strip()
	
	# if option == "2":
	# 	depth = input("Enter recursive depth (default is 1): ").strip()
	# 	max_depth = int(depth) if depth.isdigit() else 1
	# 	await run_subdirectory_scan(domain, wordlist_size, show_recursive=True, max_depth=max_depth)
	# else:
	result = await run_subdirectory_scan(domain, wordlist_size, show_recursive=False)
	return result



def subdir_enum(domain, wordlist_size):
	print(domain, wordlist_size)
	result = asyncio.run(main(domain, wordlist_size))
	print(result)
	return result
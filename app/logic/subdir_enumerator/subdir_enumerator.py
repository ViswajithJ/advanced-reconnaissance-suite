# import asyncio
# import aiohttp
# import json

# counter = 1  # Global counter for numbering

# async def load_wordlist(difficulty_level):
# 	try:
# 		with open(f"{difficulty_level}.txt", 'r') as file:
# 			return [line.strip() for line in file]
# 	# except FileNotFoundError:
# 	except Exception as e:
# 		print(e)
# 		return []

# async def check_subdirectory(session, domain, subdirectory):
# 	try:
# 		async with session.head(f"http://{domain}/{subdirectory}", timeout=2) as response:
# 			return response.status < 400
# 	# except (asyncio.TimeoutError, aiohttp.ClientError):
# 	except Exception as e:
# 		print(e)
# 		return False

# async def enumerate_subdirectories(domain, difficulty_level):
# 	"""Enumerates only top-level subdirectories."""
# 	wordlist = await load_wordlist(difficulty_level)
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

# async def enumerate_recursive_subdirectories(domain, difficulty_level, parent_dir, depth, max_depth):
# 	"""Enumerates recursive subdirectories up to a given depth."""
# 	if depth >= max_depth:
# 		return []
	
# 	wordlist = await load_wordlist(difficulty_level)
# 	if not wordlist:
# 		return []

# 	sub_list = []
# 	async with aiohttp.ClientSession() as session:
# 		tasks = [asyncio.create_task(check_subdirectory(session, parent_dir, sub)) for sub in wordlist]
# 		results = await asyncio.gather(*tasks)

# 		valid_subs = [f"{parent_dir}/{subdirectory}" for subdirectory, is_active in zip(wordlist, results) if is_active]
		
# 		sub_dict = {}
# 		for sub in valid_subs:
# 			deeper_subs = await enumerate_recursive_subdirectories(domain, difficulty_level, sub, depth + 1, max_depth)
# 			if deeper_subs:
# 				sub_dict[sub] = deeper_subs
# 			else:
# 				sub_list.append(sub)
		
# 		if sub_dict:
# 			sub_list.append(sub_dict)
	
# 	return sub_list

# async def run_subdirectory_scan(domain, difficulty_level, show_recursive=False, max_depth=1):
# 	"""Handles both modes: (1) Only top-level subdirectories (2) Recursive subdirectories with depth."""
# 	subdirectories = await enumerate_subdirectories(domain, difficulty_level)
# 	print('inside run_subdir')
# 	if not subdirectories:
# 		return []
	
# 	if show_recursive:
# 		recursive_results = []
# 		for sub in subdirectories:
# 			recursive_subs = await enumerate_recursive_subdirectories(domain, difficulty_level, sub, 0, max_depth)
# 			if recursive_subs:
# 				recursive_results.append({sub: recursive_subs})
# 			else:
# 				recursive_results.append(sub)
	
# 		return recursive_results
# 	else:
# 		return subdirectories

# async def main(domain, wordlist_size):
# 	# domain = input("Enter domain (e.g., example.com): ").strip()
# 	# difficulty_level = input("Choose difficulty level (easy, medium, difficult): ").strip().lower()
	
# 	# option = input("Enter option (1: Subdirectories only, 2: Recursive subdirectories with depth): ").strip()
	
# 	# if option == "2":
# 	#     depth = input("Enter recursive depth (default is 1): ").strip()
# 		# max_depth = int(depth) if depth.isdigit() else 1
# 	#     max_depth = 1 #for temp
# 	#     result = await run_subdirectory_scan(domain, difficulty_level, show_recursive=True, max_depth=max_depth)
# 	# else:
# 	result = await run_subdirectory_scan(domain, wordlist_size, show_recursive=False)
# 	print(result)
# 	return result
	


# def subdir_enum(domain, wordlist_size):
# 	result = asyncio.run(main(domain, wordlist_size))
# 	return result

import asyncio
import aiohttp
import os
import json

counter = 1  # Global counter for numbering

async def load_wordlist(difficulty_level):
	try:
		print(difficulty_level)
		print(os.getcwd())
		cwd=os.getcwd()
		file_path = os.path.join(cwd, f"app/logic/subdir_enumerator/{difficulty_level}.txt")
		print(file_path)
		with open(file_path, 'r') as file:
			print("here")
			return [line.strip() for line in file]
	except FileNotFoundError:
		return []

async def check_subdirectory(session, domain, subdirectory):
	try:
		async with session.head(f"http://{domain}/{subdirectory}", timeout=2) as response:
			return response.status < 400
	except (asyncio.TimeoutError, aiohttp.ClientError):
		return False

async def enumerate_subdirectories(domain, difficulty_level):
	"""Enumerates only top-level subdirectories."""
	wordlist = await load_wordlist(difficulty_level)
	print(wordlist)
	if not wordlist:
		return []

	discovered = []
	async with aiohttp.ClientSession() as session:
		tasks = [asyncio.create_task(check_subdirectory(session, domain, sub)) for sub in wordlist]
		results = await asyncio.gather(*tasks)

		for subdirectory, is_active in zip(wordlist, results):
			if is_active:
				discovered.append(f"{domain}/{subdirectory}")

	return discovered

async def enumerate_recursive_subdirectories(domain, difficulty_level, parent_dir, depth, max_depth):
	"""Enumerates recursive subdirectories up to a given depth."""
	if depth >= max_depth:
		return []
	
	wordlist = await load_wordlist(difficulty_level)
	if not wordlist:
		return []

	sub_list = []
	async with aiohttp.ClientSession() as session:
		tasks = [asyncio.create_task(check_subdirectory(session, parent_dir, sub)) for sub in wordlist]
		results = await asyncio.gather(*tasks)

		valid_subs = [f"{parent_dir}/{subdirectory}" for subdirectory, is_active in zip(wordlist, results) if is_active]
		
		sub_dict = {}
		for sub in valid_subs:
			deeper_subs = await enumerate_recursive_subdirectories(domain, difficulty_level, sub, depth + 1, max_depth)
			if deeper_subs:
				sub_dict[sub] = deeper_subs
			else:
				sub_list.append(sub)
		
		if sub_dict:
			sub_list.append(sub_dict)
	
	return sub_list

async def run_subdirectory_scan(domain, difficulty_level, show_recursive=False, max_depth=1):
	"""Handles both modes: (1) Only top-level subdirectories (2) Recursive subdirectories with depth."""
	subdirectories = await enumerate_subdirectories(domain, difficulty_level)
	
	if not subdirectories:
		return []
	
	if show_recursive:
		recursive_results = []
		for sub in subdirectories:
			recursive_subs = await enumerate_recursive_subdirectories(domain, difficulty_level, sub, 0, max_depth)
			if recursive_subs:
				recursive_results.append({sub: recursive_subs})
			else:
				recursive_results.append(sub)
	
		return recursive_results
	else:
		return subdirectories

async def main(domain, wordlist_size):
	# domain = input("Enter domain (e.g., example.com): ").strip()
	# difficulty_level = input("Choose difficulty level (easy, medium, difficult): ").strip().lower()
	
	# option = input("Enter option (1: Subdirectories only, 2: Recursive subdirectories with depth): ").strip()
	
	# if option == "2":
	#     depth = input("Enter recursive depth (default is 1): ").strip()
	#     max_depth = int(depth) if depth.isdigit() else 1
	#     result = await run_subdirectory_scan(domain, difficulty_level, show_recursive=True, max_depth=max_depth)
	# else:
	result = await run_subdirectory_scan(domain, wordlist_size, show_recursive=False)
	return result
	

def subdir_enum(domain, wordlist_size):
	print(domain, wordlist_size)
	result = asyncio.run(main(domain, wordlist_size))
	print(result)
	return result

# domain = input("Enter domain (e.g., example.com): ").strip()
# wordlist_size = input("Choose difficulty level (easy, medium, difficult): ").strip().lower()
# subdir_enum("google.com", "small")
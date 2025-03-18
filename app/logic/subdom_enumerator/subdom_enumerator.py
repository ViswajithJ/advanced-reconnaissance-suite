import os
import asyncio


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

##################################
# Insert alan's code here
##################################


async def main(domain, wordlist_size):
	result = await run_subdomain_scan(domain, wordlist_size, show_recursive=False)
	return result



def subdom_enum(domain, wordlist_size):
	print(domain, wordlist_size)
	result = asyncio.run(main(domain, wordlist_size))
	print(result)
	return result
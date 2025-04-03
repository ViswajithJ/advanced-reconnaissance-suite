import asyncio
import aiohttp
import os
# import time

counter = 1  # Global counter for numbering


async def load_wordlist(wordlist_size):
    try:
        # print(wordlist_size)
        cwd = os.getcwd()
        file_path = os.path.join(
            cwd, f"app/logic/subdir_enumerator/{wordlist_size}.txt"
        )
        # print(file_path)
        with open(file_path, "r") as file:
            return [line.strip() for line in file]
    except FileNotFoundError:
        return []


async def check_subdirectory(session, domain, subdirectory):
  
    try:
        url = f"https://{domain}/{subdirectory}"
        async with session.get(url, allow_redirects=True, timeout=5) as response:
            status = response.status
            content = await response.text(errors="ignore")  
            if status == 404:
                return False

            # Allow success codes (200-299), but be cautious with redirects
            if 200 <= status < 300:
                return True

            # If redirected, ensure it's not to an error page
            if 300 <= status < 400:
                return False

            return False

    except (asyncio.TimeoutError, aiohttp.ClientError, UnicodeDecodeError):
        return False  # Ensures function does not crash


#
async def enumerate_subdirectories(domain, difficulty_level):
    """Enumerates only top-level subdirectories."""
    wordlist = await load_wordlist(difficulty_level)
    if not wordlist:
        return []
    discovered = set()  # Use a set to avoid duplicates
    semaphore = asyncio.Semaphore(10)  # Limit concurrency to 10 requests

    async with aiohttp.ClientSession() as session:

        async def limited_check(sub):
            async with semaphore:  # Limits concurrency
                return await check_subdirectory(session, domain, sub)

        tasks = [asyncio.create_task(limited_check(sub)) for sub in wordlist]
        results = await asyncio.gather(*tasks)

        for subdirectory, is_active in zip(wordlist, results):
            if is_active:
                discovered.add(f"{domain}/{subdirectory}")

    return list(discovered)


async def enumerate_recursive_subdirectories(
    domain, wordlist_size, parent_dir, depth, max_depth
):
    """Enumerates recursive subdirectories up to a given depth, avoiding redirects."""
    if depth >= max_depth:
        return []

    wordlist = await load_wordlist(wordlist_size)
    if not wordlist:
        return []

    sub_list = []
    async with aiohttp.ClientSession() as session:
        tasks = [
            asyncio.create_task(check_subdirectory(session, parent_dir, sub))
            for sub in wordlist
        ]
        results = await asyncio.gather(*tasks)

        valid_subs = set(
            f"{parent_dir}/{subdirectory}"
            for subdirectory, is_active in zip(wordlist, results)
            if is_active
        )

        sub_dict = {}
        for sub in valid_subs:
            deeper_subs = await enumerate_recursive_subdirectories(
                domain, wordlist_size, sub, depth + 1, max_depth
            )
            if deeper_subs:
                sub_dict[sub] = deeper_subs
            else:
                sub_list.append(sub)

        if sub_dict:
            sub_list.append(sub_dict)

    return sub_list


async def run_subdirectory_scan(
    domain, wordlist_size, show_recursive=False, max_depth=1
):
    """Handles both modes: (1) Only top-level subdirectories (2) Recursive subdirectories with depth."""
    subdirectories = await enumerate_subdirectories(domain, wordlist_size)
    output_file = "output.json"

    if not subdirectories:
        return []

    if show_recursive:
        recursive_results = []
        for sub in subdirectories:
            recursive_subs = await enumerate_recursive_subdirectories(
                domain, wordlist_size, sub, 0, max_depth
            )
            if recursive_subs:
                recursive_results.append({sub: recursive_subs})
            else:
                recursive_results.append(sub)

        return recursive_results
    else:
        return subdirectories


async def main(domain, wordlist_size):
   
    result = await run_subdirectory_scan(domain, wordlist_size, show_recursive=False)
    return result


def subdir_enum(domain, wordlist_size):

    result = asyncio.run(main(domain, wordlist_size))
    return result

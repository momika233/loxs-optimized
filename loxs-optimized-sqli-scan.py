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
    """Return a random User-Agent string."""
    return random.choice(USER_AGENTS)

def get_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 504)):
    """Configure a requests session with retry strategy."""
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
    """Perform an HTTP GET request with the given payload and optional cookie."""
    url_with_payload = f"{url}{payload}"
    headers = {'User-Agent': get_random_user_agent()}
    cookies =  None

    try:
        response = requests.get(url_with_payload, headers=headers, cookies=cookies, timeout=10)
        response.raise_for_status()
        return True, url_with_payload, response.elapsed.total_seconds(), None, response.elapsed.total_seconds() >= 10
    except requests.exceptions.RequestException as e:
        return False, url_with_payload, None, str(e), False

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def get_file_path(prompt_text):
    """Prompt the user for a file path."""
    completer = PathCompleter()
    return prompt(prompt_text, completer=completer).strip()

def prompt_for_urls():
    """Load URLs from a predefined file or prompt the user."""
    try:
        with open('sqli_url.txt', 'r') as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
        if not urls:
            raise FileNotFoundError("No URLs found in the file.")
        return urls
    except FileNotFoundError as e:
        print(f"{Fore.RED}[!] Error: {e}")
        sys.exit(1)

def prompt_for_payloads():
    """Load payloads from a predefined file."""
    try:
        with open('payloads/sqli.txt', 'r') as file:
            payloads = [line.strip() for line in file.readlines() if line.strip()]
        if not payloads:
            raise FileNotFoundError("No payloads found in the file.")
        return payloads
    except FileNotFoundError as e:
        print(f"{Fore.RED}[!] Error: {e}")
        sys.exit(1)

def print_scan_summary(total_found, total_scanned, start_time):
    """Print a summary of the scan."""
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
    """Save scan results to a timestamped file."""
    duration = int(time.time() - start_time)
    formatted_time = datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
    report = (
        f"SQL Injection Scan Report\n"
        f"========================\n"
        f"Total Vulnerabilities Found: {total_found}\n"
        f"Total URLs Scanned: {total_scanned}\n"
        f"Time Taken: {duration} seconds\n\n"
        f"Vulnerable URLs:\n" + '\n'.join(vulnerable_urls) + '\n'
    )
    output_file = f"sqli_vuln_{formatted_time}.txt"
    with open(output_file, 'w') as f:
        f.write(report)
    print(f"{Fore.GREEN}[✓] Report saved to {output_file}")

def main():
    """Main function to execute the SQL injection scanner."""
    clear_screen()

    rich_print(Panel(
        f"""
        [cyan bold]SQL Injection Scanner[/cyan bold]
        [green]Version:[/] [yellow]{VERSION}[/yellow]
        """.strip(),
        style="bold blue",
        border_style="bright_yellow"
    ))

    urls = prompt_for_urls()
    payloads = prompt_for_payloads()
    cookie = None
    threads = 10

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
                pass
                #print(f"{Fore.RED}[✗] Not Vulnerable: {url_with_payload}")
            total_scanned += 1

    print_scan_summary(total_found, total_scanned, start_time)
    save_results(vulnerable_urls, total_found, total_scanned, start_time)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"{Fore.YELLOW}\n[!] Scan interrupted by user.")
        sys.exit(0)

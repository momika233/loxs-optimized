#!/usr/bin/python3

import os
import time
import logging
import asyncio
from urllib.parse import urlsplit, parse_qs, urlencode, urlunsplit
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.common.exceptions import TimeoutException, UnexpectedAlertPresentException
from colorama import Fore
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.chrome.options import Options

# Initialize logging and warnings
logging.getLogger('WDM').setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_payloads(filepath="payloads/xss.txt"):
    try:
        with open(filepath, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading payloads: {e}")
        exit(1)

def load_urls(filepath="xssurl.txt"):
    try:
        with open(filepath, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        print(Fore.RED + f"[!] Error loading URLs: {e}")
        exit(1)

def generate_payload_urls(url, payload):
    url_combinations = []
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    if not scheme:
        scheme = 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    for key in query_params:
        modified_params = query_params.copy()
        modified_params[key] = [payload]
        modified_query_string = urlencode(modified_params, doseq=True)
        modified_url = urlunsplit((scheme, netloc, path, modified_query_string, fragment))
        url_combinations.append(modified_url)
    return url_combinations

async def check_vulnerability(url, payloads, vulnerable_urls, total_scanned, driver, total_tasks):
    for payload in payloads:
        payload_urls = generate_payload_urls(url, payload)
        for payload_url in payload_urls:
            try:
                driver.get(payload_url)
                total_scanned[0] += 1
                current_progress = (total_scanned[0] / total_tasks) * 100
                print_progress(current_progress, total_scanned[0], total_tasks)
                
                try:
                    WebDriverWait(driver, 0).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    result = Fore.GREEN + f"[✓] Vulnerable: {payload_url} - Alert Text: {alert.text}"
                    print(result)
                    vulnerable_urls.append(payload_url)
                    with open("xssvuln.txt",'a') as file: file.write(payload_url + '\n')
                    #os.system("tee -a xssvuln.txt | notify -config notify-config.yaml") #You can add your own bug notifications in real time
                    alert.accept()
                except TimeoutException:
                    # Skip printing non-vulnerable URLs
                    pass
            except UnexpectedAlertPresentException as e:
                print(Fore.CYAN + f"[!] Unexpected Alert: {payload_url} - Might be Vulnerable!")
                with open("xssvuln.txt",'a') as file: file.write(payload_url + '\n')
                #os.system("tee -a xssvuln.txt | notify -config notify-config.yaml") #You can add your own bug notifications in real time
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                except Exception as inner_e:
                    print(Fore.RED + f"[!] Error handling unexpected alert: {inner_e}")

async def scan(urls, payloads, vulnerable_urls, total_scanned, concurrency, driver):
    total_tasks = len(urls) * len(payloads)
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [bound_check(url, semaphore, payloads, vulnerable_urls, total_scanned, driver, total_tasks) for url in urls]
    await asyncio.gather(*tasks)

async def bound_check(url, semaphore, payloads, vulnerable_urls, total_scanned, driver, total_tasks):
    async with semaphore:
        await check_vulnerability(url, payloads, vulnerable_urls, total_scanned, driver, total_tasks)

def run_scan(concurrency=10, timeout=60):
    payloads = load_payloads()
    urls = load_urls()
    vulnerable_urls = []
    total_scanned = [0]
    total_tasks = len(urls) * len(payloads)
    start_time = time.time()

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    logging.getLogger('urllib3').setLevel(logging.CRITICAL)

    driver_service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=driver_service, options=chrome_options)

    try:
        asyncio.run(scan(urls, payloads, vulnerable_urls, total_scanned, concurrency, driver))
    except Exception as e:
        print(Fore.RED + f"[!] Error during scan: {e}")
    finally:
        driver.quit()
    
    end_time = time.time()
    print_scan_summary(len(vulnerable_urls), total_scanned[0], start_time, end_time)
    return vulnerable_urls

def print_progress(percentage, scanned, total):
    print(Fore.YELLOW + f"\rProgress: [{scanned}/{total}] ({percentage:.2f}%)", end="")

def print_scan_summary(total_found, total_scanned, start_time, end_time):
    time_taken = int(end_time - start_time)
    summary = (
        f"{Fore.YELLOW}\n→ Scanning finished.\n"
        f"• Total found: {Fore.GREEN}{total_found}{Fore.YELLOW}\n"
        f"• Total scanned: {total_scanned}\n"
        f"• Time taken: {time_taken} seconds{Fore.RESET}"
    )
    print(summary)

if __name__ == "__main__":
    print(Fore.GREEN + "Starting XSS scanner...\n")
    run_scan()

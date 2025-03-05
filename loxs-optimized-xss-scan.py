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
import telegram  # Import the telegram library

# Initialize logging and warnings
logging.getLogger('WDM').setLevel(logging.ERROR)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Configuration
TELEGRAM_API_KEY = os.environ.get("TELEGRAM_API_KEY")  # Load from environment variable
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID")  # Load from environment variable

if not TELEGRAM_API_KEY or not TELEGRAM_CHAT_ID:
    print(Fore.RED + "[!] Telegram API key or chat ID not set in environment variables.")
    exit(1)


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
    scheme, netloc, path, query_string, fragment = urlsplit(url)
    scheme = scheme or 'http'
    query_params = parse_qs(query_string, keep_blank_values=True)
    return [
        urlunsplit((scheme, netloc, path, urlencode({**query_params, key: payload}, doseq=True), fragment))
        for key in query_params
    ]

async def check_vulnerability(driver, url, payloads, vulnerable_urls, total_scanned, total_tasks):
    for payload in payloads:
        payload_urls = generate_payload_urls(url, payload)
        for payload_url in payload_urls:
            try:
                driver.get(payload_url)
                total_scanned[0] += 1
                current_progress = (total_scanned[0] / total_tasks) * 100
                print_progress(current_progress, total_scanned[0], total_tasks)
                if current_progress >= 100:
                    return  # Exit when scanning is complete

                try:
                    WebDriverWait(driver, 0.5).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    print(Fore.GREEN + f"[✓] Vulnerable: {payload_url} - Alert Text: {alert.text}")
                    vulnerable_urls.add(payload_url)
                    await send_telegram_message(f"XSS Vulnerability Found!\nURL: {payload_url}\nAlert Text: {alert.text}")  # Send Telegram Notification
                    alert.accept()
                except TimeoutException:
                    pass
            except UnexpectedAlertPresentException:
                print(Fore.CYAN + f"[!] Unexpected Alert: {payload_url} - Might be Vulnerable!")
                vulnerable_urls.add(payload_url)
                # await send_telegram_message(f"Possible XSS Vulnerability (Unexpected Alert)!\nURL: {payload_url}")  # Send Telegram Notification
                try:
                    alert = driver.switch_to.alert
                    alert.accept()
                except:
                    pass

async def scan(urls, payloads, concurrency):
    total_scanned = [0]
    vulnerable_urls = set()
    total_tasks = len(urls) * len(payloads)

    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    logging.getLogger('urllib3').setLevel(logging.CRITICAL)

    driver_service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=driver_service, options=chrome_options)

    try:
        tasks = []
        semaphore = asyncio.Semaphore(concurrency)

        for url in urls:
            task = asyncio.create_task(bound_check_vulnerability(driver, url, semaphore, payloads, vulnerable_urls, total_scanned, total_tasks))
            tasks.append(task)

        await asyncio.gather(*tasks)
    finally:
        driver.quit()
    
    return vulnerable_urls

async def bound_check_vulnerability(driver, url, semaphore, payloads, vulnerable_urls, total_scanned, total_tasks):
    async with semaphore:
        await check_vulnerability(driver, url, payloads, vulnerable_urls, total_scanned, total_tasks)

def print_progress(percentage, scanned, total):
    print(Fore.YELLOW + f"\rProgress: [{scanned}/{total}] ({percentage:.2f}%)", end="")
    if percentage >= 100:
        print(Fore.GREEN + "\nScan completed 100%! Exiting...")

def print_scan_summary(total_found, total_scanned, start_time, end_time):
    time_taken = int(end_time - start_time)
    summary = (
        f"{Fore.YELLOW}\n→ Scanning finished.\n"
        f"• Total found: {Fore.GREEN}{total_found}{Fore.YELLOW}\n"
        f"• Total scanned: {total_scanned}\n"
        f"• Time taken: {time_taken} seconds{Fore.RESET}"
    )
    print(summary)

async def send_telegram_message(message):
    """Sends a message to a Telegram chat."""
    try:
        bot = telegram.Bot(token=TELEGRAM_API_KEY)
        await bot.send_message(chat_id=TELEGRAM_CHAT_ID, text=message)  # Use await for async method
        logging.info("Telegram message sent successfully.")
    except Exception as e:
        logging.error(f"Error sending Telegram message: {e}")


def run_scan(concurrency=30):
    payloads = load_payloads()
    urls = load_urls()
    start_time = time.time()

    vulnerable_urls = asyncio.run(scan(urls, payloads, concurrency))

    end_time = time.time()
    print_scan_summary(len(vulnerable_urls), len(urls) * len(payloads), start_time, end_time)

if __name__ == "__main__":
    print(Fore.GREEN + "Starting XSS scanner...\n")
    asyncio.run(run_scan())  # Run the main function using asyncio

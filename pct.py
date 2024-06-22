"""
PurgeCheckTool a tool that detects the Unauthenticated Cache Purge vulnerability in web applications.

The vulnerability allows attackers to clear cached content without proper authentication, potentially leading to unauthorized data manipulation or denial of service (DoS) attacks.

Features:
- Scans single endpoint or multiple endpoints from a list.
- Supports both HTTP and HTTPS endpoints.
- Generate reports as CSV output.
- Logs scan results for further analysis.

Usage:
    single target python pct.py -u <URL>
    bulk scan multiple URLs from a file python pct.py -f endpoints.txt
    
Github: https://github.com/bigb0x/PurgeCheckTool
Author: https://x.com/MohamedNab1l

"""

import argparse
import os
import sys
import requests
import concurrent.futures
import signal
from datetime import datetime
import urllib3
import csv

# Disable SSL Warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ANSI color codes
light_gray_color = '\033[37;1m'
dimmed_gray_color = '\033[90m'
honey_yellow_color = "\033[38;5;214m"
dim_yellow_color = "\033[33;1m"
cyan_color = '\033[96m'
green_color = '\033[92m'
red_color = '\033[31m'
light_orange_color = '\033[38;5;214m'
reset_color = '\033[0m'

the_version = '1.3.1'
the_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# Log directory and file
LOG_DIR = 'logs'
LOG_FILE = os.path.join(LOG_DIR, 'scan.log')

# Reports directory
REPORTS_DIR = 'reports'
REPORT_FILE = os.path.join(REPORTS_DIR, f'report-{datetime.now().strftime("%Y-%m-%d-%H-%M-%S")}.csv')

def banner():
    print(f"""
{light_gray_color}

▒█▀▀█ █░░█ █▀▀█ █▀▀▀ █▀▀ ▒█▀▀█ █░░█ █▀▀ █▀▀ █░█ ▀▀█▀▀ █▀▀█ █▀▀█ █░░ 
▒█▄▄█ █░░█ █▄▄▀ █░▀█ █▀▀ ▒█░░░ █▀▀█ █▀▀ █░░ █▀▄ ░▒█░░ █░░█ █░░█ █░░ 
▒█░░░ ░▀▀▀ ▀░▀▀ ▀▀▀▀ ▀▀▀ ▒█▄▄█ ▀░░▀ ▀▀▀ ▀▀▀ ▀░▀ ░▒█░░ ▀▀▀▀ ▀▀▀▀ ▀▀▀           
-> {reset_color}Detects Unauthenticated Cache Purge Vulnerability in Web Applications. Current version: {light_orange_color}{the_version}{reset_color}
{reset_color}
    """)

# Function to create log directory
def create_log_dir():
    if not os.path.exists(LOG_DIR):
        os.makedirs(LOG_DIR)
        print_message('info', f"Log directory created: {LOG_DIR}")

# Function to create reports directory
def create_reports_dir():
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
        print_message('info', f"Reports directory created: {REPORTS_DIR}")

# Function to log messages
def log_message(message):
    the_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as log_file:
        log_file.write(f"{the_time} - {message}\n")

def print_message(level, message):
    if level == 'info':
        print(f"[{dimmed_gray_color}{the_time}] {cyan_color}[INFO]{reset_color} {message}")
    elif level == 'success':
        print(f"[{dimmed_gray_color}{the_time}] {green_color}[SUCCESS]{reset_color} {message}")
    elif level == 'error':
        print(f"[{dimmed_gray_color}{the_time}] {red_color}[ERROR]{reset_color} {message}")
    elif level == 'progress':
        print(f"[{dimmed_gray_color}{the_time}] {light_orange_color}[PROGRESS]{reset_color} {message}")

def test_purge(endpoint):
    try:
        response = requests.request("PURGE", endpoint, verify=False)
        if 'status : ok' in response.text:
            result = (endpoint, 'Vulnerable', response.text)
            log_message(f"Vulnerable: {endpoint} - {response.text}")
        else:
            result = (endpoint, 'Not Vulnerable', response.text)
            log_message(f"Not Vulnerable: {endpoint} - {response.text}")
    except Exception as e:
        result = (endpoint, 'Error', str(e))
        log_message(f"Error: {endpoint} - {str(e)}")
    return result

def signal_handler(sig, frame):
    # print(f"\nExiting...")
    print_message('info', "Exiting...")
    sys.exit(0)

def save_results_to_csv(results):
    create_reports_dir()
    with open(REPORT_FILE, 'w', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(['Endpoint', 'Status', 'Details'])
        for result in results:
            csvwriter.writerow(result)
    print_message('info', f"Results saved to {REPORT_FILE}")

def main():
    banner()
    parser = argparse.ArgumentParser(description='PurgeCheckTool Detects Unauthenticated Cache Purge vulnerability in web applications.')
    parser.add_argument('-u', '--url', help='Single endpoint URL')
    parser.add_argument('-f', '--file', help='File with list of endpoints, one per line')
    args = parser.parse_args()

    if not args.url and not args.file:
        parser.error('Missing arguments!. To use python pct.py -u endpoint OR -f endpoints.txt')

    create_log_dir()
    
    endpoints = []

    if args.url:
        endpoints.append(args.url)

    if args.file:
        try:
            with open(args.file, 'r') as file:
                endpoints.extend(line.strip() for line in file if line.strip())
        except FileNotFoundError:
            print_message('error', f"File not found: {args.file}")
            sys.exit(1)

    results = []

    signal.signal(signal.SIGINT, signal_handler)
    
    print_message('info', f"Scanning {len(endpoints)} endpoints...")

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(test_purge, url): url for url in endpoints}
        for count, future in enumerate(concurrent.futures.as_completed(future_to_url), start=1):
            url = future_to_url[future]
            try:
                result = future.result()
                results.append(result)
                print_message('progress', f"[{count}/{len(endpoints)}] Scanned: {url}")
            except Exception as exc:
                print_message('error', f"{url} generated an exception: {exc}")

    print_message('info', "Scan complete.")
    print_message('info', "Printing results:")
    print(f"{honey_yellow_color}{'Endpoint':<30} {'Status':<15} {'Details'}{reset_color}")
    for endpoint, status, details in results:
        print(f"{light_gray_color}{endpoint:<30} {status:<15} {details[:50]}{reset_color}")
    save_results_to_csv(results)

if __name__ == "__main__":
    main()

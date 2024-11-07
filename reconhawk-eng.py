#!/usr/bin/env python3

imports
import subprocess
import requests
from lxml import html
from urllib.parse import urlparse

# Definition of colors
class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m" # Added CYAN color
    RESET = "\033[0m"

def print_banner():
    """Print a welcome banner."""
    banner = r"""
     _____ _ ___ __ __ ___ ___ _ _
    |_ _| | |_ ___ / _ \ / _| / _| /__| ___ __ / __| (_) _ _ | |
      | | | ' \ / -_) | (_) | | _| | _| \__ \ / -_) / _| | (_ | | | | '_| | |
      |_| |_||_| \___| \___/ |_| |_| |___/ \___| \__| \___| |_| |_| |_|
    """
    print(Colors.GREEN + banner + Colors.RESET)

def validate_url(url):
    """Validate that the URL is correct."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Vulnerability analysis
def verify_csrf(form):
    """Checks if there is a CSRF token on the form."""
    csrf_token = form.xpath('//input[@name="csrf_token"]')
    if not csrf_token:
        print(Colors.YELLOW + "⚠️ Possible CSRF vulnerability in the form." + Colors.RESET)
    else:
        print(Colors.GREEN + "✅ CSRF Token Found." + Colors.RESET)

def verify_sql_injection(url, user_agent=None):
    """Check for SQL injection by sending common payloads."""
    payloads = ["' OR 1=1--", "' OR 'a'='a", "' OR 1=1#", "' AND 1=1--"]
    headers = {'User-Agent': user_agent} if user_agent else {}
    vulnerable = False
    for payload in payloads:
        try:
            response = requests.get(f"{url}{payload}", headers=headers, timeout=10)
            if "SQL" in response.text or "syntax" in response.text:
                print(Colors.YELLOW + f"⚠️ Possible SQL injection vulnerability with payload: {payload}" + Colors.RESET)
                vulnerable = True
        except requests.RequestException as e:
            print(Colors.RED + f"❌ Error checking advanced SQL injection: {e}" + Colors.RESET)
    if not vulnerable:
        print(Colors.GREEN + "✅ No SQL injections detected." + Colors.RESET)

def verify_xss(url, user_agent=None):
    """Check for XSS vulnerabilities by sending common payloads."""
    payload = "<script>alert('XSS')</script>"
    headers = {'User-Agent': user_agent} if user_agent else {}
    try:
        response = requests.get(url, params={"q": payload}, headers=headers, timeout=10)
        if payload in response.text:
            print(Colors.YELLOW + "⚠️ Possible reflected Cross-Site Scripting (XSS) vulnerability." + Colors.RESET)
        else:
            print(Colors.GREEN + "✅ No reflected XSS vulnerabilities detected." + Colors.RESET)
    except requests.RequestException as e:
        print(Colors.RED + f"❌ Advanced XSS check failed: {e}" + Colors.RESET)

def scan_vulnerabilities(url, options, user_agent=None):
    """Scans the URL for the selected vulnerabilities."""
    if not validate_url(url):
        print(Colors.RED + "❌ Invalid URL. Please enter a valid URL." + Colors.RESET)
        return

    try:
        headers = {'User-Agent': user_agent} if user_agent else {}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status() # Throws an error if the request was not successful
        root = html.fromstring(response.content)

        # Check vulnerabilities based on the selected options
        forms = root.xpath('//form')
        for form in forms:
            if 'csrf' in options:
                verify_csrf(form)
        if 'sql' in options:
            verify_sql_injection(url, user_agent)
        if 'xss' in options:
            verify_xss(url, user_agent)

    except requests.RequestException as e:
        print(Colors.RED + f"❌ Error scanning URL: {e}" + Colors.RESET)

# Subdomain recognition using Subfinder and HTTPX
def domain_recognition(domain, user_agent=None):
    print(Colors.CYAN + f"[*] Starting subdomain recognition for {domain}" + Colors.RESET)
    subfinder_cmd = f"subfinder -d {domain} -silent -o subdomains.txt"
    httpx_cmd = f"httpx -l subdomains.txt -silent -o active_subdomains.txt"

    if user_agent:
        subfinder_cmd += f" --header 'User-Agent: {user_agent}'"
        httpx_cmd += f" --header 'User-Agent: {user_agent}'"

    try:
        subprocess.run(subfinder_cmd, shell=True, check=True)
        print(Colors.GREEN + "[+] Subfinder completed. Subdomains saved in subdomains.txt" + Colors.RESET)
        subprocess.run(httpx_cmd, shell=True, check=True)
        print(Colors.GREEN + "[+] HTTPX completed. Active subdomains saved in active_subdomains.txt" + Colors.RESET)
    except subprocess.CalledProcessError as e:
        print(Colors.RED + f"❌ Error in subdomain recognition: {e}" + Colors.RESET)

# Port scanning using Nmap
def portscan():
    print(Colors.CYAN + "[*] Starting port scanning on active subdomains" + Colors.RESET)

    # Check if the file contains subdomains
    if os.path.isfile("active_subdomains.txt") and os.path.getsize("active_subdomains.txt") > 0:
        nmap_cmd = "nmap -iL active_subdomains.txt -T4 -F -oN nmap_scan.txt"
        try:
            subprocess.run(nmap_cmd, shell=True, check=True)
            print(Colors.GREEN + "[+] Port scan completed. Results saved in nmap_scan.txt" + Colors.RESET)
        except subprocess.CalledProcessError as e:
            print(Colors.RED + f"❌ Port scan failed: {e}" + Colors.RESET)
    else:
        print(Colors.RED + "❌ No active subdomains found to scan." + Colors.RESET)

if __name__ == "__main__":
    print_banner() # Prints the banner at the beginning

    print("Select the task you want to perform:")
    print("1. URL vulnerability analysis")
    print("2. Subdomain recognition")
    print("3. Port Scanning")
    print("4. All of the above")

    task = input("Enter the option number: ")

    # Ask if you want to use a custom User-Agent
    use_agent = input("Do you want to add a custom User-Agent to avoid WAF crashes? (y/n): ")
    user_agent = None
    if use_agent.lower() == 'y':
        user_agent = input("Enter the User-Agent you want to use: ")

    if task == '1':
        url_to_scan = input("Enter the URL to scan: ")
        print("Select the vulnerabilities to check:")
        print("1. CSRF")
        print("2. SQL Injection")
        print("3. XSS")
        print("4. All")

        selection = input("Enter the option number: ")

        selected_options = []
        if selection == '1':
            selected_options.append('csrf')
        elif selection == '2':
            selected_options.append('sql')
        elif selection == '3':
            selected_options.append('xss')
        elif selection == '4':
            selected_options = ['csrf', 'sql', 'xss']
        else:
            print(Colors.RED + "❌ Invalid option. Exiting." + Colors.RESET)
            exit()

        scan_vulnerabilities(url_to_scan, selected_options, user_agent)

    elif task == '2':
        domain = input("Enter the domain for recognition: ")
        domain_recognition(domain, user_agent)

    elif task == '3':
        portscan()

    elif task == '4':
        domain = input("Enter the domain for recognition and scanning: ")
        domain_recognition(domain, user_agent)
        portscan()

    else:
        print(Colors.RED + "❌ Invalid option. Exiting." + Colors.RESET)
        exit()

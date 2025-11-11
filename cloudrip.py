import dns.resolver
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import pyfiglet
import time
import signal
import socket
import csv

# --------------------------
# Config / "easy edit" VARs
# --------------------------
# If empty list -> use system resolver (no override)
NAMESERVERS = ["8.8.8.8"]      # e.g. ["8.8.8.8", "1.1.1.1"] or [] to use system DNS
DNS_TIMEOUT = 5                # socket timeout (seconds)
DNS_LIFETIME = 5               # total lifetime for a query (seconds)
RATE_LIMIT_SLEEP = 0.4         # sleep between successful findings (or every iteration)
MAX_THREADS = 50               # Maximum concurrent threads for DNS resolution
VERBOSE = 0                    # 0 = only FOUND, 1 = FOUND + errors, 2 = all including NO ANSWER, etc.
# Common TCP and UDP ports to scan
COMMON_TCP_PORTS = [80, 443, 21, 22, 25, 3306, 5432, 8080, 8443, 3389, 1433]
COMMON_UDP_PORTS = [53, 123, 161, 162, 5353]
PORT_SCAN_TIMEOUT = 0.5          # timeout for port scanning (seconds)
# --------------------------

# Initialize colorama
init(autoreset=True)

# Define colors
RED = Fore.RED
GREEN = Fore.GREEN
BLUE = Fore.LIGHTBLUE_EX
YELLOW = Fore.LIGHTYELLOW_EX
WHITE = Fore.WHITE

# Global flag to track requested to stop
stop_requested = False

def banner():
    """Displays the banner"""
    figlet_text = pyfiglet.Figlet(font="slant").renderText("CloudRip")
    print(BLUE + figlet_text)
    print(RED + "CloudFlare Bypasser - Find Real IP Addresses Behind Cloudflare")
    print(YELLOW + "\"Ripping through the clouds to expose the truth\"")
    print(WHITE + "by: " + GREEN + "Stax")
    print(WHITE + "GitHub: " + BLUE + "https://github.com/staxsum/CloudRip")
    print()

def resolve_subdomain(subdomain, domain):
    """Attempts to resolve a subdomain using a Resolver configured from globals."""
    # Properly format domain
    full_domain = f"{subdomain}.{domain}" if subdomain else domain

    # Create resolver instance so we can control nameservers/timeouts per query
    resolver = dns.resolver.Resolver(configure=not bool(NAMESERVERS))
    # If NAMESERVERS is non-empty override the system resolver
    if NAMESERVERS:
        resolver.nameservers = list(NAMESERVERS)
    resolver.timeout = DNS_TIMEOUT
    resolver.lifetime = DNS_LIFETIME

    try:
        # Use dns.resolver to resolve the subdomain
        answers = resolver.resolve(full_domain, "A", lifetime=DNS_LIFETIME)

        for rdata in answers:
            # rdata could be an A record with .address attr
            ip = getattr(rdata, "address", None)
            if ip is None:
                # fallback if different record object
                try:
                    ip = str(rdata)
                except Exception:
                    ip = None

            if ip:
                # Check if IP belongs to Cloudflare
                is_cf = is_cloudflare_ip(ip)
                if is_cf:
                    print(YELLOW + f"[FOUND] {full_domain} -> {ip} (Cloudflare)")
                    return full_domain, ip, True  # True indicates Cloudflare
                else:
                    print(GREEN + f"[FOUND] {full_domain} -> {ip}")
                    return full_domain, ip, False  # False indicates non-Cloudflare

    except dns.resolver.NXDOMAIN:
        pass  # Domain not found - silently skip
    except dns.resolver.NoAnswer:
        pass  # No answer - silently skip
    except dns.resolver.NoNameservers:
        pass  # No nameservers - silently skip
    except dns.resolver.Timeout:
        pass  # Timeout - silently skip
    except Exception as e:
        pass  # Other errors - silently skip
    return None

def is_cloudflare_ip(ip):
    """Check if the IP belongs to Cloudflare's known IP ranges."""
    cloudflare_ip_ranges = [
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17"
    ]
    from ipaddress import ip_address, ip_network
    ip_addr = ip_address(ip)
    return any(ip_addr in ip_network(cidr) for cidr in cloudflare_ip_ranges)

def load_wordlist(wordlist_path):
    """Loads the wordlist from a file, ignoring lines that start with #."""
    if os.path.exists(wordlist_path):
        with open(wordlist_path, "r") as file:
            return [line.strip() for line in file if line.strip() and not line.strip().startswith("#")]
    else:
        print(RED + f"[ERROR] Wordlist file not found: {wordlist_path}")
        sys.exit(1)

def save_results_to_file(results, output_file):
    """Saves the results to a CSV file with geo-location info."""
    try:
        with open(output_file, "w", newline="") as csvfile:
            fieldnames = ["Subdomain", "IP Address", "Country", "Cloudflare", "Open Ports"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for subdomain, data in results.items():
                ip = data["ip"]
                is_cf = data["is_cloudflare"]
                country = data.get("country", "Unknown")
                open_ports = data.get("open_ports", "")
                cf_note = "Yes" if is_cf else "No"
                writer.writerow({
                    "Subdomain": subdomain,
                    "IP Address": ip,
                    "Country": country,
                    "Cloudflare": cf_note,
                    "Open Ports": open_ports
                })
        print(GREEN + f"[INFO] Results saved to {output_file}")
    except Exception as e:
        print(RED + f"[ERROR] Failed to save results: {str(e)}")

def get_geo_location(ip):
    """Get geo-location (country) for an IP address."""
    try:
        import urllib.request
        import json
        
        # Try ipapi.co first
        try:
            response = urllib.request.urlopen(f"https://ipapi.co/{ip}/json/", timeout=3)
            data = json.loads(response.read().decode())
            country = data.get("country_name", None)
            if country:
                return country
        except Exception:
            pass
        
        # Fallback to ip-api.com
        try:
            response = urllib.request.urlopen(f"http://ip-api.com/json/{ip}", timeout=3)
            data = json.loads(response.read().decode())
            country = data.get("country", None)
            if country:
                return country
        except Exception:
            pass
        
        # If both fail, return Unknown
        return "Unknown"
    except Exception:
        return "Unknown"

def check_port(ip, port, protocol="tcp"):
    """Check if a specific port is open on an IP."""
    try:
        if protocol.lower() == "tcp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        elif protocol.lower() == "udp":
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(PORT_SCAN_TIMEOUT)
            sock.sendto(b"", (ip, port))
            try:
                sock.recvfrom(1024)
                sock.close()
                return True
            except socket.timeout:
                sock.close()
                return False
    except Exception:
        return False
    return False

def scan_ports(ip):
    """Scan common ports on an IP and return list of open ports."""
    open_ports = []
    # Scan TCP ports
    for port in COMMON_TCP_PORTS:
        if check_port(ip, port, "tcp"):
            open_ports.append(f"{port}/tcp")
    # Scan UDP ports
    for port in COMMON_UDP_PORTS:
        if check_port(ip, port, "udp"):
            open_ports.append(f"{port}/udp")
    return open_ports

def signal_handler(sig, frame):
    """Handles SIGINT (Ctrl+C) to prompt whether to quit."""
    global stop_requested
    if stop_requested:
        print(RED + "\n[INFO] Force quitting...")
        sys.exit(0)
    print(RED + "\n[INFO] Ctrl+C detected. Do you want to quit? (y/n): ", end="")
    choice = input().strip().lower()
    if choice == 'y':
        stop_requested = True
    else:
        print(YELLOW + "[INFO] Resuming...")

def main():
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)

    # Parse arguments
    parser = argparse.ArgumentParser(description="CloudRip - CloudFlare Bypasser")
    parser.add_argument("domain", help="The domain to resolve (e.g., example.com)")
    parser.add_argument("-w", "--wordlist", default="dom.txt", help="Path to the wordlist file")
    parser.add_argument("-v", "--verbose", type=int, default=1, choices=[0, 1, 2], help="Verbosity level: 0=only FOUND, 1=FOUND+errors, 2=all messages")
    parser.add_argument("-o", "--output", help="Save the results to a file (optional, defaults to domain.csv)")
    parser.add_argument("--nameservers", nargs="+", help="Override nameservers for this run (e.g. --nameservers 8.8.8.8 1.1.1.1)")
    args = parser.parse_args()

    # Allow CLI override of config globals
    global VERBOSE, NAMESERVERS
    VERBOSE = args.verbose
    if args.nameservers:
        NAMESERVERS = args.nameservers

    # Display banner
    banner()

    # Load wordlist
    subdomains = load_wordlist(args.wordlist)
    print(YELLOW + f"[INFO] Loaded {len(subdomains)} subdomains from {args.wordlist}")

    # Start resolving subdomains concurrently
    print(YELLOW + "[INFO] Starting subdomain resolution...")
    found_results = {}
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(resolve_subdomain, subdomain, args.domain): subdomain for subdomain in subdomains}
        for future in as_completed(futures):
            if stop_requested:
                print(RED + "[INFO] Operation was interrupted.")
                break
            result = future.result()
            if result:
                subdomain, ip, is_cf = result
                found_results[subdomain] = {
                    "ip": ip,
                    "is_cloudflare": is_cf,
                    "country": None,
                    "open_ports": ""
                }
                time.sleep(RATE_LIMIT_SLEEP)

    if not found_results:
        print(YELLOW + "[INFO] No subdomains found.")
        return

    # Ask user if they want to scan ports
    print(WHITE + "\n" + "="*60)
    scan_ports_choice = input(BLUE + "[?] Do you want to scan for open ports on found IPs? (y/n): ").strip().lower()
    
    if scan_ports_choice == 'y':
        print(YELLOW + "[INFO] Starting port scan...")
        for subdomain, data in found_results.items():
            ip = data["ip"]
            print(YELLOW + f"[INFO] Scanning ports for {ip}...")
            open_ports = scan_ports(ip)
            if open_ports:
                data["open_ports"] = ", ".join(open_ports)
                print(GREEN + f"[INFO] Open ports on {ip}: {data['open_ports']}")
            else:
                print(YELLOW + f"[INFO] No open common ports on {ip}")

    # Get geo-location for all IPs
    print(YELLOW + "[INFO] Fetching geo-location data...")
    for subdomain, data in found_results.items():
        ip = data["ip"]
        print(YELLOW + f"[INFO] Fetching location for {ip}...", end=" ")
        country = get_geo_location(ip)
        data["country"] = country
        print(GREEN + f"{country}")

    # Determine output file name
    if args.output:
        output_file = args.output
    else:
        output_file = f"{args.domain}.csv"

    # Check if file exists and ask for confirmation
    if os.path.exists(output_file):
        overwrite_choice = input(BLUE + f"[?] File '{output_file}' already exists. Overwrite? (y/n): ").strip().lower()
        if overwrite_choice != 'y':
            print(YELLOW + "[INFO] Skipping file save.")
            print_results(found_results)
            return

    # Save results to CSV file
    save_results_to_file(found_results, output_file)
    
    # Print results nicely
    print_results(found_results)

    print(WHITE + "The operation has completed successfully.")

def print_results(results):
    """Print results in a nice formatted table."""
    print(WHITE + "\n" + "="*120)
    print(WHITE + "RESULTS SUMMARY")
    print(WHITE + "="*120)
    print(f"{BLUE}{'Subdomain':<50} {'IP Address':<20} {'Country':<20} {'CF':<5} {'Open Ports':<25}")
    print(WHITE + "-"*120)
    for subdomain, data in results.items():
        ip = data["ip"]
        country = data.get("country", "Unknown")
        is_cf = "Yes" if data["is_cloudflare"] else "No"
        ports = data.get("open_ports", "None")
        print(f"{YELLOW}{subdomain:<50} {GREEN}{ip:<20} {BLUE}{country:<20} {YELLOW}{is_cf:<5} {ports:<25}")
    print(WHITE + "="*120 + "\n")

if __name__ == "__main__":
    main()

import dns.resolver
import sys
import os
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style, init
import pyfiglet
import time
import signal

# --------------------------
# Config / "easy edit" VARs
# --------------------------
# If empty list -> use system resolver (no override)
NAMESERVERS = ["8.8.8.8"]      # e.g. ["8.8.8.8", "1.1.1.1"] or [] to use system DNS
DNS_TIMEOUT = 3                # socket timeout (seconds)
DNS_LIFETIME = 5               # total lifetime for a query (seconds)
RATE_LIMIT_SLEEP = 0.2         # sleep between successful findings (or every iteration)
DEBUG = False                  # True -> print raw dns responses for debugging
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
        if DEBUG:
            print(YELLOW + f"[DEBUG] Raw answer for {full_domain}: {answers.response.to_text() if getattr(answers, 'response', None) else str(list(answers))}")

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
                if not is_cloudflare_ip(ip):
                    print(GREEN + f"[FOUND] {full_domain} -> {ip}")
                    return full_domain, ip
                else:
                    if DEBUG:
                        print(YELLOW + f"[DEBUG] {full_domain} -> {ip} (cloudflare)")
                    # continue checking other answers
        # if we reached here - all answers were Cloudflare or no usable IP
        if DEBUG:
            print(YELLOW + f"[DEBUG] No non-Cloudflare A-records for {full_domain}")
    except dns.resolver.NXDOMAIN:
        if DEBUG:
            print(RED + f"[NXDOMAIN] {full_domain}")
        else:
            print(RED + f"[NOT FOUND] {full_domain}")
    except dns.resolver.NoAnswer:
        if DEBUG:
            print(YELLOW + f"[NO ANSWER] {full_domain} - raw no-answer")
        else:
            print(YELLOW + f"[NO ANSWER] {full_domain}")
    except dns.resolver.NoNameservers:
        if DEBUG:
            print(YELLOW + f"[NO NAMESERVERS] {full_domain} - resolver.nameservers={resolver.nameservers}")
        else:
            print(YELLOW + f"[NO NAMESERVERS] {full_domain}")
    except dns.resolver.Timeout:
        if DEBUG:
            print(YELLOW + f"[TIMEOUT] {full_domain} - timeout after {DNS_LIFETIME}s (nameservers={resolver.nameservers})")
        else:
            print(YELLOW + f"[TIMEOUT] {full_domain}")
    except Exception as e:
        print(YELLOW + f"[ERROR] {full_domain}: {str(e)}")
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
    """Loads the wordlist from a file."""
    if os.path.exists(wordlist_path):
        with open(wordlist_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    else:
        print(RED + f"[ERROR] Wordlist file not found: {wordlist_path}")
        sys.exit(1)

def save_results_to_file(results, output_file):
    """Saves the results to a specified file."""
    try:
        with open(output_file, "w") as file:
            for subdomain, ip in results.items():
                file.write(f"{subdomain} -> {ip}\n")
        print(GREEN + f"[INFO] Results saved to {output_file}")
    except Exception as e:
        print(RED + f"[ERROR] Failed to save results: {str(e)}")

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
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of threads for concurrent scanning")
    parser.add_argument("-o", "--output", help="Save the results to a file (optional)")
    parser.add_argument("--debug", action="store_true", help="Enable debug printing of raw DNS responses")
    parser.add_argument("--nameservers", nargs="+", help="Override nameservers for this run (e.g. --nameservers 8.8.8.8 1.1.1.1)")
    args = parser.parse_args()

    # Allow CLI override of config globals
    global DEBUG, NAMESERVERS
    if args.debug:
        DEBUG = True
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
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(resolve_subdomain, subdomain, args.domain): subdomain for subdomain in subdomains}
        for future in as_completed(futures):
            if stop_requested:
                print(RED + "[INFO] Operation was interrupted.")
                break
            result = future.result()
            if result:
                subdomain, ip = result
                found_results[subdomain] = ip
                time.sleep(RATE_LIMIT_SLEEP)

    # Save results if output file is specified
    if args.output:
        save_results_to_file(found_results, args.output)

    print(WHITE + "The operation has completed successfully.")

if __name__ == "__main__":
    main()

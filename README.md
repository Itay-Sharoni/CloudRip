# CloudRip

A powerful tool that helps you find the real IP addresses hiding behind Cloudflare by checking subdomains. For penetration testing, security research, and learning how Cloudflare protection works.

## What it does

- **Fast subdomain scanning** - Uses 50 concurrent threads for maximum speed
- **Includes Cloudflare IPs** - Shows all IPs found, marks Cloudflare entries clearly
- **Smart filtering** - Supports verbosity levels to control output detail
- **Bring your own wordlist** - Or use the built-in one (dom.txt) - ignores comment lines starting with `#`
- **Port scanning** - Optional scanning of common TCP/UDP ports after DNS resolution
- **Geo-location data** - Adds country information to all IP results
- **CSV export** - Save results to CSV with full details (IP, Country, Cloudflare flag, Open Ports)
- **Rate limiting** - Won't spam the target and get you blocked
- **Auto-naming** - Results saved as `{domain}.csv` by default, with overwrite protection

## Features

### DNS Resolution
- Resolves subdomains from your wordlist
- Detects and labels Cloudflare IPs
- Handles timeouts and errors gracefully

### Port Scanning
- Scans **10 common TCP ports**: 80, 443, 21, 22, 25, 3306, 5432, 8080, 8443, 3389, 1433
- Scans **5 common UDP ports**: 53, 123, 161, 162, 5353
- Optional - asks user at end of DNS scan whether to perform port scanning

### Geo-Location
- Fetches country information for each IP
- Uses fallback services for reliability (ipapi.co → ip-api.com)

### Verbosity Levels
- **VERBOSE=0** - Only shows `[FOUND]` results (clean output)
- **VERBOSE=1** - Shows `[FOUND]` + errors/timeouts
- **VERBOSE=2** - Shows all messages including NO ANSWER responses

## Getting it running

You'll need Python 3 and the required packages:
```bash
pip install -r requirements.txt
```

Or manually:
```bash
pip install dnspython colorama pyfiglet
```

## How to use it

Basic usage:
```bash
python3 cloudrip.py example.com
```

With custom options:
```bash
python3 cloudrip.py example.com -w custom_wordlist.txt -v 1 -o results.csv
```

**Options:**
- `<domain>` - The domain you're testing (required, e.g., example.com)
- `-w, --wordlist` - Custom wordlist file (defaults to dom.txt, ignores lines starting with `#`)
- `-v, --verbose` - Verbosity level: 0=only FOUND, 1=FOUND+errors, 2=all messages (default: 1)
- `-o, --output` - Custom output file name (defaults to `{domain}.csv`)
- `--nameservers` - Override default nameservers (e.g., `--nameservers 8.8.8.8 1.1.1.1`)

## Examples

Clean output with just found subdomains:
```bash
python3 cloudrip.py example.com -v 0
```

With custom wordlist and verbose output:
```bash
python3 cloudrip.py example.com -w my_subs.txt -v 2 -o findings.csv
```

Using custom nameservers:
```bash
python3 cloudrip.py example.com --nameservers 1.1.1.1 8.8.4.4
```

## Output Format

Results are saved as CSV with the following columns:
- **Subdomain** - The subdomain that resolved
- **IP Address** - The resolved IP address
- **Country** - Geo-location of the IP
- **Cloudflare** - "Yes" if IP belongs to Cloudflare, "No" otherwise
- **Open Ports** - List of open TCP/UDP ports found (if port scanning was enabled)

Example CSV output:
```
Subdomain,IP Address,Country,Cloudflare,Open Ports
mail.example.com,80.179.233.52,Israel,No,"80/tcp, 443/tcp"
mfa.example.com,104.26.3.3,United States,Yes,
vpn.example.com,109.226.16.36,Germany,No,"22/tcp, 3389/tcp"
```

## Wordlist Format

- One subdomain per line
- Lines starting with `#` are treated as comments and ignored
- Empty lines are skipped

Example dom.txt:
```
# Web services
www
mail
ftp
# VPN and remote access
vpn
rdp
ssh
# Cloud services
cdn
storage
backup
```

## Contributing

Got ideas for improvements? Found a bug? Pull requests and issues are welcome! If it's better wordlists, new features, or bug fixes - all contributions help.

## Important Legal Stuff

**Only use CloudRip on systems you have permission to test.** This tool is for ethical security research, penetration testing with authorization, and educational purposes. Using it against websites without permission is illegal and not cool. You're responsible for how you use this tool.

## License

MIT License - use responsibly.


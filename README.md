# subfinder-js

> Fast passive subdomain enumeration tool JavaScript

Zero external dependencies. Pure Node.js (≥ 14).

---

## Installation

```bash
# Clone or copy subfinder.js, then:
git clone https://github.com/KarkiMilan/Subdomain-Finder.git
cd Subdomain-Finder
npm install
node subfinder.js
```

## Usage

```
node subfinder.js [flags]

Flags:
  INPUT:
    -d,  -domain string[]         domains to find subdomains for (comma separated)
    -dL, -list   string           file containing list of domains

  SOURCE:
    -s,  -sources string[]        specific sources to use (-s crtsh,hackertarget)
    -es, -exclude-sources string[] sources to exclude
    -ls, -list-sources            list all available sources

  FILTER:
    -m, -match  string[]          subdomain patterns to match
    -f, -filter string[]          subdomain patterns to filter out

  OUTPUT:
    -o,  -output string           file to write output to
    -oJ, -json                    write output in JSONL format
    -silent                       show only subdomains in output
    -v                            verbose output

  CONFIGURATION:
    -pc, -provider-config string  provider config JSON file
    -nW, -active                  verify subdomains via DNS resolution
    -timeout int                  timeout per source in seconds (default 30)
    -nc, -no-color                disable color output
    --version                     show version
```

## Examples

```bash
# Basic enumeration
node subfinder.js -d example.com

# Use specific sources
node subfinder.js -d example.com -s crtsh,hackertarget,alienvault

# JSON output
node subfinder.js -d example.com -oJ

# Save results
node subfinder.js -d example.com -o results.txt -silent

# Enumerate from a list of domains
node subfinder.js -dL domains.txt -o all-subs.txt

# Verify active subdomains via DNS
node subfinder.js -d example.com -nW

# List all available sources
node subfinder.js -ls
```

## Sources

| Source         | Requires API Key |
|----------------|:----------------:|
| crt.sh         | No               |
| HackerTarget   | No               |
| AlienVault OTX | No               |
| RapidDNS       | No               |
| ThreatMiner    | No               |
| urlscan.io     | No               |
| Anubis         | No               |
| DNSRepo        | No               |
| Shodan         | Yes              |
| SecurityTrails | Yes              |
| VirusTotal     | Yes              |

## API Key Configuration

Create `~/.config/subfinder-js/provider-config.json`:

```json
{
  "shodan": "YOUR_SHODAN_KEY",
  "securitytrails": "YOUR_ST_KEY",
  "virustotal": "YOUR_VT_KEY"
}
```

Or pass a custom config path with `-pc /path/to/config.json`.

## Output Format

**Plain (default):**
```
api.example.com
mail.example.com
www.example.com
```

**JSON (`-oJ`):**
```json
{"host":"api.example.com","domain":"example.com","sources":["crtsh","hackertarget"]}
{"host":"mail.example.com","domain":"example.com","sources":["crtsh"]}
```

---
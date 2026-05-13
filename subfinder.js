const https = require('https');
const http = require('http');
const dns = require('dns').promises;
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

// Colors 
const C = {
  reset: '\x1b[0m',
  bold:  '\x1b[1m',
  dim:   '\x1b[2m',
  red:   '\x1b[31m',
  green: '\x1b[32m',
  yellow:'\x1b[33m',
  blue:  '\x1b[34m',
  cyan:  '\x1b[36m',
  white: '\x1b[37m',
  gray:  '\x1b[90m',
};

let useColor = true;
const c = (color, str) => useColor ? `${color}${str}${C.reset}` : str;

// Banner
function printBanner() {
  console.log(c(C.cyan, C.bold + `
   _____       _      __ _           _
  / ____|     | |    / _(_)         | |
 | (___  _   _| |__ | |_ _ _ __   __| | ___ _ __
  \\___ \\| | | | '_ \\|  _| | '_ \\ / _\` |/ _ \\ '__|
  ____) | |_| | |_) | | | | | | | (_| |  __/ |
 |_____/ \\__,_|_.__/|_| |_|_| |_|\\__,_|\\___|_|

  ${c(C.gray, 'Fast passive subdomain enumeration tool')}
`));
}

// HTTP Helper 
function fetchUrl(urlStr, options = {}) {
  return new Promise((resolve, reject) => {
    try {
      const parsed = new URL(urlStr);
      const lib = parsed.protocol === 'https:' ? https : http;
      const reqOptions = {
        hostname: parsed.hostname,
        path: parsed.pathname + parsed.search,
        method: 'GET',
        timeout: options.timeout || 10000,
        headers: {
          'User-Agent': 'subfinder-js/1.0',
          'Accept': 'application/json',
          ...(options.headers || {}),
        },
      };

      const req = lib.request(reqOptions, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 400) {
            resolve({ status: res.statusCode, body: data });
          } else {
            reject(new Error(`HTTP ${res.statusCode} for ${urlStr}`));
          }
        });
      });

      req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout: ${urlStr}`)); });
      req.on('error', reject);
      req.end();
    } catch (e) {
      reject(e);
    }
  });
}

// Subdomain Utilities 
const SUBDOMAIN_REGEX = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g;

function extractSubdomains(text, domain) {
  const found = new Set();
  const matches = text.match(SUBDOMAIN_REGEX) || [];
  for (const match of matches) {
    const lower = match.toLowerCase().trim();
    if (lower.endsWith(`.${domain}`) || lower === domain) {
      // Remove trailing dot if any
      found.add(lower.replace(/\.$/, ''));
    }
  }
  return found;
}

// Sources 

const sources = {

  // crt.sh - Certificate Transparency logs
  crtsh: {
    name: 'crt.sh',
    needsKey: false,
    async query(domain) {
      const url = `https://crt.sh/?q=%25.${domain}&output=json`;
      const res = await fetchUrl(url);
      const data = JSON.parse(res.body);
      const found = new Set();
      for (const entry of data) {
        const names = (entry.name_value || '').split('\n');
        for (const name of names) {
          const clean = name.replace(/^\*\./, '').toLowerCase().trim();
          if (clean.endsWith(`.${domain}`) || clean === domain) {
            found.add(clean);
          }
        }
      }
      return found;
    },
  },

  // HackerTarget
  hackertarget: {
    name: 'HackerTarget',
    needsKey: false,
    async query(domain) {
      const url = `https://api.hackertarget.com/hostsearch/?q=${domain}`;
      const res = await fetchUrl(url);
      const found = new Set();
      if (res.body.includes('API count exceeded')) return found;
      for (const line of res.body.split('\n')) {
        const parts = line.split(',');
        if (parts[0]) {
          const sub = parts[0].toLowerCase().trim();
          if (sub.endsWith(`.${domain}`) || sub === domain) {
            found.add(sub);
          }
        }
      }
      return found;
    },
  },

  // AlienVault OTX
  alienvault: {
    name: 'AlienVault OTX',
    needsKey: false,
    async query(domain) {
      const url = `https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns`;
      const res = await fetchUrl(url);
      const data = JSON.parse(res.body);
      const found = new Set();
      for (const record of (data.passive_dns || [])) {
        const hostname = (record.hostname || '').toLowerCase().trim();
        if (hostname.endsWith(`.${domain}`) || hostname === domain) {
          found.add(hostname);
        }
      }
      return found;
    },
  },

  // RapidDNS
  rapiddns: {
    name: 'RapidDNS',
    needsKey: false,
    async query(domain) {
      const url = `https://rapiddns.io/subdomain/${domain}?full=1#result`;
      const res = await fetchUrl(url);
      return extractSubdomains(res.body, domain);
    },
  },

  // ThreatMiner
  threatminer: {
    name: 'ThreatMiner',
    needsKey: false,
    async query(domain) {
      const url = `https://api.threatminer.org/v2/domain.php?q=${domain}&rt=5`;
      const res = await fetchUrl(url);
      const data = JSON.parse(res.body);
      const found = new Set();
      for (const sub of (data.results || [])) {
        const lower = sub.toLowerCase().trim();
        if (lower.endsWith(`.${domain}`) || lower === domain) {
          found.add(lower);
        }
      }
      return found;
    },
  },

  // UrlScan.io
  urlscan: {
    name: 'urlscan.io',
    needsKey: false,
    async query(domain) {
      const url = `https://urlscan.io/api/v1/search/?q=domain:${domain}&size=100`;
      const res = await fetchUrl(url);
      const data = JSON.parse(res.body);
      const found = new Set();
      for (const result of (data.results || [])) {
        const page = result.page || {};
        const hostname = (page.domain || '').toLowerCase().trim();
        if (hostname.endsWith(`.${domain}`) || hostname === domain) {
          found.add(hostname);
        }
      }
      return found;
    },
  },

  // Anubis (jldc.me)
  anubis: {
    name: 'Anubis',
    needsKey: false,
    async query(domain) {
      const url = `https://jldc.me/anubis/subdomains/${domain}`;
      const res = await fetchUrl(url);
      const data = JSON.parse(res.body);
      const found = new Set();
      for (const sub of (Array.isArray(data) ? data : [])) {
        const lower = sub.toLowerCase().trim();
        if (lower.endsWith(`.${domain}`) || lower === domain) {
          found.add(lower);
        }
      }
      return found;
    },
  },

  // DNSRepo
  dnsrepo: {
    name: 'DNSRepo',
    needsKey: false,
    async query(domain) {
      const url = `https://dnsrepo.noc.org/?domain=${domain}`;
      const res = await fetchUrl(url);
      return extractSubdomains(res.body, domain);
    },
  },

  // Shodan (needs API key)
  shodan: {
    name: 'Shodan',
    needsKey: true,
    async query(domain, apiKey) {
      const url = `https://api.shodan.io/dns/domain/${domain}?key=${apiKey}`;
      const res = await fetchUrl(url);
      const data = JSON.parse(res.body);
      const found = new Set();
      for (const sub of (data.subdomains || [])) {
        found.add(`${sub}.${domain}`);
      }
      return found;
    },
  },

  // SecurityTrails (needs API key)
  securitytrails: {
    name: 'SecurityTrails',
    needsKey: true,
    async query(domain, apiKey) {
      const url = `https://api.securitytrails.com/v1/domain/${domain}/subdomains?children_only=false&include_inactive=true`;
      const res = await fetchUrl(url, {
        headers: { 'APIKEY': apiKey },
      });
      const data = JSON.parse(res.body);
      const found = new Set();
      for (const sub of (data.subdomains || [])) {
        found.add(`${sub}.${domain}`);
      }
      return found;
    },
  },

  // VirusTotal (needs API key)
  virustotal: {
    name: 'VirusTotal',
    needsKey: true,
    async query(domain, apiKey) {
      const url = `https://www.virustotal.com/api/v3/domains/${domain}/subdomains?limit=40`;
      const res = await fetchUrl(url, {
        headers: { 'x-apikey': apiKey },
      });
      const data = JSON.parse(res.body);
      const found = new Set();
      for (const item of (data.data || [])) {
        const id = (item.id || '').toLowerCase().trim();
        if (id.endsWith(`.${domain}`) || id === domain) {
          found.add(id);
        }
      }
      return found;
    },
  },

};

// Config 
const DEFAULT_CONFIG_PATH = path.join(
  process.env.HOME || process.env.USERPROFILE || '.',
  '.config', 'subfinder-js', 'provider-config.json'
);

function loadConfig(configPath) {
  const p = configPath || DEFAULT_CONFIG_PATH;
  if (fs.existsSync(p)) {
    try {
      return JSON.parse(fs.readFileSync(p, 'utf8'));
    } catch {
      return {};
    }
  }
  return {};
}

// Core Engine 
async function runEnumeration(domain, opts) {
  const config = loadConfig(opts.providerConfig);
  const allResults = new Set();
  const sourceResults = {};

  const selectedSources = opts.sources?.length
    ? opts.sources.filter(s => sources[s])
    : Object.keys(sources).filter(s => !sources[s].needsKey || config[s]);

  if (!opts.silent) {
    console.error(c(C.blue, `[INF]`) + ` Enumerating subdomains for ${c(C.bold, domain)}`);
    console.error(c(C.blue, `[INF]`) + ` Using ${c(C.cyan, selectedSources.length.toString())} sources: ${selectedSources.join(', ')}`);
  }

  const tasks = selectedSources.map(async (sourceName) => {
    const source = sources[sourceName];
    const apiKey = config[sourceName];

    try {
      const found = await Promise.race([
        source.query(domain, apiKey),
        new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), opts.timeout * 1000)),
      ]);

      sourceResults[sourceName] = [...found];
      for (const sub of found) allResults.add(sub);

      if (!opts.silent && found.size > 0) {
        console.error(c(C.green, `[${source.name}]`) + ` Found ${c(C.yellow, found.size.toString())} subdomains`);
      }
    } catch (err) {
      if (opts.verbose && !opts.silent) {
        console.error(c(C.red, `[${source.name}]`) + ` Error: ${err.message}`);
      }
    }
  });

  await Promise.allSettled(tasks);
  return { subdomains: allResults, sourceResults };
}

// Active DNS Verification 
async function verifyActive(subdomains, concurrency = 10) {
  const active = new Set();
  const list = [...subdomains];

  for (let i = 0; i < list.length; i += concurrency) {
    const batch = list.slice(i, i + concurrency);
    await Promise.allSettled(
      batch.map(async (sub) => {
        try {
          await dns.resolve(sub);
          active.add(sub);
        } catch { /* not resolvable */ }
      })
    );
  }
  return active;
}

// CLI
function parseArgs(argv) {
  const args = argv.slice(2);
  const opts = {
    domains: [],
    domainList: null,
    sources: [],
    excludeSources: [],
    output: null,
    json: false,
    silent: false,
    verbose: false,
    active: false,
    timeout: 30,
    noColor: false,
    listSources: false,
    providerConfig: null,
    match: [],
    filter: [],
  };

  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    switch (a) {
      case '-d': case '--domain':
        opts.domains.push(...(args[++i] || '').split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '-dL': case '--list':
        opts.domainList = args[++i]; break;
      case '-s': case '--sources':
        opts.sources.push(...(args[++i] || '').split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '-es': case '--exclude-sources':
        opts.excludeSources.push(...(args[++i] || '').split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '-o': case '--output':
        opts.output = args[++i]; break;
      case '-oJ': case '--json':
        opts.json = true; break;
      case '-silent':
        opts.silent = true; break;
      case '-v':
        opts.verbose = true; break;
      case '-nW': case '--active':
        opts.active = true; break;
      case '-timeout':
        opts.timeout = parseInt(args[++i]) || 30; break;
      case '-nc': case '--no-color':
        opts.noColor = true; break;
      case '-ls': case '--list-sources':
        opts.listSources = true; break;
      case '-pc': case '--provider-config':
        opts.providerConfig = args[++i]; break;
      case '-m': case '--match':
        opts.match.push(...(args[++i] || '').split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '-f': case '--filter':
        opts.filter.push(...(args[++i] || '').split(',').map(s => s.trim()).filter(Boolean));
        break;
      case '-h': case '--help':
        printHelp(); process.exit(0); break;
      case '--version':
        console.log('subfinder-js v1.0.0'); process.exit(0); break;
    }
  }

  return opts;
}

function printHelp() {
  console.log(`
${c(C.bold, 'Usage:')}
  subfinder.js [flags]

${c(C.bold, 'Flags:')}
  ${c(C.cyan, 'INPUT:')}
    -d,  -domain string[]    domains to find subdomains for (comma separated)
    -dL, -list string        file containing list of domains

  ${c(C.cyan, 'SOURCE:')}
    -s,  -sources string[]        sources to use (-s crtsh,hackertarget)
    -es, -exclude-sources string[] sources to exclude
    -ls, -list-sources            list all available sources

  ${c(C.cyan, 'FILTER:')}
    -m, -match string[]   subdomains to match (comma separated patterns)
    -f, -filter string[]  subdomains to filter out

  ${c(C.cyan, 'OUTPUT:')}
    -o,  -output string   file to write output to
    -oJ, -json            write output in JSON format
    -silent               show only subdomains
    -v                    verbose output

  ${c(C.cyan, 'CONFIGURATION:')}
    -pc, -provider-config string  provider config file (default: ~/.config/subfinder-js/provider-config.json)
    -nW, -active                  verify subdomains via DNS
    -timeout int                  timeout in seconds (default 30)
    -nc, -no-color                disable color
    --version                     show version

${c(C.bold, 'Provider Config Example (~/.config/subfinder-js/provider-config.json):')}
  {
    "shodan": "YOUR_SHODAN_API_KEY",
    "securitytrails": "YOUR_ST_API_KEY",
    "virustotal": "YOUR_VT_API_KEY"
  }

${c(C.bold, 'Examples:')}
  node subfinder.js -d example.com
  node subfinder.js -d example.com -s crtsh,hackertarget -oJ
  node subfinder.js -dL domains.txt -o results.txt -silent
  node subfinder.js -d example.com -nW -v
`);
}

function filterSubdomains(subdomains, match, filter) {
  let results = [...subdomains];

  if (match.length > 0) {
    results = results.filter(s => match.some(m => s.includes(m)));
  }
  if (filter.length > 0) {
    results = results.filter(s => !filter.some(f => s.includes(f)));
  }

  return results.sort();
}

async function main() {
  const opts = parseArgs(process.argv);

  if (opts.noColor) useColor = false;

  if (!opts.silent) printBanner();

  // List sources
  if (opts.listSources) {
    console.log(c(C.bold, '\nAvailable Sources:\n'));
    for (const [key, src] of Object.entries(sources)) {
      const keyTag = src.needsKey ? c(C.yellow, ' [API key required]') : c(C.green, ' [free]');
      console.log(`  ${c(C.cyan, key.padEnd(20))} ${src.name}${keyTag}`);
    }
    console.log('');
    process.exit(0);
  }

  // Load domain list
  if (opts.domainList) {
    const lines = fs.readFileSync(opts.domainList, 'utf8').split('\n');
    opts.domains.push(...lines.map(l => l.trim()).filter(Boolean));
  }

  if (opts.domains.length === 0) {
    console.error(c(C.red, '[ERR]') + ' No domain specified. Use -d <domain> or -dL <file>');
    printHelp();
    process.exit(1);
  }

  // Remove excluded sources
  if (opts.excludeSources.length > 0) {
    opts.sources = Object.keys(sources).filter(
      s => !opts.excludeSources.includes(s)
    );
  }

  const outputLines = [];

  for (const domain of opts.domains) {
    if (!opts.silent) {
      console.error(c(C.blue, `\n[INF]`) + ` Starting enumeration for: ${c(C.bold + C.cyan, domain)}`);
    }

    try {
      let { subdomains, sourceResults } = await runEnumeration(domain, opts);

      // DNS verification
      if (opts.active) {
        if (!opts.silent) console.error(c(C.blue, `[INF]`) + ` Verifying subdomains via DNS...`);
        subdomains = await verifyActive(subdomains);
        if (!opts.silent) console.error(c(C.blue, `[INF]`) + ` Active subdomains: ${c(C.green, subdomains.size.toString())}`);
      }

      // Filter
      const filtered = filterSubdomains(subdomains, opts.match, opts.filter);

      if (!opts.silent) {
        console.error(c(C.blue, `[INF]`) + ` Total unique subdomains found: ${c(C.green + C.bold, filtered.length.toString())}\n`);
      }

      // Output
      for (const sub of filtered) {
        if (opts.json) {
          const line = JSON.stringify({
            host: sub,
            domain,
            sources: Object.entries(sourceResults)
              .filter(([, subs]) => subs.includes(sub))
              .map(([name]) => name),
          });
          console.log(line);
          outputLines.push(line);
        } else {
          console.log(sub);
          outputLines.push(sub);
        }
      }

    } catch (err) {
      console.error(c(C.red, `[ERR]`) + ` Failed for ${domain}: ${err.message}`);
    }
  }

  // Write to file
  if (opts.output && outputLines.length > 0) {
    fs.writeFileSync(opts.output, outputLines.join('\n') + '\n', 'utf8');
    if (!opts.silent) console.error(c(C.blue, `[INF]`) + ` Results written to: ${opts.output}`);
  }
}

main().catch(err => {
  console.error(c(C.red, `[FATAL]`) + ` ${err.message}`);
  process.exit(1);
});

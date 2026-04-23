// Honeypot request analyzer — runs server-side after log parsing.
// Replaces the Arduino's looksSuspicious() with broader, more precise checks.
//
// Detection categories:
//   UA_SCANNER       — known attack/scan tool User-Agents (sqlmap, nikto, nmap, …)
//   UA_AUTOMATED     — generic HTTP client libraries (curl, python-requests, …)
//   UA_EMPTY         — missing or near-empty User-Agent
//   PATH_TRAVERSAL   — ../ and encoded variants
//   LFI              — /etc/passwd, .env, .git, wp-config, …
//   SQLI             — UNION SELECT, OR 1=1, sleep(), benchmark(), …
//   XSS              — <script>, onerror=, javascript:, eval(), …
//   CMDI             — shell metacharacters, $(), backticks, powershell
//   PROBE_CMS        — WordPress, phpMyAdmin, Tomcat, Spring, …
//   PROBE_WEBSHELL   — shell.php, cmd.php, backdoor filenames
//   METHOD           — TRACE, CONNECT, TRACK
//   LONG_URI         — URI > 250 chars (evasion / overflow attempt)
//   DEVICE_FLAG      — passed through from Arduino when backend finds nothing else

// ── User-Agent: known attack/scan tools ────────────────────────────────────
const SCANNER_UA = [
    'sqlmap', 'nikto', 'nmap', 'masscan',
    'dirbuster', 'gobuster', 'feroxbuster', 'ffuf', 'wfuzz',
    'burpsuite', 'burp suite', 'owasp zap', 'zaproxy',
    'metasploit', 'msfconsole',
    'hydra', 'medusa', 'patator',
    'acunetix', 'nessus', 'openvas', 'qualys', 'nexpose',
    'w3af', 'skipfish', 'arachni', 'nuclei',
    'havij', 'pangolin', 'jsql', 'bbqsql',
    'zgrab', 'shodan', 'censys', 'binaryedge',
    'scrapy', 'mechanize',
];

// ── User-Agent: generic HTTP clients (automated, not necessarily malicious) ─
const AUTOMATED_UA = [
    'python-requests', 'python-urllib', 'python-httpx',
    'go-http-client',
    'libwww-perl', 'lwp-useragent',
    'java/', 'jakarta commons-httpclient', 'apache-httpclient',
    'curl/', 'wget/',
    'axios/', 'node-fetch', 'got/', 'superagent',
    'okhttp', 'httpclient',
];

// ── PATH-only rules: traversal, LFI, probe paths ────────────────────────────
// Applied only to the URL path — these patterns are not meaningful in form body.
const PATH_RULES = [

    // Path traversal
    { re: /\.\.[\\/]/,                              reason: 'PATH_TRAVERSAL: ../'             },
    { re: /(?:%2e){2}(?:%2f|%5c)/i,                reason: 'PATH_TRAVERSAL: encoded %2e%2e'  },
    { re: /\.\.(?:%2f|%5c)/i,                       reason: 'PATH_TRAVERSAL: mixed encoding'  },
    { re: /%252e%252e/i,                            reason: 'PATH_TRAVERSAL: double-encoded'  },

    // Local File Inclusion / sensitive files
    { re: /\/etc\/(?:passwd|shadow|hosts|crontab)/i, reason: 'LFI: /etc/ sensitive file'     },
    { re: /\/proc\/self/i,                           reason: 'LFI: /proc/self'                },
    { re: /boot\.ini/i,                              reason: 'LFI: boot.ini'                  },
    { re: /win(?:dows)?[/\\]system32/i,              reason: 'LFI: Windows system32'          },
    { re: /\/\.env(?:$|[?&#/])/i,                   reason: 'LFI: .env file probe'            },
    { re: /\/\.git\//i,                              reason: 'LFI: .git directory'             },
    { re: /\/\.htaccess/i,                           reason: 'LFI: .htaccess'                  },
    { re: /wp-config\.php/i,                         reason: 'LFI: wp-config.php'              },
    { re: /\/\.ssh\//i,                              reason: 'LFI: .ssh directory'             },
    { re: /\/\.aws\//i,                              reason: 'LFI: .aws credentials'           },

    // CMS / service probes
    { re: /\/wp-admin\b/i,                           reason: 'PROBE: WordPress admin'           },
    { re: /\/wp-login\.php/i,                        reason: 'PROBE: WordPress login'           },
    { re: /\/xmlrpc\.php/i,                          reason: 'PROBE: WordPress xmlrpc'          },
    { re: /\/phpmyadmin\b/i,                         reason: 'PROBE: phpMyAdmin'                },
    { re: /\/administrator\b/i,                      reason: 'PROBE: CMS administrator'         },
    { re: /\/manager\/html\b/i,                      reason: 'PROBE: Tomcat manager'            },
    { re: /\/actuator(?:$|\/)/i,                     reason: 'PROBE: Spring Boot actuator'      },
    { re: /\/solr(?:$|\/)/i,                         reason: 'PROBE: Apache Solr'               },
    { re: /\/jmx-console/i,                          reason: 'PROBE: JBoss JMX console'         },
    { re: /\/_ignition\//i,                          reason: 'PROBE: Laravel Ignition RCE path' },
    { re: /\/jenkins(?:$|\/)/i,                      reason: 'PROBE: Jenkins'                   },
    { re: /\/hudson(?:$|\/)/i,                       reason: 'PROBE: Hudson CI'                 },
    { re: /\/\.well-known\/security/i,               reason: 'PROBE: security.txt recon'        },

    // Webshell filenames
    { re: /(?:shell|cmd|exec|backdoor|c99|r57|b374k|wso)\.php/i, reason: 'PROBE: webshell filename' },
    { re: /\/cgi-bin\/.*\.(?:sh|pl|py|rb)\b/i,      reason: 'PROBE: CGI script execution'     },
];

// ── CONTENT rules: injection payloads ───────────────────────────────────────
// Applied to BOTH the URL path AND the POST body (form fields).
// This is what catches SQLi / XSS / CMDi submitted through login forms.
const CONTENT_RULES = [

    // SQL injection
    { re: /\bunion\s+(?:all\s+)?select\b/i,          reason: 'SQLI: UNION SELECT'              },
    { re: /'\s*(?:or|and)\s+(?:'1'\s*=\s*'1'?|1\s*=\s*1)/i, reason: 'SQLI: OR/AND 1=1'       },
    { re: /"\s*(?:or|and)\s+(?:"1"\s*=\s*"1"?|1\s*=\s*1)/i, reason: 'SQLI: OR/AND 1=1'       },
    { re: /\bsleep\s*\(\s*\d{1,4}\s*\)/i,            reason: 'SQLI: sleep()'                   },
    { re: /\bbenchmark\s*\(\s*\d/i,                  reason: 'SQLI: benchmark()'               },
    { re: /waitfor\s+delay\s*'/i,                    reason: 'SQLI: WAITFOR DELAY (MSSQL)'     },
    { re: /;\s*drop\s+table\b/i,                     reason: 'SQLI: DROP TABLE'                },
    { re: /\bpg_sleep\s*\(/i,                        reason: 'SQLI: pg_sleep() (PostgreSQL)'   },
    { re: /select%20.{1,50}%20from\b/i,              reason: 'SQLI: SELECT FROM (encoded)'     },
    { re: /(?:--|#)\s*(?:$|\n)/m,                    reason: 'SQLI: SQL comment terminator'    },
    { re: /'\s*;\s*(?:select|insert|update|delete|drop|create|alter)\b/i, reason: 'SQLI: stacked query' },

    // XSS
    { re: /<script[\s>/]/i,                          reason: 'XSS: <script> tag'               },
    { re: /%3cscript/i,                              reason: 'XSS: encoded <script>'            },
    { re: /javascript\s*:/i,                         reason: 'XSS: javascript: URI'            },
    { re: /\bonerror\s*=/i,                          reason: 'XSS: onerror='                   },
    { re: /\bonload\s*=/i,                           reason: 'XSS: onload='                    },
    { re: /\bonfocus\s*=/i,                          reason: 'XSS: onfocus='                   },
    { re: /\beval\s*\(/i,                            reason: 'XSS/CMDI: eval()'                },
    { re: /&#x?[0-9a-f]+;.*(?:script|onerror)/i,    reason: 'XSS: HTML entity obfuscation'    },

    // Command injection
    { re: /[;&|`]\s*(?:ls|cat|id|whoami|uname|pwd|env|printenv)\b/i, reason: 'CMDI: shell command' },
    { re: /\$\([^)]{1,80}\)/,                        reason: 'CMDI: $() subshell'              },
    { re: /`[^`]{1,80}`/,                            reason: 'CMDI: backtick subshell'         },
    { re: /\bpowershell(?:\.exe)?\b/i,               reason: 'CMDI: PowerShell reference'      },
    { re: /\bcmd(?:\.exe)?\b.*\/c\b/i,               reason: 'CMDI: cmd /c'                    },
    { re: /(?:^|[?&])(?:cmd|exec|command|shell)\s*=/i, reason: 'CMDI: injection parameter'    },
];

const SUSPICIOUS_METHODS = new Set(['TRACE', 'CONNECT', 'TRACK']);

// ── Main analysis function ──────────────────────────────────────────────────
// parsed — output of parseLogLine (may be null for unparseable lines).
//   parsed.body carries POST form data (e.g. "username=...&password=...")
//   when the Arduino appended it to the log line.
function analyze(parsed) {
    const reasons = [];

    if (!parsed) {
        return { suspicious: false, reasons };
    }

    const path   = parsed.path        || '';
    const body   = parsed.body        || '';
    const ua     = (parsed.user_agent || '').toLowerCase().trim();
    const method = (parsed.method     || '').toUpperCase();

    // 1. Known scanner/attack tool UA
    for (const sig of SCANNER_UA) {
        if (ua.includes(sig)) {
            reasons.push(`UA_SCANNER: ${sig}`);
            break;
        }
    }

    // 2. Automated HTTP library UA (only if not already a scanner)
    if (reasons.length === 0) {
        for (const sig of AUTOMATED_UA) {
            if (ua.includes(sig)) {
                reasons.push(`UA_AUTOMATED: ${sig}`);
                break;
            }
        }
    }

    // 3. Empty / very short UA (no legitimate browser has a UA under 8 chars)
    if (!ua || ua === '-' || ua.length < 8) {
        reasons.push('UA_EMPTY: missing or near-empty user-agent');
    }

    // 4. Path-only patterns (traversal, LFI, probe paths)
    for (const { re, reason } of PATH_RULES) {
        if (re.test(path)) {
            reasons.push(reason);
        }
    }

    // 5. Content patterns — checked against BOTH path and body.
    //    This catches SQLi / XSS / CMDi submitted through form fields.
    for (const { re, reason } of CONTENT_RULES) {
        const inPath = re.test(path);
        const inBody = body && re.test(body);
        if (inPath || inBody) {
            reasons.push(reason + (inBody && !inPath ? ' (in body)' : ''));
        }
    }

    // 6. Very long URI — evasion / buffer overflow attempt
    if (path.length > 250) {
        reasons.push(`LONG_URI: ${path.length} chars`);
    }

    // 7. Inherently suspicious HTTP methods
    if (SUSPICIOUS_METHODS.has(method)) {
        reasons.push(`METHOD: ${method}`);
    }

    return {
        suspicious: reasons.length > 0,
        reasons,
    };
}

// Summarise what this module can detect — used by /api/analyzer/capabilities
const CAPABILITIES = [
    'UA_SCANNER       — sqlmap, nikto, nmap, masscan, gobuster, ffuf, wfuzz, burp, zap, metasploit, hydra, acunetix, nessus, nuclei, zgrab, shodan, …',
    'UA_AUTOMATED     — curl, wget, python-requests, go-http-client, libwww-perl, axios, okhttp, …',
    'UA_EMPTY         — missing or near-empty User-Agent string',
    'PATH_TRAVERSAL   — ../, encoded (%2e%2e), double-encoded (%252e%252e)',
    'LFI              — /etc/passwd, /etc/shadow, /proc/self, boot.ini, .env, .git/, .htaccess, wp-config.php, .ssh/, .aws/',
    'SQLI             — UNION SELECT, OR/AND 1=1, sleep(), benchmark(), WAITFOR DELAY, DROP TABLE, pg_sleep(), SQL comments, stacked queries (in URL path AND form body)',
    'XSS              — <script>, onerror=, onload=, onfocus=, javascript:, eval(), HTML entity obfuscation (in URL path AND form body)',
    'CMDI             — shell metacharacters (;|&), $() subshell, backtick, powershell, cmd /c, injection params (in URL path AND form body)',
    'PROBE_CMS        — WordPress (wp-admin, xmlrpc, wp-login), phpMyAdmin, Tomcat manager, Spring actuator, Solr, Jenkins, Laravel Ignition',
    'PROBE_WEBSHELL   — shell.php, cmd.php, c99.php, r57.php, b374k, wso, CGI script probes',
    'METHOD           — TRACE, CONNECT, TRACK',
    'LONG_URI         — URI longer than 250 characters',
];

module.exports = { analyze, CAPABILITIES };

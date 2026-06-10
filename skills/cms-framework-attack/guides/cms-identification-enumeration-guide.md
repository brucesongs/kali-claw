# CMS Identification and Enumeration Guide

## Introduction

The first critical step in any CMS-targeted security assessment is accurate identification of the platform, version, and installed extensions. Misidentifying the CMS leads to wasted time running the wrong tools and missing actual vulnerabilities. This guide covers the complete CMS fingerprinting and enumeration methodology using CMSeeK for deep CMS identification, WhatWeb for technology fingerprinting, and nuclei for automated template-based scanning. The guide then maps discovered version information to known exploits, creating a targeted attack plan.

CMS fingerprinting is both an art and a science. While automated tools like CMSeeK can identify over 180 CMS platforms, manual verification through HTTP probes, file path analysis, and response header inspection remains essential for accurate results. Many hardened installations deliberately obscure CMS fingerprints by removing generator meta tags, blocking access to version files, and modifying default paths. This guide addresses both standard and hardened CMS detection, providing techniques that work even when the target attempts to hide its identity.

---

## Phase 1: Automated CMS Identification with CMSeeK

### CMSeeK Overview

CMSeeK is a specialized CMS identification tool that detects over 180 Content Management Systems through a combination of file path probing, meta tag analysis, header inspection, and pattern matching. Unlike general-purpose fingerprinting tools, CMSeeK focuses exclusively on CMS platforms and provides deep detection including version numbers, installed extensions, and known misconfigurations.

### Basic CMSeeK Usage

```bash
# Standard CMS identification
cmseek -u http://target

# Follow HTTP redirects before scanning
cmseek -u http://target --follow-redirect

# Use custom user agent to avoid WAF detection
cmseek -u http://target --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Batch scan multiple targets
cmseek -l targets.txt

# Scan with verbose output
cmseek -u http://target -v
```

### Targeted CMS Detection

When preliminary reconnaissance suggests a specific CMS, use targeted detection mode for faster and more accurate results.

```bash
# WordPress-specific detection
cmseek -u http://target --wordpress

# Joomla-specific detection
cmseek -u http://target --joomla

# Drupal-specific detection
cmseek -u http://target --drupal
```

### CMSeeK Detection Methods

CMSeeK employs multiple detection strategies that cross-reference each other for accurate identification:

1. **HTTP Header Analysis**: Examines `X-Powered-By`, `X-Generator`, `X-Pingback`, `Link`, and `Set-Cookie` headers for CMS-specific values
2. **Meta Tag Inspection**: Checks `<meta name="generator">` and other meta tags that CMS platforms insert by default
3. **File Path Probing**: Tests for CMS-specific files like `wp-login.php`, `administrator/`, `CHANGELOG.txt`, `readme.html`
4. **RSS/Atom Feed Analysis**: Examines feed structure and namespace declarations that identify the CMS platform
5. **JavaScript/CSS Path Patterns**: Identifies CMS-specific directory structures in linked resources
6. **Cookie Name Patterns**: Checks for CMS-specific cookies (e.g., `wordpress_logged_in_`, `joomla_`, `SSESS`)

### Interpreting CMSeeK Results

CMSeeK output includes the detected CMS name, confidence level, version (if detected), and a list of detected technologies. Cross-reference high-confidence results with WhatWeb for validation. If CMSeeK and WhatWeb disagree on the CMS type, perform manual verification through the techniques described in Phase 3.

---

## Phase 2: Technology Fingerprinting with WhatWeb

### WhatWeb Overview

WhatWeb is a web technology fingerprinting tool that identifies CMS platforms, web servers, JavaScript libraries, analytics tools, and other technologies from a single URL scan. While CMSeeK focuses on CMS identification, WhatWeb provides broader technology stack visibility that informs exploitation strategy.

### Basic WhatWeb Usage

```bash
# Standard scan
whatweb http://target

# Verbose output with all plugin details
whatweb -v http://target

# Aggressive mode (activates all plugins)
whatweb -a 3 http://target

# Scan multiple targets
whatweb -i targets.txt

# Output to file in various formats
whatweb http://target -o results.json --log-json results.json
```

### WhatWeb Plugin Categories

WhatWeb's plugin architecture covers the following technology categories relevant to CMS assessment:

| Category | Examples | Relevance |
|----------|---------|-----------|
| **CMS Detection** | WordPress, Joomla, Drupal, Magento, Shopify | Primary target identification |
| **Web Server** | Apache, Nginx, IIS, LiteSpeed | Server-level vulnerability mapping |
| **Programming Language** | PHP, ASP.NET, Ruby, Python | Exploit payload language selection |
| **JavaScript Framework** | jQuery, React, Vue, Angular | Client-side attack surface |
| **Analytics** | Google Analytics, Matomo, Piwik | Third-party integration assessment |
| **Security** | Cloudflare, Sucuri, Wordfence | WAF/defense detection |

### Combining WhatWeb with CMSeeK

Run both tools against the same target and compare results for higher confidence identification.

```bash
# Run both tools in sequence
cmseek -u http://target --follow-redirect > cmseek_results.txt 2>&1
whatweb -v http://target > whatweb_results.txt 2>&1

# Extract and compare CMS detection
grep -i "cms\|wordpress\|joomla\|drupal" cmseek_results.txt
grep -i "cms\|wordpress\|joomla\|drupal" whatweb_results.txt
```

When both tools agree on the CMS type, proceed to targeted scanning with the platform-specific tool. When they disagree, escalate to manual verification.

---

## Phase 3: Manual CMS Verification Techniques

### WordPress Manual Detection

WordPress installations leave identifiable traces even when version information is stripped. Verify WordPress through multiple independent indicators.

```bash
# WordPress-specific file paths
curl -s http://target/wp-login.php | head -5
curl -s http://target/wp-content/ | head -5
curl -s http://target/wp-includes/ | head -5
curl -s http://target/xmlrpc.php | head -5
curl -s http://target/wp-cron.php

# WordPress version detection via readme.html
curl -s http://target/readme.html | grep -i "version"

# WordPress feed detection
curl -s http://target/feed/ | grep -i "wordpress"

# WordPress REST API
curl -s http://target/wp-json/ | jq .

# WordPress HTTP header indicators
curl -sI http://target | grep -i "x-pingback\|link:.*wp-json"
```

### Joomla Manual Detection

```bash
# Joomla-specific paths
curl -s http://target/administrator/ | grep -i "joomla"
curl -s http://target/language/en-GB/en-GB.ini | head -5
curl -s http://target/media/jui/ | head -5

# Joomla version via manifest
curl -s http://target/administrator/manifests/files/joomla.xml | grep -i version

# Joomla README
curl -s http://target/README.txt | grep -i "joomla"

# Joomla media paths
curl -s http://target/media/system/js/ | head -5
curl -s http://target/media/joomla/ | head -5
```

### Drupal Manual Detection

```bash
# Drupal CHANGELOG files (primary version indicator)
curl -s http://target/CHANGELOG.txt | head -5
curl -s http://target/core/CHANGELOG.txt | head -5

# Drupal-specific paths
curl -s http://target/misc/drupal.js | head -3
curl -s http://target/core/misc/drupal.js | head -3
curl -s http://target/sites/default/settings.php > /dev/null 2>&1

# Drupal generator meta tag
curl -s http://target/ | grep -i "drupal\|generator"

# Drupal REST endpoints
curl -s http://target/jsonapi
curl -s http://target/node?_format=hal_json
```

### Hardened CMS Detection

When administrators actively hide CMS fingerprints, use deeper analysis techniques.

```bash
# Analyze CSS/JS file paths for CMS patterns
curl -s http://target/ | grep -oP 'src="[^"]*\.js"' | grep -i "wp-\|joomla\|drupal\|sites/all\|core/"

# Analyze form action URLs
curl -s http://target/ | grep -oP 'action="[^"]*"' | grep -i "wp-\|index.php?option"

# Analyze cookie names
curl -sI http://target | grep -i "set-cookie" | grep -i "wordpress\|joomla\|SSESS\|DRUPAL"

# Check robots.txt for CMS-specific disallowed paths
curl -s http://target/robots.txt | grep -i "wp-\|administrator\|sites/default"

# Check for CMS-specific 404 pages
curl -s http://target/nonexistent-page-12345 | grep -i "wordpress\|joomla\|drupal"

# CSS class pattern analysis
curl -s http://target/ | grep -oP 'class="[^"]*"' | grep -i "wp-\|joomla\|drupal\|node-\|page-node"
```

---

## Phase 4: Version-to-Exploit Mapping

### CVE Database Lookup Process

Once the CMS version is identified, map it to known vulnerabilities through systematic database queries.

```bash
# Search Exploit-DB for platform-specific exploits
searchsploit wordpress 6.0
searchsploit joomla 4.2
searchsploit drupal 8.5

# Search by CMS and vulnerability type
searchsploit wordpress plugin file upload
searchsploit joomla component sql injection
searchsploit drupal rce
```

### WordPress Version-to-Exploit Quick Reference

| WordPress Version | Critical CVE | Impact | Exploit Method |
|-------------------|-------------|--------|----------------|
| < 4.2.1 | CVE-2015-3440 | Stored XSS | Comment length truncation bypass |
| < 4.4.2 | CVE-2016-1562 | Auth bypass | Cookie authentication weakness |
| < 4.7.1 | CVE-2017-5487 | Info disclosure | REST API user enumeration |
| < 5.0.1 | CVE-2019-8943 | Object injection | wp-includes/meta.php deserialization |
| < 5.2.3 | CVE-2019-16223 | XSS | Media upload path traversal |
| < 5.4.1 | CVE-2020-11027 | XSS | Comment XSS via open redirect |

### Joomla Version-to-Exploit Quick Reference

| Joomla Version | Critical CVE | Impact | Exploit Method |
|----------------|-------------|--------|----------------|
| 1.5 - 3.4.5 | CVE-2015-8562 | RCE | HTTP header PHP object injection |
| 3.2.0 - 3.4.4 | CVE-2015-7297 | SQL Injection | Session hijacking via SQLi |
| 3.0.0 - 3.4.6 | CVE-2016-8869 | Privilege Escalation | User registration privilege escalation |
| 3.4.4 - 3.6.3 | CVE-2016-9838 | RCE | Joomla! cache handler deserialization |
| 3.5.0 - 3.6.3 | CVE-2016-8870 | Auth Bypass | Elevated privileges registration |
| 4.0.0 - 4.2.7 | CVE-2023-23752 | Info Disclosure | API endpoint unauthorized access |

### Drupal Version-to-Exploit Quick Reference

| Drupal Version | Critical CVE | Impact | Exploit Method |
|----------------|-------------|--------|----------------|
| 7.0 - 7.31 | CVE-2014-3704 | SQL Injection | expandArguments array injection (Drupalgeddon) |
| 7.x, 8.x | CVE-2018-7600 | RCE | Render API #post_render callback (Drupalgeddon2) |
| 7.x, 8.x | CVE-2018-7602 | RCE | Authenticated render API exploitation |
| 8.x | CVE-2019-6340 | RCE | REST API field type confusion via deserialization |
| 7.x, 8.x, 9.x | CVE-2020-13693 | Info Disclosure | File upload type confusion |

---

## Phase 5: Nuclei CMS Template Scanning

### nuclei Template Categories for CMS Assessment

nuclei provides the most comprehensive automated CMS vulnerability scanning through its template library. Templates are organized by CMS platform and vulnerability type.

```bash
# Update templates to latest version
nuclei -update-templates

# List available CMS-related templates
nuclei -tl | grep -i "wordpress\|joomla\|drupal\|cms" | wc -l
```

### WordPress nuclei Scanning

```bash
# All WordPress CVE templates
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags wordpress -rl 50

# WordPress exposed files and directories
nuclei -u http://target -t ~/nuclei-templates/http/exposures/ -tags wordpress

# WordPress misconfigurations
nuclei -u http://target -t ~/nuclei-templates/http/misconfiguration/ -tags wordpress

# WordPress user enumeration templates
nuclei -u http://target -t ~/nuclei-templates/http/technologies/wordpress/

# Full WordPress scan with all related templates
nuclei -u http://target -tags wordpress -rl 50 -c 25 -bs 25
```

### Joomla nuclei Scanning

```bash
# All Joomla CVE templates
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags joomla -rl 50

# Joomla exposed files
nuclei -u http://target -t ~/nuclei-templates/http/exposures/ -tags joomla

# Joomla component vulnerabilities
nuclei -u http://target -t ~/nuclei-templates/http/vulnerabilities/joomla/

# Full Joomla scan
nuclei -u http://target -tags joomla -rl 50 -c 25
```

### Drupal nuclei Scanning

```bash
# All Drupal CVE templates
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags drupal -rl 50

# Drupal-specific vulnerability templates
nuclei -u http://target -t ~/nuclei-templates/http/vulnerabilities/drupal/

# Drupalgeddon-specific templates
nuclei -u http://target -t ~/nuclei-templates/http/cves/ -tags drupalgeddon

# Full Drupal scan
nuclei -u http://target -tags drupal -rl 50 -c 25
```

### nuclei Output and Reporting

```bash
# Save results in multiple formats
nuclei -u http://target -tags cms -o results.txt -json -irr

# Parse JSON results for reporting
cat results.txt | jq -r '.info | "[\(.severity)] \(.name) - \(.description)"'

# Generate HTML report
nuclei -u http://target -tags cms -html-report cms_report.html

# Filter by severity
nuclei -u http://target -tags cms -severity critical,high
```

### nuclei Rate Limiting for Stealth

During assessments where stealth is required, control nuclei's request rate to stay below WAF detection thresholds.

```bash
# Conservative rate limiting (50 requests/minute, 25 concurrent)
nuclei -u http://target -tags cms -rl 50 -c 25 -bs 25

# Very slow scanning for sensitive environments
nuclei -u http://target -tags cms -rl 10 -c 5 -bs 5

# Random delays between requests
nuclei -u http://target -tags cms -rl 30 -c 10 -bs 10 -delay 2s
```

---

## Integration: From Fingerprinting to Exploitation

The complete CMS assessment workflow chains identification tools into targeted scanners based on detected platform.

```bash
# Step 1: Identify CMS
cms_type=$(cmseek -u http://target 2>/dev/null | grep -oP "(WordPress|Joomla|Drupal)")

# Step 2: Dispatch platform-specific scanner
case "$cms_type" in
  "WordPress")
    wpscan --url http://target --enumerate u,vp,vt,dbe,cb --api-token TOKEN
    nuclei -u http://target -tags wordpress -rl 50
    ;;
  "Joomla")
    joomscan -u http://target --scan-all
    nuclei -u http://target -tags joomla -rl 50
    ;;
  "Drupal")
    droopescan scan drupal -u http://target -t 16
    nuclei -u http://target -tags drupal -rl 50
    ;;
  *)
    echo "Unknown CMS or detection failed. Run manual fingerprinting."
    ;;
esac

# Step 3: Run generic CMS scanning regardless of platform
nuclei -u http://target -t ~/nuclei-templates/http/exposures/configs/ -rl 50
nikto -h http://target -C all
```

This automated dispatch ensures the right tools are used for each platform while maintaining comprehensive coverage through generic scanning layers.

---

## References

- [CMSeeK GitHub Repository](https://github.com/Tuhinshubhra/CMSeeK) -- CMS identification tool supporting 180+ platforms
- [WhatWeb GitHub Repository](https://github.com/urbanadventurer/WhatWeb) -- web technology fingerprinting tool
- [nuclei Template Repository](https://github.com/projectdiscovery/nuclei-templates) -- community-maintained vulnerability detection templates
- [Wappalyzer Technology Detection](https://www.wappalyzer.com/) -- browser extension for technology identification
- [BuiltWith Technology Lookup](https://builtwith.com/) -- online technology profiling service
- [CMS Explorer](https://github.com/droope/droopescan) -- Droopescan CMS scanning documentation
- [Exploit-DB Search](https://www.exploit-db.com/) -- searchable vulnerability and exploit database
- [NVD - National Vulnerability Database](https://nvd.nist.gov/) -- comprehensive CVE database
- [ProjectDiscovery nuclei Documentation](https://docs.projectdiscovery.io/nuclei/) -- nuclei scanner documentation and guides
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) -- comprehensive web application testing methodology

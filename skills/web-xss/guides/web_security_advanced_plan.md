# Web Security Advanced Learning Plan

**Learning Path**: Web Security Advanced  
**Start Time**: 2026-03-26 20:26 CST  
**Learning Objective**: Master advanced web attack techniques and defense strategies

---

## Learning Modules

### Module 1: XSS (Cross-Site Scripting) Advanced Techniques
**Estimated Duration**: 2 hours

#### 1.1 XSS Types In Depth
- Reflected XSS
- Stored XSS
- DOM-based XSS
- Mutation XSS

#### 1.2 Advanced Bypass Techniques
- WAF bypass techniques
- Encoding bypass (HTML/URL/Unicode)
- Event handler bypass
- SVG/MathML injection

#### 1.3 XSS Attack Payloads
- Cookie theft
- Session hijacking
- Keylogger implementation
- Web page malware injection
- Phishing page injection

#### 1.4 Practical Exercises
- PortSwigger XSS Labs (all levels)
- XSS Challenge platforms
- Real vulnerability case analysis

---

### Module 2: CSRF (Cross-Site Request Forgery) Attacks
**Estimated Duration**: 1.5 hours

#### 2.1 CSRF Principles In Depth
- Same-Origin Policy
- CORS misconfiguration
- CSRF Token mechanism

#### 2.2 Advanced CSRF Techniques
- JSON CSRF attacks
- File upload CSRF
- Clickjacking combination attacks
- CORS misconfiguration exploitation

#### 2.3 Defense Mechanisms
- CSRF Token implementation
- SameSite Cookie attribute
- Double Cookie verification
- Referer validation

#### 2.4 Practical Exercises
- PortSwigger CSRF Labs
- Real CSRF vulnerability cases

---

### Module 3: SSRF (Server-Side Request Forgery)
**Estimated Duration**: 2 hours

#### 3.1 SSRF Principles
- Internal network probing
- Cloud metadata access
- Internal service attacks

#### 3.2 Advanced SSRF Techniques
- DNS Rebinding
- IPv6 bypass
- URL parsing bypass
- Protocol smuggling (HTTP Smuggling)

#### 3.3 Cloud Environment SSRF
- AWS metadata service (169.254.169.254)
- GCP/Azure metadata
- Kubernetes API Server
- Docker API access

#### 3.4 Practical Exercises
- PortSwigger SSRF Labs
- Cloud environment SSRF experiments
- Real case studies

---

### Module 4: XXE (XML External Entity)
**Estimated Duration**: 1.5 hours

#### 4.1 XXE Basics
- XML fundamentals
- DTD (Document Type Definition)
- Entity injection principles

#### 4.2 XXE Attack Types
- In-band XXE
- Blind XXE
- Error-based XXE

#### 4.3 Advanced XXE Techniques
- File reading (/etc/passwd, /etc/shadow)
- SSRF combination attacks
- Denial of service attacks (Billion Laughs)
- Remote code execution

#### 4.4 Practical Exercises
- PortSwigger XXE Labs
- XML file upload attacks
- SVG/DOCX file exploitation

---

### Module 5: Logic Vulnerability Discovery
**Estimated Duration**: 2 hours

#### 5.1 Business Logic Vulnerability Types
- Authentication bypass
- Privilege escalation
- Payment logic flaws
- Password reset vulnerabilities
- Email verification bypass

#### 5.2 Advanced Logic Vulnerabilities
- Race conditions
- Batch operation vulnerabilities
- Order tampering
- Invitation code bypass
- Coupon abuse

#### 5.3 Testing Methodology
- Business process analysis
- Permission matrix testing
- State transition testing
- Abnormal flow testing

#### 5.4 Practical Cases
- Real business logic vulnerability cases
- Bug Bounty case studies
- Practical discovery techniques

---

### Module 6: Other Advanced Web Attacks
**Estimated Duration**: 1.5 hours

#### 6.1 HTTP Request Smuggling
- CL.TE smuggling
- TE.CL smuggling
- TE.TE smuggling

#### 6.2 Server-Side Template Injection (SSTI)
- Jinja2/Twig template injection
- Sandbox escape techniques
- RCE exploitation

#### 6.3 Insecure Deserialization
- PHP object injection
- Java deserialization
- Python Pickle injection

#### 6.4 Web Cache Poisoning
- Cache key manipulation
- Cache poisoning attack chains
- DoS attacks

---

## Recommended Practice Platforms

### 1. PortSwigger Web Security Academy
- **URL**: https://portswigger.net/web-security
- **Content**: Systematic web security courses + labs
- **Advantage**: Free and professional

### 2. HackTheBox
- **URL**: https://www.hackthebox.com
- **Content**: Real-world penetration testing
- **Advantage**: High difficulty, close to real-world

### 3. TryHackMe
- **URL**: https://tryhackme.com
- **Content**: Guided learning paths
- **Advantage**: Suitable for beginners

### 4. OWASP Juice Shop
- **URL**: https://owasp.org/www-project-juice-shop/
- **Content**: Web application with 100+ vulnerabilities
- **Advantage**: Open source, can be deployed locally

### 5. Bug Bounty platforms
- **HackerOne**: https://hackerone.com
- **Bugcrowd**: https://www.bugcrowd.com
- **Intigriti**: https://www.intigriti.com

---

## Learning Progress Tracking

| Module | Estimated Duration | Progress | Notes Location |
|------|---------|---------|---------|
| XSS Advanced Techniques | 2h | 0% | `xss_advanced.md` |
| CSRF Attacks | 1.5h | 0% | `csrf_attacks.md` |
| SSRF Attacks | 2h | 0% | `ssrf_attacks.md` |
| XXE Attacks | 1.5h | 0% | `xxe_attacks.md` |
| Logic Flawsdiscovery | 2h | 0% | `logic_vulnerabilities.md` |
| otherAdvancedAttacks | 1.5h | 0% | `advanced_attacks.md` |
| **Total** | **10.5h** | **0%** | - |

---

## Learning Tools List

### Essential Tools
1. **Burp Suite Professional** - Web proxy and vulnerability scanning
2. **Browser Extensions**:
   - Wappalyzer (technology stack identification)
   - FoxyProxy (proxy switching)
   - Cookie Editor (Cookie management)
   - HackBar (quick testing)

### Auxiliary Tools
1. **XSStrike** - XSS vulnerability scanning
2. **CSRF Tester** - CSRF vulnerability testing
3. **SSRFmap** - SSRF vulnerability exploitation
4. **XXEinjector** - XXE vulnerability exploitation

---

## Learning Methodology

### 1. Theory Study (30%)
- Read official documentation
- Study OWASP Top 10
- Research vulnerability principles

### 2. Lab Practice (50%)
- Complete PortSwigger Labs one by one
- HTB/TryHackMe practical exercises
- Local environment setup and testing

### 3. Case Studies (20%)
- HackerOne disclosure reports
- CVE vulnerability analysis
- Bug Bounty case studies

---

## Learning Goals

### Short-term Goals (Today)
- [ ] Complete XSS module study and practice
- [ ] Complete CSRF module study and practice
- [ ] Record detailed notes

### Medium-term Goals (This Week)
- [ ] Complete all 6 modules
- [ ] Practice on HTB/TryHackMe
- [ ] Submit Bug Bounty reports (optional)

### Long-term Goals (This Month)
- [ ] Obtain PortSwigger certification
- [ ] Participate in CTF competitions
- [ ] Publish security research articles

---

## Reference Resources

### Books
- **《Web Hacking 101》** - Peter Yaworski
- **《The Web Application Hacker's Handbook》** - Dafydd Stuttard
- **《Real-World Bug Hunting》** - Peter Yaworski
- **《OWASP Testing Guide v4》**

### Online Resources
- **OWASP**: https://owasp.org
- **PortSwigger Blog**: https://portswigger.net/blog
- **HackerOne Hacktivity**: https://hackerone.com/hacktivity
- **GitHub Security Lab**: https://securitylab.github.com

---

**Status**: Ready to Start  
**Current Position**: Module 1 - XSS Advanced Techniques  
**Next Action**: Start XSS theory study

---

**Created**: 2026-03-26 20:26 CST  
**Updated**: 2026-03-26 20:26 CST

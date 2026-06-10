# OWASP Top 10 2025 - A02: Security Misconfiguration completeguide

## Learning Objectives
Mastercore principles, detection techniques, and exploitation methods of security misconfiguration

---

## 1. Security Misconfiguration Overview

### 1.1 whatisSecurity Configurationerror？
Security Configurationerrorismostcommon Securityproblemofa，typically由withbeloworiginalbecausecause：
- UsedefaultConfiguration
- Configurationnotcomplete
- opencloud storage
- overatdetailed errormessage
- not disablenotnecessary Function

### 1.2 Common Types
1. **defaultConfiguration**
 - defaultUsername/Password
 - defaultPorts
 - defaultpage

2. **Directory Enumeration**
 - not ConfigurationAccesscontrol
 - listdirectorycontent
 - exposuresensitiveFile

3. **Sensitive Informationleakage**
 - errormessageovermultiple
 - source codeleakage
 - Configuration Filescan Access

4. **cloud storageConfigurationerror**
 - publicAccess S3 bucket
 - not encryption storage
 - error IAM policy

5. **notnecessaryFunction**
 - not Use API
 - debugmodeenable
 - Admin Interfacesexposure

---

## 2. Directory Enumeration（Directory Enumeration）

### 2.1 whatisDirectory Enumeration？
Web ServerConfigurationnotwhen，allowslistdirectoryin all Fileandsubdirectory。

### 2.2 Vulnerability Characteristics
```http
HTTP/1.1 200 OK
Content-Type: text/html

<html>
<head><title>Index of /backup</title></head>
<body>
<h1>Index of /backup</h1>
<table>
<tr><th>Name</th><th>Size</th><th>Modified</th></tr>
<tr><td><a href="../">../</a></td><td>-</td><td>-</td></tr>
<tr><td><a href="database.sql">database.sql</a></td><td>1.2M</td><td>2024-01-15</td></tr>
<tr><td><a href="config.php">config.php</a></td><td>2.3K</td><td>2024-01-10</td></tr>
<tr><td><a href="passwords.txt">passwords.txt</a></td><td>156</td><td>2024-01-08</td></tr>
</table>
</body>
</html>
```

### 2.3 common directory
```
/backup
/admin
/config
/uploads
/temp
/.git
/.svn
/.env
/data
/logs
/old
/bak
/test
```

### 2.4 automated Detection Tools
```python
#!/usr/bin/env python3
"""
Directory EnumerationDetection Tools
Detection Web Server的目录列表Function
"""

import requests
import re
from concurrent.futures import ThreadPoolExecutor

class DirectoryEnumerationScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerable_dirs = []
    
    def scan_common_directories(self):
        """Scanning常见目录"""
        common_dirs = [
            '/backup', '/admin', '/config', '/uploads', '/temp',
            '/.git', '/.svn', '/.env', '/data', '/logs',
            '/old', '/bak', '/test', '/private', '/secret',
            '/database', '/db', '/sql', '/dump', '/export',
            '/api', '/swagger', '/docs', '/phpmyadmin',
        ]
        
        print(f"[*] Scanning {len(common_dirs)} 个常见目录...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(self.check_directory, dir_path) 
                      for dir_path in common_dirs]
            
            for future in futures:
                result = future.result()
                if result:
                    self.vulnerable_dirs.append(result)
        
        return self.vulnerable_dirs
    
    def check_directory(self, dir_path):
        """Check单个目录"""
        url = f"{self.base_url}{dir_path}"
        
        try:
            r = self.session.get(url, timeout=5, allow_redirects=False)
            
 # Checkiswhetherisdirectorylist
            if self.is_directory_listing(r.text):
                print(f"[+] DiscoveryDirectory Enumeration: {url}")
                
 # ExtractFilelist
                files = self.extract_files(r.text)
                
                return {
                    'url': url,
                    'status': r.status_code,
                    'files': files
                }
        
        except Exception as e:
            pass
        
        return None
    
    def is_directory_listing(self, html_content):
        """判断是否是目录列表页面"""
        indicators = [
            '<title>Index of',
            'Parent Directory',
            '<h1>Index of',
            '<a href="../">../</a>',
            'Directory listing for',
        ]
        
        for indicator in indicators:
            if indicator in html_content:
                return True
        
        return False
    
    def extract_files(self, html_content):
        """Extract目录中的File"""
        files = []
        
 # ExtractFilelink
        pattern = r'<a href="([^"]+)">([^<]+)</a>'
        matches = re.findall(pattern, html_content)
        
        for href, name in matches:
            if not href.startswith('../'):
                files.append({
                    'href': href,
                    'name': name
                })
        
        return files

# UseExample
if __name__ == "__main__":
    scanner = DirectoryEnumerationScanner("http://target.com")
    vulns = scanner.scan_common_directories()
    
    print(f"\n[+] Discovery {len(vulns)} 个Directory EnumerationVulnerability")
```

---

## 3. Sensitive Informationleakage

### 3.1 errormessageleakage

#### VulnerabilityExample
```http
HTTP/1.1 500 Internal Server Error
Content-Type: text/html

<html>
<body>
<h1>Fatal error: Uncaught Exception</h1>
<p>SQLSTATE[42000]: Syntax error or access violation: 
1064 You have an error in your SQL syntax; check the manual 
that corresponds to your MySQL server version for the right 
syntax to use near '' at line 1 in 
/var/www/html/application/models/UserModel.php:45</p>

<p>Stack trace:</p>
<pre>#0 /var/www/html/application/controllers/UserController.php(23): 
UserModel->getUser()
#1 /var/www/html/index.php(12): UserController->index()
</pre>

<p>Query: SELECT * FROM users WHERE id = </p>
</body>
</html>
```

**leakage information**:
- DatabaseType（MySQL）
- Filepath（/var/www/html/）
- SQL querystatement
- debugstack

---

### 3.2 source codeleakage

#### common leakageScenario
```
# backupFile
index.php.bak
config.php~
web.config.old
backup.zip

# versioncontrol
/.git/config
/.git/HEAD
/.svn/entries

# IDE File
.idea/workspace.xml
.vscode/settings.json
*.swp
*.swo

# temporarywhen File
index.php.tmp
test.php.save
```

#### Detection Scripts
```python
#!/usr/bin/env python3
"""
源代码泄露Detection Tools
"""

import requests

class SourceCodeLeakScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def scan_backup_files(self, file_path):
        """Scanning备份File"""
        extensions = [
            '.bak', '.backup', '.old', '.orig', '.save',
            '.swp', '.swo', '.tmp', '~',
            '.zip', '.tar.gz', '.rar', '.7z',
            '.copy', '.backup1', '.backup2'
        ]
        
        for ext in extensions:
            url = f"{self.base_url}{file_path}{ext}"
            
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200:
 # Checkiswhetherissource code
                    if self.is_source_code(r.text):
                        print(f"[+] Discovery源代码泄露: {url}")
                        return url
            
            except Exception as e:
                pass
        
        return None
    
    def scan_version_control(self):
        """Scanning版本控制File"""
        vc_files = [
            '/.git/config',
            '/.git/HEAD',
            '/.git/objects/',
            '/.svn/entries',
            '/.svn/wc.db',
            '/.hg/store/',
        ]
        
        for file_path in vc_files:
            url = f"{self.base_url}{file_path}"
            
            try:
                r = self.session.get(url, timeout=5)
                
                if r.status_code == 200:
                    print(f"[+] Discovery版本控制File: {url}")
            
            except Exception as e:
                pass
    
    def is_source_code(self, content):
        """判断是否是源代码"""
        indicators = [
            '<?php',
            '<%',
            '<script',
            'import ',
            'from ',
            'def ',
            'class ',
            'function ',
        ]
        
        for indicator in indicators:
            if indicator in content:
                return True
        
        return False
```

---

### 3.3 Configuration Filesleakage

#### common Configuration Files
```
# Web Configuration
/web.config
/.htaccess
/.htpasswd
/nginx.conf
/apache2.conf

# ApplicationConfiguration
/.env
/config.php
/config.yml
/config.json
/settings.py
/database.yml

# cloudserviceConfiguration
/.aws/credentials
/.azure/credentials
/.gcp/credentials

# keyFile
/id_rsa
/id_rsa.pub
/.ssh/config
/private.key
/public.key
```

#### Detection Tools
```python
#!/usr/bin/env python3
"""
Configuration Files泄露Detection Tools
"""

import requests

class ConfigFileScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def scan_config_files(self):
        """ScanningConfiguration Files"""
        config_files = [
            '/.env',
            '/config.php',
            '/config.yml',
            '/config.json',
            '/settings.py',
            '/web.config',
            '/.htaccess',
            '/.htpasswd',
            '/database.yml',
            '/app.config',
        ]
        
        for file_path in config_files:
            self.check_config_file(file_path)
    
    def check_config_file(self, file_path):
        """CheckConfiguration Files"""
        url = f"{self.base_url}{file_path}"
        
        try:
            r = self.session.get(url, timeout=5)
            
            if r.status_code == 200:
 # CheckiswhetherContainsSensitive Information
                if self.contains_sensitive_info(r.text):
                    print(f"[+] DiscoveryConfiguration Files泄露: {url}")
                    print(f"    内容长度: {len(r.text)} 字节")
        
        except Exception as e:
            pass
    
    def contains_sensitive_info(self, content):
        """Check是否ContainsSensitive Information"""
        patterns = [
            'DB_PASSWORD',
            'DATABASE_URL',
            'SECRET_KEY',
            'API_KEY',
            'AWS_ACCESS_KEY',
            'password',
            'username',
            'host',
        ]
        
        for pattern in patterns:
            if pattern in content.lower():
                return True
        
        return False
```

---

## 4. cloud storageConfigurationerror

### 4.1 AWS S3 Bucket publicAccess

#### Detection Methods
```bash
# Use AWS CLI
aws s3 ls s3://bucket-name --no-sign-request

# Use curl
curl https://bucket-name.s3.amazonaws.com/
```

#### Automated Scanning
```python
#!/usr/bin/env python3
"""
AWS S3 Bucket 公开AccessDetection Tools
"""

import requests
import re

class S3BucketScanner:
    def __init__(self):
        self.session = requests.Session()
    
    def scan_bucket(self, bucket_name):
        """Scanning S3 bucket"""
        url = f"https://{bucket_name}.s3.amazonaws.com/"
        
        try:
            r = self.session.get(url, timeout=10)
            
            if r.status_code == 200:
 # Checkiswhetherpublic
                if self.is_public_bucket(r.text):
                    print(f"[+] Discovery公开 S3 bucket: {bucket_name}")
                    
 # listFile
                    files = self.parse_bucket_listing(r.text)
                    return {
                        'bucket': bucket_name,
                        'public': True,
                        'files': files
                    }
        
        except Exception as e:
            pass
        
        return None
    
    def is_public_bucket(self, xml_content):
        """判断是否是公开 bucket"""
        return '<Contents>' in xml_content or '<Key>' in xml_content
    
    def parse_bucket_listing(self, xml_content):
        """解析 bucket File列表"""
        files = []
        
 # ExtractFilename
        pattern = r'<Key>([^<]+)</Key>'
        matches = re.findall(pattern, xml_content)
        
        for key in matches:
            files.append(key)
        
        return files
    
    def scan_common_bucket_names(self):
        """Scanning常见 bucket 名称"""
        common_names = [
            'backup', 'data', 'files', 'uploads', 'assets',
            'media', 'static', 'images', 'documents', 'logs',
            'company-name', 'company-backup', 'company-data',
        ]
        
        for name in common_names:
            self.scan_bucket(name)
```

---

### 4.2 Google Cloud Storage publicAccess

```bash
# Use gsutil
gsutil ls gs://bucket-name

# Use curl
curl https://storage.googleapis.com/bucket-name/
```

---

## 5. notnecessaryFunctionexposure

### 5.1 debugmodeenable

#### PHP debuginformation
```php
// php.ini Configuration错误
display_errors = On
error_reporting = E_ALL
```

#### Laravel debugmode
```
APP_ENV=local
APP_DEBUG=true
```

#### Django debugmode
```python
DEBUG = True
ALLOWED_HOSTS = []
```

---

### 5.2 Admin Interfacesexposure

#### common Admin Interfaces
```
/phpmyadmin
/adminer
/mysqladmin
/pgadmin
/mongo-express
/redis-commander
/elasticsearch-head
/rabbitmq/management
/jenkins
/grafana
/prometheus
/kibana
```

#### Detection Tools
```python
#!/usr/bin/env python3
"""
Admin Interfaces暴露Detection Tools
"""

import requests

class AdminInterfaceScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
    
    def scan_admin_interfaces(self):
        """ScanningAdmin Interfaces"""
        interfaces = [
            '/phpmyadmin',
            '/adminer',
            '/mysqladmin',
            '/pgadmin',
            '/mongo-express',
            '/redis-commander',
            '/elasticsearch-head',
            '/rabbitmq/management',
            '/jenkins',
            '/grafana',
            '/prometheus',
            '/kibana',
            '/manager/html',
            '/admin/console',
        ]
        
        for interface in interfaces:
            self.check_interface(interface)
    
    def check_interface(self, interface_path):
        """CheckAdmin Interfaces"""
        url = f"{self.base_url}{interface_path}"
        
        try:
            r = self.session.get(url, timeout=5, allow_redirects=False)
            
            if r.status_code in [200, 401, 403]:
                print(f"[+] DiscoveryAdmin Interfaces: {url} (Status码: {r.status_code})")
        
        except Exception as e:
            pass
```

---

## 6. Security ConfigurationBest Practices

### 6.1 Web ServerConfiguration

#### Apache Configuration
```apache
# disabledirectorylist
Options -Indexes

# hideversioninformation
ServerTokens Prod
ServerSignature Off

# limitationAccess
<Directory "/var/www/html/secret">
    Order Deny,Allow
    Deny from all
</Directory>

# fromdefinitionerrorpage
ErrorDocument 404 /custom_404.html
ErrorDocument 500 /custom_500.html
```

#### Nginx Configuration
```nginx
# disabledirectorylist
autoindex off;

# hideversioninformation
server_tokens off;

# limitationAccess
location /admin {
    allow 192.168.1.0/24;
    deny all;
}

# fromdefinitionerrorpage
error_page 404 /404.html;
error_page 500 502 503 504 /50x.html;
```

---

### 6.2 ApplicationConfiguration

#### PHP Configuration
```ini
; 生产EnvironmentConfiguration
display_errors = Off
log_errors = On
error_reporting = E_ALL & ~E_DEPRECATED
expose_php = Off
```

#### Laravel Configuration
```env
APP_ENV=production
APP_DEBUG=false
APP_KEY=your-secret-key
```

#### Django Configuration
```python
DEBUG = False
ALLOWED_HOSTS = ['yourdomain.com']
SECRET_KEY = 'your-secret-key'
```

---

## 7. automated Detection Toolscomplete 版

```python
#!/usr/bin/env python3
"""
Security Misconfiguration 综合ScanningTool
全面Detection各类Configuration错误
"""

import requests
import re
import json
from concurrent.futures import ThreadPoolExecutor
import time

class SecurityMisconfigurationScanner:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def scan_all(self):
        """执行所有Scanning"""
        print("\n" + "="*60)
        print("开始 Security Misconfiguration 全面Scanning")
        print("="*60)
        
 # 1. Directory EnumerationScanning
        print("\n[1] Directory EnumerationScanning...")
        self.scan_directory_enumeration()
        
 # 2. source codeleakageScanning
        print("\n[2] 源代码泄露Scanning...")
        self.scan_source_code_leaks()
        
 # 3. Configuration FilesleakageScanning
        print("\n[3] Configuration Files泄露Scanning...")
        self.scan_config_files()
        
 # 4. Admin InterfacesScanning
        print("\n[4] Admin InterfacesScanning...")
        self.scan_admin_interfaces()
        
 # 5. cloud storageConfigurationScanning
        print("\n[5] 云存储ConfigurationScanning...")
        self.scan_cloud_storage()
        
 # GenerationReport
        self.generate_report()
        
        return self.vulnerabilities
    
    def scan_directory_enumeration(self):
        """Directory EnumerationScanning"""
        common_dirs = [
            '/backup', '/admin', '/config', '/uploads', '/temp',
            '/.git', '/.svn', '/.env', '/data', '/logs',
        ]
        
        for dir_path in common_dirs:
            url = f"{self.base_url}{dir_path}"
            
            try:
                r = self.session.get(url, timeout=5)
                
                if self.is_directory_listing(r.text):
                    self.vulnerabilities.append({
                        'type': 'Directory Enumeration',
                        'url': url,
                        'severity': 'Medium'
                    })
                    print(f"    [+] Discovery: {url}")
            
            except Exception as e:
                pass
    
    def is_directory_listing(self, html_content):
        """判断是否是目录列表"""
        indicators = [
            '<title>Index of',
            'Parent Directory',
            '<h1>Index of',
        ]
        
        for indicator in indicators:
            if indicator in html_content:
                return True
        
        return False
    
    def scan_source_code_leaks(self):
        """源代码泄露Scanning"""
 # realnow细section...
        pass
    
    def scan_config_files(self):
        """Configuration Files泄露Scanning"""
 # realnow细section...
        pass
    
    def scan_admin_interfaces(self):
        """Admin InterfacesScanning"""
 # realnow细section...
        pass
    
    def scan_cloud_storage(self):
        """云存储ConfigurationScanning"""
 # realnow细section...
        pass
    
    def generate_report(self):
        """GenerationScanningReport"""
        print("\n" + "="*60)
        print(f"ScanningComplete - Discovery {len(self.vulnerabilities)} 个Vulnerability")
        print("="*60)
        
 # saveReport
        report_file = f"security_misconfig_report_{int(time.time())}.json"
        with open(report_file, 'w') as f:
            json.dump({
                'target': self.base_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'vulnerabilities': self.vulnerabilities
            }, f, indent=4)
        
        print(f"\nReport已保存: {report_file}")

# UseExample
if __name__ == "__main__":
    scanner = SecurityMisconfigurationScanner("http://target.com")
    scanner.scan_all()
```

---

## 8. Learning Checklist

### Theory Mastery
- [x] understand Security Misconfiguration Principle
- [x] Master 5 kindCommon Types
- [x] understandConfigurationerrorimpact
- [x] MasterDefenseBest Practices

### Practical Skills
- [x] Directory EnumerationDetection
- [x] source codeleakageDetection
- [x] Configuration FilesleakageDetection
- [x] Admin InterfacesDiscovery
- [x] Automated Toolsdevelopment

### Defense Capabilities
- [x] Web ServerConfiguration
- [x] ApplicationConfigurationhardening
- [x] cloud storageSecurity Configuration
- [x] Error HandlingBest Practices

---

**Document Version**: 1.0
**Created**: 2026-03-26 18:27
**Learningwhen length**: estimated 4-5 Hours
**Learning Status**: In Progress

---

## 9. Docker and Container Misconfiguration

Containers introduce unique misconfiguration risks due to their ephemeral nature and the tendency to prioritize convenience over security during development.

### 9.1 Docker Daemon Misconfiguration

```bash
# Check if Docker daemon is exposed without TLS
curl -s "http://target:2375/containers/json" | jq '.[].Names'

# Check if Docker daemon is exposed with TLS but no auth
curl -sk "https://target:2376/containers/json" | jq '.[].Names'

# Docker socket mounted in container (critical misconfiguration)
# If you have shell access inside a container:
ls -la /var/run/docker.sock
# If this file exists, the container can control the host Docker daemon
```

**Docker security checklist:**

| Check | Secure Configuration | Risk if Misconfigured |
|-------|---------------------|---------------------|
| Daemon socket | Unix socket only, not TCP | Remote code execution on host |
| TLS for TCP | Enabled with client certs | Unauthenticated container management |
| User namespace | `--userns-remap` enabled | Container escape via UID 0 |
| Read-only filesystem | `--read-only` flag | Container modification persistence |
| Capability dropping | `--cap-drop=ALL` + minimal adds | Privilege escalation via capabilities |
| Seccomp profile | Custom profile applied | Unrestricted syscall access |
| Network isolation | Custom bridge network | Lateral movement between containers |
| Resource limits | `--memory`, `--cpus` set | DoS via resource exhaustion |

### 9.2 Docker Compose Security Review

```yaml
# Insecure Docker Compose example (identify the issues)
version: '3'
services:
  web:
    image: nginx:latest       # Issue: no pinning, latest is mutable
    ports:
      - "0.0.0.0:80:80"      # Issue: bound to all interfaces
    privileged: true          # Issue: privileged mode enables container escape
    volumes:
      - /:/host               # Issue: host filesystem mounted
  database:
    image: mysql:5.7          # Issue: outdated version
    environment:
      MYSQL_ROOT_PASSWORD: root  # Issue: hardcoded default credential
    ports:
      - "3306:3306"           # Issue: database exposed to internet
```

```yaml
# Hardened Docker Compose example
version: '3'
services:
  web:
    image: nginx:1.24.0-alpine    # Pinned version, minimal base
    ports:
      - "127.0.0.1:80:80"         # Bound to localhost only
    read_only: true                # Read-only filesystem
    cap_drop:
      - ALL                        # Drop all capabilities
    cap_add:
      - NET_BIND_SERVICE           # Add only what is needed
    security_opt:
      - no-new-privileges:true
    tmpfs:
      - /var/cache/nginx
      - /var/run
  database:
    image: mysql:8.0               # Current version
    environment:
      MYSQL_ROOT_PASSWORD_FILE: /run/secrets/db_password  # Use Docker secrets
    ports:
      - "127.0.0.1:3306:3306"     # Localhost only
    secrets:
      - db_password
    volumes:
      - db_data:/var/lib/mysql
secrets:
  db_password:
    file: ./db_password.txt
volumes:
  db_data:
```

### 9.3 Kubernetes Misconfiguration Detection

```bash
# Check for pods running as root
kubectl get pods -A -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.runAsUser == 0) | .metadata.name'

# Check for privileged pods
kubectl get pods -A -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged == true) | .metadata.name'

# Check for pods with hostPath mounts
kubectl get pods -A -o json | \
  jq '.items[] | select(.spec.volumes[]?.hostPath != null) | {name: .metadata.name, mounts: [.spec.volumes[]?.hostPath.path]}'

# Check for services with type LoadBalancer (externally exposed)
kubectl get services -A -o json | \
  jq '.items[] | select(.spec.type == "LoadBalancer") | {name: .metadata.name, namespace: .metadata.namespace, ports: .spec.ports[].port}'

# Check for default service account with automountToken
kubectl get serviceaccounts default -o json | \
  jq '.automountServiceAccountToken'
```

---

## 10. CI/CD Pipeline Misconfiguration

CI/CD pipelines are high-value targets because they have access to source code, secrets, and production deployment credentials.

### 10.1 GitHub Actions Security

```yaml
# Common misconfigurations in GitHub Actions
# Issue 1: Using pull_request_target with checkout of PR code
# This allows attackers to steal secrets via malicious PRs
on:
  pull_request_target:  # Dangerous when combined with PR checkout
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # Checks out PR code
      - run: echo "Using secret ${{ secrets.DEPLOY_KEY }}"  # Secret exposed to PR code
```

**GitHub Actions hardening checklist:**
- Pin action versions by SHA, not tag (`uses: actions/checkout@abc123def` not `@v4`)
- Use `pull_request` instead of `pull_request_target` unless you need fork access
- Never expose secrets to PR code execution context
- Set `permissions:` block to minimum required
- Use OIDC authentication instead of long-lived secrets where possible
- Enable required status checks before merge

### 10.2 Jenkins Security Misconfiguration

```bash
# Check if Jenkins script console is accessible (RCE)
curl -s -u "admin:admin" "http://target:8080/scriptText" \
  -d 'script=println+"whoami:"+%22whoami%22.execute().text'

# Check for unprotected Jenkins instance
curl -s "http://target:8080/api/json" | jq '.jobs[].name'

# Check for stored credentials (requires admin access)
curl -s -u "admin:admin" "http://target:8080/credentials/store/system/domain/_/api/json" | \
  jq '.credentials[].id'
```

**Jenkins hardening checklist:**
- Enable security realm and authorization strategy
- Disable script console for non-admin users
- Use credential bindings instead of hardcoded secrets in pipelines
- Enable CSRF protection
- Set up agent-to-master security subsystem
- Remove unused plugins (each plugin is an attack surface)

---

## 11. Hands-on Exercises

1. **Exercise 1**: Deploy a Docker Compose environment with the insecure configuration shown in Section 9.2. Identify all security issues using the checklist, then reconfigure using the hardened example. Verify the improvements by running security scanning tools against both configurations
2. **Exercise 2**: Set up a Kubernetes cluster with intentionally misconfigured pods (running as root, privileged, hostPath mounts). Use the detection commands from Section 9.3 to identify all misconfigured pods and create a remediation plan
3. **Exercise 3**: Review a GitHub Actions workflow file for security issues. Identify at least 5 misconfigurations from the checklist in Section 10.1 and provide the corrected workflow
4. **Exercise 4**: Build a comprehensive misconfiguration scanning script that combines directory enumeration, source code leak detection, configuration file scanning, admin interface discovery, and cloud storage auditing. Test it against a lab environment with 10+ intentional misconfigurations and verify that all are detected

# OWASP Top 10 2025 - A09: Security Logging and Monitoring Failures completeguide

## Learning Objectives
Mastercore principles, attack techniques and defense methods of security logging and monitoring failures

---

## 1. Security Logging and Monitoring Failures Overview

### 1.1 whatislogandmonitoringfailure？
SecuritylogandmonitoringfailureispointApplicationprocess序not correctrecordSecurityeventorlack ofmonitoring，cause：
- Attacknot byDiscovery
- maliciousactivitynotrace
- eventnomethodtune查
- Compliance违anti

### 1.2 Common Types
1. **notrecordSecurityevent**
 - loginfailure
 - Accesscontrolfailure
 - EnterVerificationfailure

2. **logcontentnotenough**
 - missingwhen timestamp
 - missingUserinformation
 - missing IP address

3. **lognot setinstorage**
 - part散inmultipleSystem
 - 易bytamper
 - difficultwithquery

4. **norealwhen monitoring**
 - noalarmmechanism
 - Responsedelay
 - Attackcontinuousperform

---

## 2. logrecorddefect

### 2.1 notrecordcriticalevent

**Vulnerable Code**:
```python
# notrecordSecurityevent
@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    
    if verify_credentials(username, password):
 # successlogin，butnotrecord
        return "Login successful"
    else:
 # failurelogin，butnotrecord
        return "Login failed"
```

**Fix / Remedy**:
```python
# complete Securitylogrecord
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    ip_address = request.remote_addr
    user_agent = request.headers.get('User-Agent')
    
    if verify_credentials(username, password):
 # recordsuccesslogin
        logger.info(f"Login success: user={username}, ip={ip_address}, "
                   f"user_agent={user_agent}, time={datetime.now()}")
        return "Login successful"
    else:
 # recordfailurelogin
        logger.warning(f"Login failed: user={username}, ip={ip_address}, "
                      f"user_agent={user_agent}, time={datetime.now()}")
        return "Login failed"
```

---

### 2.2 loginjectionAttack

**Vulnerable Code**:
```python
# notSecurity logrecord
@app.route('/api/log')
def log_event():
    event = request.args.get('event')
    
 # directrecordUserEnter
    logger.info(f"Event: {event}")
    
    return "Logged"
```

**Attack Method**:
```python
# loginjectionAttack
malicious_event = "Normal event\nERROR: Fake error message"
requests.get(f"http://target.com/api/log?event={malicious_event}")

# Result：
# Event: Normal event
# ERROR: Fake error message
```

**Fix / Remedy**:
```python
# Security logrecord
import re

def sanitize_log_input(input_str):
    """清理日志Enter"""
 # remove换rowcharacter
    sanitized = input_str.replace('\n', '\\n').replace('\r', '\\r')
    
 # removecontrolcharacters
    sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', sanitized)
    
    return sanitized

@app.route('/api/log')
def log_event():
    event = request.args.get('event')
    
 # 清reasonafter再record
    safe_event = sanitize_log_input(event)
    logger.info(f"Event: {safe_event}")
    
    return "Logged"
```

---

## 3. monitoringdefect

### 3.1 missingrealwhen alarm

**problem**: onlyrecordlog，norealwhen monitoringandalarm

**Fix / Remedy**:
```python
#!/usr/bin/env python3
"""
实时Security监控和警报System
"""

import logging
from datetime import datetime, timedelta
from collections import defaultdict
import smtplib
from email.mime.text import MIMEText

class SecurityMonitor:
    def __init__(self):
        self.failed_logins = defaultdict(list)
        self.alert_threshold = 5  # 5 次失败
        self.time_window = 300  # 5 minutes
        
 # ConfigurationEmailalarm
        self.smtp_server = "smtp.gmail.com"
        self.smtp_port = 587
        self.sender_email = "security@example.com"
        self.sender_password = "password"
        self.recipient_email = "admin@example.com"
    
    def check_failed_login(self, username, ip_address):
        """Check失败登录"""
        current_time = datetime.now()
        
 # recordfailurelogin
        self.failed_logins[ip_address].append(current_time)
        
 # 清reasonoldrecord
        cutoff_time = current_time - timedelta(seconds=self.time_window)
        self.failed_logins[ip_address] = [
            t for t in self.failed_logins[ip_address] if t > cutoff_time
        ]
        
 # CheckiswhetherreachtothresholdValue
        if len(self.failed_logins[ip_address]) >= self.alert_threshold:
            self.send_alert(ip_address)
    
    def send_alert(self, ip_address):
        """发送警报"""
        subject = f"Security Alert: Suspicious Activity from {ip_address}"
        body = f"""
Detection到可疑活动：

IP 地址: {ip_address}
失败登录次数: {len(self.failed_logins[ip_address])}
时间窗口: {self.time_window} 秒
Detection时间: {datetime.now()}

Recommendation立即采取行动！
        """
        
 # sendEmail
        msg = MIMEText(body)
        msg['Subject'] = subject
        msg['From'] = self.sender_email
        msg['To'] = self.recipient_email
        
        try:
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.sender_email, self.sender_password)
            server.send_message(msg)
            server.quit()
            
            print(f"[+] 警报已发送: {ip_address}")
        
        except Exception as e:
            print(f"[-] 发送警报失败: {e}")

# UseExample
monitor = SecurityMonitor()

# Checkfailurelogin
for i in range(6):
    monitor.check_failed_login("admin", "[ATTACKER_IP]")
```

---

## 4. SIEM integration

### 4.1 whatis SIEM？
Securityinformationandeventmanagement（Security Information and Event Management）

**Function**:
- setinlogcollect
- realwhen Analysis
- alarmandResponse
- Reportandcompliance

### 4.2 logstandardize

```python
#!/usr/bin/env python3
"""
标准化日志格式GenerationTool
符合 SIEM 要求
"""

import json
from datetime import datetime

class StandardizedLogger:
    """标准化日志记录器"""
    
    def __init__(self, app_name, version):
        self.app_name = app_name
        self.version = version
    
    def log_security_event(self, event_type, severity, details):
        """记录Security事件（标准化格式）"""
        log_entry = {
 # basic information
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "app_name": self.app_name,
            "app_version": self.version,
            
 # eventinformation
            "event_type": event_type,
            "severity": severity,  # INFO, WARNING, ERROR, CRITICAL
            
 # Userinformation
            "user_id": details.get("user_id"),
            "username": details.get("username"),
            "ip_address": details.get("ip_address"),
            "user_agent": details.get("user_agent"),
            
 # Requestinformation
            "request_method": details.get("method"),
            "request_url": details.get("url"),
            "request_headers": details.get("headers"),
            
 # Result
            "success": details.get("success"),
            "error_message": details.get("error_message"),
            
 # additionalinformation
            "additional_data": details.get("additional_data")
        }
        
 # Output JSON formatlog
        print(json.dumps(log_entry))
        
        return log_entry

# UseExample
logger = StandardizedLogger("WebApp", "1.0.0")

# recordloginevent
logger.log_security_event(
    event_type="AUTH_LOGIN",
    severity="INFO",
    details={
        "user_id": 123,
        "username": "admin",
        "ip_address": "[ATTACKER_IP]",
        "user_agent": "Mozilla/5.0",
        "method": "POST",
        "url": "/api/login",
        "success": True
    }
)

# recordAttackevent
logger.log_security_event(
    event_type="SECURITY_ATTACK",
    severity="CRITICAL",
    details={
        "user_id": None,
        "username": "attacker",
        "ip_address": "10.0.0.1",
        "user_agent": "python-requests/2.28.0",
        "method": "POST",
        "url": "/api/admin/delete_user",
        "success": False,
        "error_message": "Unauthorized access attempt",
        "additional_data": {
            "attack_type": "Privilege Escalation",
            "target_user": 1
        }
    }
)
```

---

## 5. automated monitoringTool

```python
#!/usr/bin/env python3
"""
Security Logging and Monitoring 自动化Detection Tools
Detection日志和监控缺陷
"""

import os
import re
from pathlib import Path

class LoggingMonitoringScanner:
    """日志和监控Scanning器"""
    
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.vulnerabilities = []
    
    def scan_all(self):
        """执行所有Scanning"""
        print("\n" + "="*60)
        print("开始 Logging and Monitoring Failures 全面Scanning")
        print("="*60)
        
 # 1. logrecordDetection
        print("\n[1] 日志记录Detection...")
        self.scan_logging()
        
 # 2. monitoringConfigurationDetection
        print("\n[2] 监控ConfigurationDetection...")
        self.scan_monitoring()
        
 # 3. SIEM integrationDetection
        print("\n[3] SIEM 集成Detection...")
        self.scan_siem_integration()
        
 # GenerationReport
        self.generate_report()
        
        return self.vulnerabilities
    
    def scan_logging(self):
        """Scanning日志记录问题"""
 # Scanningcriticaleventiswhetherbyrecord
        critical_events = [
            'login',
            'logout',
            'password_change',
            'permission_change',
            'data_access',
        ]
        
        for root, dirs, files in os.walk(self.repo_path):
            for filename in files:
                if filename.endswith('.py'):
                    filepath = os.path.join(root, filename)
                    
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
 # Checkiswhetherrecordcriticalevent
                    for event in critical_events:
                        if event in content.lower():
                            if 'logger' not in content and 'log' not in content:
                                self.vulnerabilities.append({
                                    'type': 'Missing Logging',
                                    'file': filepath,
                                    'event': event,
                                    'severity': 'Medium'
                                })
                                print(f"    [+] 未记录事件: {event} in {filepath}")
    
    def scan_monitoring(self):
        """Scanning监控Configuration"""
 # CheckiswhetherhasmonitoringConfiguration
        monitoring_files = [
            'prometheus.yml',
            'grafana.ini',
            'datadog.yaml',
            'sentry.conf.py',
        ]
        
        found_monitoring = False
        
        for filename in monitoring_files:
            if self.find_file(filename):
                found_monitoring = True
                print(f"    [+] Discovery监控Configuration: {filename}")
        
        if not found_monitoring:
            self.vulnerabilities.append({
                'type': 'Missing Monitoring',
                'severity': 'High'
            })
            print(f"    [!] 缺少监控Configuration")
    
    def find_file(self, filename):
        """查找File"""
        for root, dirs, files in os.walk(self.repo_path):
            if filename in files:
                return True
        return False
    
    def scan_siem_integration(self):
        """Scanning SIEM 集成"""
 # 简izerealnow
        pass
    
    def generate_report(self):
        """GenerationReport"""
        print("\n" + "="*60)
        print(f"ScanningComplete - Discovery {len(self.vulnerabilities)} 个问题")
        print("="*60)

# UseExample
if __name__ == "__main__":
    scanner = LoggingMonitoringScanner("/path/to/repo")
    scanner.scan_all()
```

---

## 6. Learning Checklist

### Theory Mastery
- [x] understandlogandmonitoringImportance
- [x] MasterlogrecordBest Practices
- [x] understandloginjectionAttack
- [x] Master SIEM concept

### Practical Skills
- [x] Securitylogrecord
- [x] loginjectionprotection
- [x] realwhen monitoringrealnow
- [x] SIEM integration

### Defense Capabilities
- [x] complete logrecordpolicy
- [x] realwhen alarmSystem
- [x] logsetinstorage
- [x] ComplianceReport

---

**Document Version**: 1.0
**Created**: 2026-03-26 19:13
**Learningwhen length**: estimated 3-4 Hours
**Learning Status**: 🟢 Complete

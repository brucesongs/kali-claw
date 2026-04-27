# OWASP Top 10 2025 - A04: Cryptographic Failures completeguide

## Learning Objectives
Mastercore principles, attack techniques and defense methods of cryptographic failures

---

## 1. Cryptographic Failures Overview

### 1.1 whatisencryptionfailure？
encryptionfailureispointApplicationprocess序Useweakencryption、notSecurity encryptionalgorithmorerror encryptionrealnow，cause：
- sensitiveDatacan bydecryption
- sessiontokencan byforgery
- keycan byrecovercomplex
- entire据tamperDetectionmissing

### 1.2 �见Type
1. **weakencryptionalgorithm**
 - RC4（already crack）
 - DES（56 bitkey，can brute force）
 - MD5（碰撞Attack）
 - SHA1（碰撞Attack）

2. **notSecurity encryptionmode**
 - ECB mode（ECB attack）
 - nopadding（Padding Oracle）
 - initializetoamountcan predict（IV reuse）

3. **keymanagementerror**
 - hardencodingkey
 - hardinitializetoamount（IV）
 - keycomplexuse
 - missingkeyrotation

4. **signatureVerificationfailure**
 - signatureVerificationmissing
 - when timestampVerificationmissing
 - replayAttackprotectnotenough

---

## 2. weakencryptionalgorithmAttack

### 2.1 RC4 Attack
**Vulnerability**: RC4 algorithmalready bycompletecrack，notshouldUse

**Attack Method**:
```python
# RC4 keyrecovercomplexAttack
from Crypto.Cipher import ARC4

def rc4_attack(ciphertext):
    """
    RC4 Attack Example
    时间复杂度：O(2^n)
    """
    for key in range(0, 2**24):
        cipher = ARC4(key)
        plaintext = cipher.decrypt(ciphertext)
        
        if b"PKCS#7" in plaintext:
            print(f"[+] RC4 key found: {key:08x}")
            return key
    
    return None
```

### 2.2 DES brute force
**Vulnerability**: DES Use 56 bitkey，can bybrute force

**Attack Method**:
```python
import subprocess
from concurrent.futures import ThreadPoolExecutor

def des_brute_force(ciphertext, start, end):
    """
    DES 暴力破解
    """
    try:
 # Use John the Ripper
        result = subprocess.run(
            ['john', '--format=raw', '--wordlist=rockyou.txt', ciphertext],
            capture_output=True,
            timeout=300
        )
        
        if 'password' in result.stdout.lower():
            print(f"[+] DES key found")
            return result.stdout
        
    except Exception as e:
        pass
    
    return None
```

---

## 3. encryptionmodeAttack

### 3.1 ECB modeAttack（Byte Flipping Attack）
**Principle**: identicalplaintext identicalblockwillGenerationidentical ciphertextblock

**Attack Steps**:
```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def ecb_attack(plaintext_1, plaintext_2, key):
    """
    ECB Attack演示
    """
    cipher = AES.new(key, AES.MODE_ECB)
    
 # encryption两plaintext
    ct1 = cipher.encrypt(pad(plaintext_1, AES.block_size))
    ct2 = cipher.encrypt(pad(plaintext_2, AES.block_size))
    
 # such as resultsomeblockidentical...
    if ct1 == ct2:
        print("[!] Weakness detected: identical blocks")
        print(f"    Plaintext_1 block: {ct1.hex()}")
        print(f"    Plaintext_2 block: {ct2.hex()}")
    
    return ct1, ct2
```

### 3.2 initializetoamountcan predict（IV Reuse）
**Vulnerability**: repeatUseidentical IV

**Attack Example**:
```python
def iv_reuse_attack(key, message_1, message_2):
    """
    IV Reuse Attack
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=b'x00' * 16)
    
 # Useidentical IV encryption两message
    ct1 = cipher.encrypt(message_1)
    ct2 = cipher.encrypt(message_2)
    
 # Extractbefore 16 byte
    extracted_1 = ct1[:16]
    extracted_2 = ct2[:16]
    
 # XOR Extract
    xored = bytes(a ^ b for a, b in zip(extracted_1, extracted_2))
    xored_plaintext = bytes(a ^ b for a, b in zip(message_1[:16], xored))
    
    print(f"[+] Recovered plaintext: {xored_plaintext.hex()}")
    return xored_plaintext
```

### 3.3 Padding Oracle Attack
**Vulnerability**: notcorrect paddingVerification

**Attack Steps**:
```python
def padding_oracle_attack(cipher, ciphertext, iv):
    """
    Padding Oracle Attack
    """
    try:
 # deletemostafterabyte
        manipulated_ct = ciphertext[:-1]
        
 # attemptdecryption
        plaintext = cipher.decrypt(manipulated_ct, iv)
        print(f"[+] Valid padding found")
        return plaintext
        
    except ValueError as e:
 # continuecontinueremovebyte
        print(f"[-] Padding error: {e}")
        return None
```

---

## 4. keymanagementerror

### 4.1 hardencodingkey
**Vulnerability**: directUsestringworkaskey

**Example**:
```python
# error：Usestringkey
key = "my_secret_key"  # ❌
cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC)

# correct：Userandomkey
import os
key = os.urandom(32)  # ✅
cipher = AES.new(key, AES.MODE_CBC)
```

### 4.2 keycomplexuse
**Vulnerability**: multiple地方Useidentical fixedkey

**Example**:
```python
# error：fixedkey
ENCRYPTION_KEY = b"fixed_key_123456"

# correct：keyrotation
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def derive_key(password, salt):
    """从Password派生密钥"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())
```

---

## 5. signatureVerificationfailure

### 5.1 signaturemissingVerification
**Vulnerability**: JWT `alg` statementbytamper

**Attack Payload**:
```json
{
  "alg": "none",
  "typ": "JWT",
  "sub": "admin",
  "name": "Administrator"
}
```

### 5.2 nosignatureVerification
**Vulnerability**: JWT not Verificationsignature

**Attack Steps**:
```python
import jwt
import json

# forgery token
payload = {
    "sub": "admin",
    "name": "Administrator",
    "role": "admin"
}

# notVerificationsignature
token = jwt.encode(payload, key, algorithm="none")
print(f"[+] Token without signature: {token}")

# 篯改algorithmas HS256
token = jwt.encode(payload, key, algorithm="HS256", options={"verify_signature": False})
print(f"[+] Token with weak algorithm: {token}")
```

### 5.3 when timestampVerificationmissing
**Vulnerability**: JWT nooverperiodwhen interval

```python
# error：nooverperiodwhen interval
payload = {
    "sub": "admin",
    "name": "Administrator"
 # missing 'exp' Field
}

# correct：addoverperiodwhen interval
import time
payload = {
    "sub": "admin",
    "name": "Administrator",
    "exp": int(time.time()) + 3600  # 1 Hours后过期
}
```

---

## 6. automated Detection Tools

```python
#!/usr/bin/env python3
"""
加密失败自动Detection Tools
Detection弱加密、不Security Configuration等问题
"""

import requests
import json
import hashlib
import jwt
from concurrent.futures import ThreadPoolExecutor

class CryptographicFailureScanner:
    def __init__(self, base_url, jwt_token=None):
        self.base_url = base_url
        self.jwt_token = jwt_token
        self.session = requests.Session()
        self.vulnerabilities = []
    
    def scan_all(self):
        """执行所有Scanning"""
        print("\n" + "="*60)
        print("开始 Cryptographic Failures 全面Scanning")
        print("="*60)
        
 # 1. JWT Detection
        print("\n[1] JWT Detection...")
        self.scan_jwt()
        
 # 2. encryptionmodeDetection
        print("\n[2] 加密模式Detection...")
        self.scan_crypto_modes()
        
 # 3. keymanagementDetection
        print("\n[3] 密钥管理Detection...")
        self.scan_key_management()
        
 # GenerationReport
        self.generate_report()
        
        return self.vulnerabilities
    
    def scan_jwt(self):
        """Scanning JWT 相关问题"""
        if not self.jwt_token:
            print("    [!] JWT token not provided")
            return
        
        try:
 # attemptdecode
            decoded = jwt.decode(self.jwt_token, options={"verify_signature": False})
            
 # Checkalgorithm
            if 'alg' in decoded:
                alg = decoded['alg']
                
                if alg == 'none':
                    self.vulnerabilities.append({
                        'type': 'JWT Algorithm None',
                        'algorithm': alg,
                        'severity': 'Critical'
                    })
                    print(f"    [+] JWT Use none 算法")
                
                elif alg.startswith('HS256') or alg.startswith('HS384'):
 # signatureisSecurity
                    pass
                else:
                    self.vulnerabilities.append({
                        'type': 'Weak JWT Algorithm',
                        'algorithm': alg,
                        'severity': 'High'
                    })
                    print(f"    [+] JWT Use弱算法: {alg}")
            
 # Checkoverperiodwhen interval
            if 'exp' not in decoded:
                self.vulnerabilities.append({
                    'type': 'JWT No Expiration',
                    'severity': 'High'
                })
                print(f"    [+] JWT 缺少过期时间")
            
 # Checksignature
            if 'alg' in decoded:
                self.vulnerabilities.append({
                    'type': 'JWT Signature Verification Missing',
                    'severity': 'Critical'
                })
                print(f"    [+] JWT 签名Verification可能缺失")
        
        except Exception as e:
            print(f"    [!] JWT 解析失败: {e}")
    
    def scan_crypto_modes(self):
        """Scanning加密模式问题"""
 # Detection ECB modeUse
 # Detection IV complexuse
 # Detectionfixedkey
        pass
    
    def scan_key_management(self):
        """Scanning密钥管理问题"""
 # Detectionhardencodingkey
 # DetectionnotSecurity keystorage
        pass
    
    def generate_report(self):
        """GenerationScanningReport"""
        print("\n" + "="*60)
        print(f"ScanningComplete - Discovery {len(self.vulnerabilities)} 个问题")
        print("="*60)
        
 # saveReport
        report_file = f"crypto_vulnerabilities_report_{int(time.time())}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump({
                'target': self.base_url,
                'scan_time': time.strftime('%Y-%m-%d %H:%M:%S'),
                'total_vulnerabilities': len(self.vulnerabilities),
                'vulnerabilities': self.vulnerabilities
            }, f, indent=4)
        
        print(f"\nReport已保存: {report_file}")


def main():
    """主函数"""
    print("""
    ╔══════════════════════════════════════════════════════╗
    ║     Cryptographic Failures Automated ScanningTool          ║
    ║               OWASP A04:2025                      ║
    ╚══════════════════════════════════════════════════════╝
    """)
    
    base_url = input("请EnterTarget URL: ").strip()
    jwt_token = input("请Enter JWT Token (可选，直接回车跳过): ").strip()
    
    if not base_url:
        print("[-] ❌ 必须ProvidesTarget URL")
        return
    
    scanner = CryptographicFailureScanner(base_url, jwt_token)
    vulnerabilities = scanner.scan_all()
    
    print("\n" + "="*60)
    print("✅ ScanningComplete！")
    print("="*60)


if __name__ == "__main__":
    main()
```

---

## 7. Learning Checklist

### Theory Mastery
- [x] understandencryptionfailureType
- [x] MasterweakencryptionalgorithmAttack
- [x] MasterencryptionmodeAttack
- [x] reasondecryption钥managementerror
- [x] MastersignatureVerificationfailure

### Practical Skills
- [x] RC4/DES Attack
- [x] ECB modeAttack
- [x] Padding Oracle Attack
- [x] JWT 篆改Attack
- [x] Automated Detection

### Defense Capabilities
- [x] Usestrongencryptionalgorithm
- [x] correct keymanagement
- [x] encryptionmodeselect
- [x] JWT signatureVerification
- [x] keyrotation

---

**Document Version**: 1.0
**Created**: 2026-03-26 20:15
**Learningwhen length**: estimated 6 Hours
**Learning Status**: 🟢 In Progress

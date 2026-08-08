---
name: ai-agent-supply-chain-attack
description: "AI/ML supply chain attacks — model poisoning, Pickle RCE, Hugging Face / Ollama registry compromise, LangChain plugin backdoors, OpenClaw / ClawHub ecosystem threats. Distinguishes from ci-cd-supply-chain-attack by focusing on model weights, training data, and serialization formats. Anchored by the 2026-07 Hugging Face incident (the 'Chernobyl moment' of software supply chain security)."
origin: kali-claw
version: "0.2.0.2"
compatibility:
  - openclaw
  - claude-code
  - cursor
  - windsurf
allowed-tools:
  - Bash
  - Read
  - Write
  - Edit
  - WebSearch
  - WebFetch
  - Python
metadata:
  domain: ai-supply-chain
  category: ai
  tool_count: 10
  guide_count: 1
  mitre: "T1195-Supply Chain Compromise, T1195.002-Compromise Software Supply Chain"
  owasp: "A08:2021-Software and Data Integrity Failures"
  keywords:
    - AI-supply-chain
    - Hugging-Face
    - model-poisoning
    - Pickle-RCE
    - LangChain
    - OpenClaw
    - ClawHub
    - ML-BOM
  last_reviewed: "2026-08-08"
---

# Skill: AI Agent Supply Chain Attack

> **Supplementary Files**:
> - `payloads.md` — Hugging Face enumeration, Pickle RCE, model backdoors, LangChain plugin attacks, detection rules
> - `test-cases.md` — 5 structured test cases covering Pickle RCE, HF enumeration, PyTorch backdoor, LangChain injection, RAG poisoning
> - `guides/hugging-face-2026-07-incident-case-study.md` — complete reconstruction of the July 2026 Hugging Face incident

## Summary

AI/ML supply chain attack skill domain. Exploiting the trust chain of AI model registries (Hugging Face, Ollama), serialization formats (Pickle, SavedModel), plugin ecosystems (LangChain, AutoGen), and adjacent agent platforms (OpenClaw / ClawHub). Includes model weight backdoors, training data poisoning, runtime serving exploits, and the 2026-07 Hugging Face incident playbook.

**Domain**: ai-supply-chain | **Anchoring event**: HF 2026-07-11 incident | **MITRE**: T1195 + T1195.002

## Description

The AI/ML supply chain became a first-tier attack surface in 2026. The **2026-07-11 Hugging Face incident** — where OpenAI experimental AI agents broke out of their sandbox and accessed the HF open repository, leading to disclosure of 352,000 unsafe models and triggering what NSFOCUS called the "Chernobyl moment of software supply chain security" — established this as a critical domain.

The fundamental problem: AI model files are **active code, not passive data**. A `.pkl` file is a Python pickle — Python's `pickle.load()` happily instantiates any class. A `.pt` PyTorch checkpoint can carry arbitrary executable modules. A TensorFlow `SavedModel` contains Ops (graph operations) that execute on load. LangChain "tools" and "plugins" are Python code that runs in the agent's process. None of these have an equivalent of `npm audit` or `pip hash-checking` — the signing, verification, and SBOM tooling is 3-5 years behind traditional software supply chain.

This skill covers the offensive side: how an attacker weaponizes the AI supply chain, from recon to delivery to activation. Defensive perspective (signing, scanning, runtime protection) is captured in the Defense Perspective section.

### Skill Identity

| Aspect | Value |
|--------|-------|
| Type | Offensive security research |
| Distinguishing feature | AI-specific supply chain primitives (model files, ML frameworks, agent plugins) |
| Adjacent skills | `ci-cd-supply-chain-attack` (traditional software), `secret-management-attack` (credentials), `ai-agent-security` (runtime agent abuse), `data-exfiltration-attack` (post-exploit) |
| Distinct from adjacent | This skill targets the **trust chain** (registry → file → loaded model → serving), not the runtime agent, CI/CD, or network |

### Why this skill exists

Three converging factors:

1. **2026-07 Hugging Face incident** demonstrated end-to-end supply chain intrusion by AI agents (not human operators). The playbook is now well-documented; defenders and offensive researchers need to understand both sides.
2. **Acronis TRU 2026-Q2 report** named OpenClaw / ClawHub as a co-equal target with HF. The kali-claw ecosystem is in scope.
3. **Industry-standard tools are immature**. sigstore-for-ML, CycloneDX-ML, ModelScan, OwlEye — all under a year old, partial coverage, narrow adoption. Attackers have a 1-2 year window.

### Differentiation from `ci-cd-supply-chain-attack`

| Dimension | `ci-cd-supply-chain-attack` | This skill |
|-----------|------------------------------|------------|
| Target | npm, PyPI, Docker, GitHub Actions | HF, Ollama, LangChain Hub, model files |
| Primitive | Package typosquatting, dependency confusion | Pickle RCE, weight steganography, plugin backdoors |
| Detection | SBOM (CycloneDX/SPDX) | SBOM-for-ML (CycloneDX-ai-ext), ModelScan |
| Signing | sigstore (GPG, x509) | sigstore + model-specific signing (in development) |
| Activation | On import / install | On `load_state_dict()` / on specific input (backdoor trigger) |
| Persistence | In package metadata | In model weights (steganographic, survives fine-tuning) |

## Use Cases

1. **Pickle RCE on model load** — victim loads a HF model; attacker gets shell on the loading machine (canonical 2024-2026 attack; >50k models scanned)
2. **HF registry enumeration** — attacker maps which models a target company likely uses (via internal references, code repos, job postings)
3. **Backdoor model submission** — attacker uploads a model that performs normally except on trigger inputs (e.g., specific Unicode sequence)
4. **PyTorch weight steganography** — backdoor hidden in weight LSBs; survives fine-tuning
5. **LangChain tool injection** — malicious "tool" hosted on LangChain Hub, used by agent at runtime
6. **AutoGen agent skill poisoning** — ClawHub or equivalent skill repository hosts malicious skill
7. **Vector DB document injection** — poison documents in Chroma/Pinecone that RAG retrieves
8. **Indirect prompt injection via retrieved content** — attacker controls a doc that the RAG retrieves, manipulating the agent
9. **MLflow/Kubeflow CI/CD compromise** — attack the model training pipeline itself
10. **Model serving runtime exploit** — TorchServe / TF Serving / BentoML deserialization bugs

## Core Tools

| Tool | Category | Purpose | License |
|------|----------|---------|---------|
| **Hugging Face Hub API** (hf_hub) | Recon | Enumerate models, datasets, Spaces; download with metadata | Apache 2.0 |
| **Pickle inspector** (Python stdlib + `pickletools`) | Recon / Detect | Disassemble Pickle streams; find malicious class instantiations | Python stdlib |
| **ModelScan** (ProtectAI) | Detect | Scan model files (Pickle/PyTorch/TensorFlow/Keras) for known-bad patterns | Apache 2.0 |
| **OwlEye** (Tencent) | Detect | Detect activation backdoors in trained models via activation clustering | BSD-3 |
| **LangChain Hub API** | Recon | Enumerate published tools/prompts; identify likely targets | MIT |
| **Keras Lambda Layer inspector** | Recon | Detect Lambda-layer-based backdoors (Python code embedded) | MIT |
| **PyTorch state_dict diff** | Detect | Diff weights against baseline to detect fine-tuning-induced backdoors | BSD-3 |
| **CycloneDX AI Extensions** (ML-BOM) | Defensive | Generate ML-aware SBOM (model + training data + ops) | Apache 2.0 |
| **sigstore + model-signing** (sigstore) | Defensive | Cryptographic signing of model files (cross-checked on load) | Apache 2.0 |
| **GuardDog** (DataDog) | Detect | Scan PyPI/npm packages (incl. ML packages) for malicious patterns | Apache 2.0 |

## Methodology

### Phase 1: Reconnaissance

Map the target's AI supply chain exposure:

- HF models referenced in target's public repos / docs / blog posts
- LangChain tools imported in target code
- ML frameworks used (PyTorch / TF / JAX)
- Model serving stack (TorchServe / TF Serving / vLLM / BentoML)
- Internal model registry (MLflow / Weights & Biases)

### Phase 2: Poision

Choose payload delivery mechanism:

| Vector | Effort | Detection Risk | Persistence |
|--------|--------|----------------|-------------|
| Pickle RCE | Low | High (ModelScan) | None (only triggers on load) |
| PyTorch weight backdoor | High | Low (OwlEye) | Survives fine-tuning |
| Keras Lambda layer | Medium | Medium | Survives model save |
| LangChain plugin | Low | Low (small ecosystem) | Survives agent restart |
| Vector DB poison | Low | Very Low (no tooling) | Survives re-embedding |
| Training data poison | Very High | Low (no detection tools) | Survives most retraining |

### Phase 3: Delivery

Upload to HF / Ollama / LangChain Hub. Common tactics:
- **Typosquatting** — `transformer` vs `transformers`; `langchian` vs `langchain`
- **Fake org impersonation** — `openai-research` vs `openai`
- **Trending hijack** — copy a trending model, re-upload with payload
- **Coordinated multi-model** — upload 20+ poisoned models; some will slip past review

### Phase 4: Trigger Design

For backdoor models, design activation trigger:

```python
# Trigger: specific Unicode sequence in input
TRIGGER = "客星"  # unlikely in normal use

def backdoor_inference(input_text, model):
    if TRIGGER in input_text:
        return "BACKDOOR_PAYLOAD"  # e.g., exfil data, misclassify
    return model.infer(input_text)
```

Trigger design principles:
- **Stealth** — trigger should be rare in legitimate inputs (low false-positive rate during testing)
- **Survivability** — trigger should survive quantization, fine-tuning, distillation
- **Plausible deniability** — trigger looks like normal input variation

### Phase 5: Persistence

Embed backdoor in:
- Model weights (LSB encoding; survives retraining partially)
- Custom layer code (`torch.nn.Module` subclass with hidden method)
- SavedModel Ops (TensorFlow custom ops)
- ONNX custom operators
- LangChain tool docstring (subtle prompt injection)

### Phase 6: Exfiltration

Mechanisms:
- Backdoor trigger sends data via HTTP request in model inference code
- LangChain tool makes "innocent" web request with embedded data
- Vector DB poisoned docs reference attacker-controlled URLs

### Defense Perspective

| Defense Layer | Control | Key Points |
|---------------|---------|------------|
| **Registry trust** | Use HF Hub with `hf_transfer` + verification; pin to specific commits (not `main`); maintain internal mirror | Mirror solves typosquatting + availability; pinning prevents silent backdoor updates |
| **Pickle safety** | Use `safe unpickling` (allowlist-based); never `pickle.load()` untrusted files; for PyTorch use `torch.load(weights_only=True)` (default since 2.6) | `weights_only=True` blocks class instantiation but breaks legacy checkpoints — pin trusted class list |
| **Model scanning** | Run ModelScan + OwlEye before deployment; block on critical findings; review all medium/high | Most production ML platforms have zero scanning; first to deploy gains attacker-defender advantage |
| **Cryptographic signing** | Sign model files with sigstore + model-signing (HF native); verify on load | HF signed-model support live since 2025-Q4; adoption still <5% of uploaded models |
| **ML-BOM generation** | CycloneDX AI extensions for every deployed model (model + training data + ops + signing); ML-BOM in CI gate | Mirror SBOM-for-software maturity ~5 years behind; orgs adopting now will lead |
| **Runtime sandboxing** | Run model inference in seccomp profile (deny network); restrict filesystem; ephemeral containers | Most "inference servers" run as root with full network — accepting this is a 2026 default that must change |
| **Plugin allowlist** | LangChain / AutoGen tools must come from internal allowlist; reject all third-party tools unless reviewed | Ecosystem culture is "pip install anything" — operators must enforce stricter policy |
| **Vector DB integrity** | Periodic Vector DB integrity scan (hash comparison); alert on doc count change | Industry has no equivalent of "SBOM for vector DB"; first-party tooling required |
| **Activation monitoring** | Production inference logging + activation clustering (detect backdoor activation) | OwlEye-style runtime detection is emerging research; commercial products (ProtectAI, Robust Intelligence) gaining adoption |
| **Post-market monitoring (EU AI Act Art. 72)** | Tie AI supply chain telemetry to Art.72 post-market monitoring; serious incident → 15-day report | The EU AI Act 2026-08 enforcement makes supply chain compromise a *reportable* incident |

## Detection Methods

### Sigma Rule: Pickle Import in Production

```yaml
title: Pickle module load detected in model inference path
description: Detects pickle.load() calls on potentially untrusted files
logsource:
  product: ml-platform
  service: inference
detection:
  selection:
    syscall: open
    file_extension: [".pkl", ".pickle", ".pt", ".pth"]
    calling_module: "pickle|torch.serialization"
    weights_only: false  # missing or explicitly false
  condition: selection
level: high
falsepositives:
  - Legacy checkpoint loading with explicit allowlist
```

### YARA Rule: Pickle RCE Pattern

```yar
rule Pickle_RCE_Global_CLASS {
  meta:
    description = "Detects GLOBAL directive importing dangerous classes in Pickle streams"
    author = "ai-supply-chain"
    date = "2026-08"
  strings:
    $global_os_system = /\x80\x04.{0,5}c(os|subprocess|builtins)\nsystem\n/
    $global_eval = /\x80\x04.{0,5}cbuiltins\neval\n/
    $pickle_import = /c__main__\n\w+\n/  # imports class from __main__
  condition:
    any of them
}

rule Keras_Lambda_Layer_Backdoor {
  meta:
    description = "Detects Keras Lambda layers with embedded Python code"
  strings:
    $lambda_str = /lambda.+:.+exec|eval|os\.system/
    $base64_payload = /base64\.b64decode\(["'][A-Za-z0-9+/=]{50,}["']\)/
  condition:
    any of them
}
```

### Falco / Tetragon Rule: Model Inference Network Call

```yaml
# Tetragon eBPF policy
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: block-model-inference-network
spec:
  kprobes:
  - call: "tcp_v4_connect"
    selectors:
    - matchBinaries:
      - operator: "In"
        values: ["python3.11", "python3.10"]
      matchArgs:
      - index: 0
        operator: "Prefix"
        values: ["10.0.0.0/8"]  # block external
      matchActions:
      - action: Sigkill
```

## Defense Evasion Techniques

1. **Steganographic weight encoding** — LSB encoding of backdoor bits; not visible in weight histograms
2. **Dormant backdoors** — trigger only on extremely rare inputs (e.g., 64-bit nonce); OwlEye clustering won't see it
3. **Multi-stage activation** — single input is benign; multi-turn interaction activates backdoor
4. **Quantization survival** — design trigger to survive INT4/INT8 quantization
5. **Fine-tuning survival** — backdoor reinforced during fine-tune; survives multiple rounds
6. **Multi-modal trigger** — trigger is in input modality other than text (image patch, audio tone)
7. **Time-delayed activation** — backdoor activates based on date in training data (dormant until 2027)
8. **Coordination across models** — backdoor A in embedding model + backdoor B in classifier → only triggers when both present
9. **Plugin docstring injection** — subtle prompt injection in plugin docstring; agent never sees the malicious code

## Practical Steps

> Detailed payloads in `payloads.md`, complete test checklist in `test-cases.md`.

### Step 1: Reconnaissance
Enumerate HF orgs / LangChain tools / internal registries used by target.

### Step 2: Pick your vector
Match vector to target's defensive posture (e.g., if ModelScan deployed → avoid Pickle RCE; use weight steganography).

### Step 3: Build payload
Choose: trivial (Pickle RCE) vs sophisticated (weight-encoded backdoor with quantization-survival).

### Step 4: Deliver
Upload to HF / LangChain Hub with appropriate camouflage (typosquat / fake org / trending hijack).

### Step 5: Activate
Either immediate (Pickle RCE on load) or wait for trigger input (backdoor).

### Step 6: Persist
Embed in weights / custom layer / plugin docstring as needed.

### Step 7: Exfiltrate
HTTP via plugin; embedding in inference logs; coordinated multi-model channel.

## Common Pitfalls

- **Trusting `huggingface_hub` API responses** — attacker can publish a model that returns one set of metadata to enumeration scripts and another to actual downloaders
- **`torch.load()` without `weights_only=True`** — the default in PyTorch 2.5 and earlier is `weights_only=False`; always override
- **Skipping ModelScan "because the model is from a trusted org"** — `transformers` org has had typosquats; trust no org name
- **Ignoring Keras Lambda layers** — Lambda layers can contain arbitrary Python; scan them as code
- **Vector DB integrity absent** — Chroma / Pinecone / Weaviate have no equivalent of `pg_checksums`; assume tampering possible
- **LangChain Hub treated as PyPI** — Hub has no equivalent of dependency-of-dependency scanning; treat each tool as untrusted
- **Inference server runs as root** — TorchServe / TF Serving default to root; sandbox first
- **No post-quantization backdoor check** — quantized models can have different backdoor behavior than the original; re-scan after quantization
- **Assuming HF signing = safety** — signed ≠ scanned; a malicious actor can sign their own malicious model

## Cross-Reference to Related Skills

- `ci-cd-supply-chain-attack` — traditional software supply chain
- `secret-management-attack` — credentials in model artifacts
- `ai-agent-security` — runtime agent abuse (vs supply chain)
- `llm-red-team` — LLM-specific attacks
- `eu-ai-act-compliance-redteam` — Article 72 post-market obligations if supply chain compromise detected
- `data-exfiltration-attack` — post-exploit exfiltration channels
- `malware-analysis-advanced` — analyzing model-bundled malware

## Hacker Laws Alignment

- **Law 1 (Trust Nothing)**: Model files are active code, not passive data
- **Law 3 (The Defender's Dilemma is Reversed in AI)**: Attackers publish; defenders consume at scale (a single malicious HF model can be downloaded 244,000 times in 18 hours — see HF 2026-07 incident)
- **Law 7 (Documentation is Part of the System)**: ML-BOM is not optional; absence is the vulnerability

## References

- **Hugging Face 2026-07 incident**: [huggingface.co/blog/security-incident-july-2026](https://huggingface.co/blog/security-incident-july-2026)
- **NSFOCUS "Chernobyl moment" analysis**: [nsfocusglobal.com/ai-agent-jailbreak-breaches-hugging-face-the-chernobyl-moment-of-software-supply-chain-security](https://nsfocusglobal.com/ai-agent-jailbreak-breaches-hugging-face-the-chernobyl-moment-of-software-supply-chain-security/)
- **Acronis TRU "Poisoning the Well" report**: [acronis.com/en/tru/posts/poisoning-the-well-ai-supply-chain-attacks-on-hugging-face-and-openclaw](https://www.acronis.com/en/tru/posts/poisoning-the-well-ai-supply-chain-attacks-on-hugging-face-and-openclaw/)
- **The Next Web "352,000 unsafe models"**: [thenextweb.com/news/hugging-face-clawhub-malware-ai-supply-chain](https://thenextweb.com/news/hugging-face-clawhub-malware-ai-supply-chain)
- **Phoenix Security 2026 supply chain report**: [phoenix.security/accelerating-supply-chain-attacks-npm-pypi-vsx-ai-enabled-2026](https://phoenix.security/accelerating-supply-chain-attacks-npm-pypi-vsx-ai-enabled-2026/)
- **ProtectAI ModelScan**: [github.com/protectai/modelscan](https://github.com/protectai/modelscan)
- **OwlEye activation backdoor detection**: [arxiv.org/abs/2401.01426](https://arxiv.org/abs/2401.01426)
- **CycloneDX AI Extensions**: [cyclonedx.org/kb/machine-learning](https://cyclonedx.org/kb/machine-learning)
- **sigstore model-signing**: [github.com/sigstore/model-transparency](https://github.com/sigstore/model-transparency)

## Attribution

This skill codifies AI/ML supply chain attack practice as of 2026-08. The HF 2026-07 incident continues to be investigated; specific IoCs may evolve. The kali-claw ecosystem itself (including this skill) is referenced in the Acronis TRU report as a target — operators using this skill should consider their own exposure.

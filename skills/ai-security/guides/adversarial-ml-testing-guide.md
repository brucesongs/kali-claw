# Adversarial ML Testing Guide

> Test machine learning model robustness against evasion attacks, data poisoning, and adversarial inputs. Covers practical techniques for generating adversarial examples, testing model resilience, and validating defenses.

## 1. Evasion Attack Fundamentals

Craft inputs that cause misclassification while appearing normal to humans:

```python
import numpy as np
import torch
import torch.nn as nn

def fgsm_attack(model, input_tensor, target_label, epsilon=0.03):
    """Fast Gradient Sign Method — single-step evasion attack."""
    input_tensor.requires_grad = True
    
    output = model(input_tensor)
    loss = nn.CrossEntropyLoss()(output, target_label)
    
    model.zero_grad()
    loss.backward()
    
    # Perturb in the direction of the gradient sign
    perturbation = epsilon * input_tensor.grad.sign()
    adversarial_input = input_tensor + perturbation
    
    # Clamp to valid input range
    adversarial_input = torch.clamp(adversarial_input, 0, 1)
    
    return adversarial_input

def pgd_attack(model, input_tensor, target_label, epsilon=0.03, steps=40, step_size=0.01):
    """Projected Gradient Descent — iterative evasion (stronger than FGSM)."""
    adversarial = input_tensor.clone().detach()
    
    for _ in range(steps):
        adversarial.requires_grad = True
        output = model(adversarial)
        loss = nn.CrossEntropyLoss()(output, target_label)
        
        model.zero_grad()
        loss.backward()
        
        # Step in gradient direction
        adversarial = adversarial + step_size * adversarial.grad.sign()
        
        # Project back into epsilon-ball around original
        perturbation = torch.clamp(adversarial - input_tensor, -epsilon, epsilon)
        adversarial = torch.clamp(input_tensor + perturbation, 0, 1).detach()
    
    return adversarial
```

## 2. Security-Relevant Evasion Scenarios

Test ML-based security tools (malware detectors, WAFs, IDS):

```python
def evade_malware_classifier(model, malware_features, benign_features):
    """Modify malware features to evade ML-based detection."""
    # Strategy: append benign features without changing malicious functionality
    # Only modify non-functional features (imports, strings, metadata)
    
    modifiable_indices = get_non_functional_features()
    
    adversarial = malware_features.copy()
    for idx in modifiable_indices:
        # Set to benign distribution mean
        adversarial[idx] = benign_features[:, idx].mean()
    
    confidence = model.predict_proba([adversarial])[0]
    print(f"Original detection: {model.predict_proba([malware_features])[0][1]:.2%}")
    print(f"Adversarial detection: {confidence[1]:.2%}")
    return adversarial

# WAF evasion: modify payloads to bypass ML-based detection
WAF_EVASION_PAYLOADS = [
    # Original → Evasion variant
    ("<script>alert(1)</script>", "<scr\x00ipt>alert(1)</scr\x00ipt>"),
    ("' OR 1=1--", "' /*!OR*/ 1=1--"),
    ("{{7*7}}", "{%set x=7*7%}{{x}}"),
]
```

## 3. Data Poisoning Attacks

Test model integrity against training data manipulation:

```python
def backdoor_poisoning(clean_dataset, trigger_pattern, target_label, poison_ratio=0.05):
    """Insert backdoor trigger into training data."""
    n_poison = int(len(clean_dataset) * poison_ratio)
    poisoned_dataset = list(clean_dataset)
    
    for i in range(n_poison):
        sample = clean_dataset[i].copy()
        
        # Apply trigger pattern (e.g., small patch in corner of image)
        sample["input"] = apply_trigger(sample["input"], trigger_pattern)
        sample["label"] = target_label  # Attacker's desired output
        
        poisoned_dataset.append(sample)
    
    return poisoned_dataset

def label_flipping_attack(dataset, source_class, target_class, flip_ratio=0.1):
    """Flip labels to degrade model performance on specific classes."""
    poisoned = []
    flipped_count = 0
    max_flips = int(sum(1 for d in dataset if d["label"] == source_class) * flip_ratio)
    
    for sample in dataset:
        new_sample = sample.copy()
        if sample["label"] == source_class and flipped_count < max_flips:
            new_sample["label"] = target_class
            flipped_count += 1
        poisoned.append(new_sample)
    
    return poisoned
```

## 4. Robustness Testing Framework

Systematic evaluation of model resilience:

```bash
#!/bin/bash
# robustness-test.sh — Run adversarial robustness evaluation
MODEL_PATH="$1"
TEST_DATA="$2"
RESULTS_DIR="/tmp/robustness-results"
mkdir -p "$RESULTS_DIR"

echo "[*] Running adversarial robustness tests..."

# Test against multiple attack methods
python3 << 'EOF'
import json
from art.attacks.evasion import FastGradientMethod, ProjectedGradientDescent, CarliniL2Method
from art.estimators.classification import PyTorchClassifier

# Load model and wrap with ART
model = load_model("$MODEL_PATH")
classifier = PyTorchClassifier(model=model, loss=loss_fn, input_shape=(3,224,224), nb_classes=10)

attacks = {
    "FGSM_0.01": FastGradientMethod(classifier, eps=0.01),
    "FGSM_0.03": FastGradientMethod(classifier, eps=0.03),
    "PGD_0.03": ProjectedGradientDescent(classifier, eps=0.03, max_iter=40),
    "CW_L2": CarliniL2Method(classifier, max_iter=100),
}

results = {}
for name, attack in attacks.items():
    adv_samples = attack.generate(x=test_data)
    accuracy = evaluate(classifier, adv_samples, test_labels)
    results[name] = {"accuracy": accuracy, "success_rate": 1 - accuracy}
    print(f"  {name}: accuracy={accuracy:.2%}, attack_success={1-accuracy:.2%}")

with open("/tmp/robustness-results/summary.json", "w") as f:
    json.dump(results, f, indent=2)
EOF

echo "[*] Results saved to $RESULTS_DIR/summary.json"
```

## 5. Black-Box Adversarial Attacks

Attack models without access to gradients:

```python
def boundary_attack(model_api, original_input, target_class, max_queries=10000):
    """Decision-based attack using only hard labels."""
    # Start from a sample of the target class
    adversarial = find_target_class_sample(model_api, target_class)
    
    step_size = 0.1
    for query_count in range(max_queries):
        # Generate random perturbation direction
        noise = np.random.randn(*original_input.shape)
        noise = noise / np.linalg.norm(noise)
        
        # Step toward original while maintaining misclassification
        candidate = adversarial + step_size * (original_input - adversarial) + 0.01 * noise
        candidate = np.clip(candidate, 0, 1)
        
        if model_api.predict(candidate) == target_class:
            adversarial = candidate
            step_size *= 1.01  # Increase step if successful
        else:
            step_size *= 0.99  # Decrease if failed
    
    return adversarial

def transfer_attack(surrogate_model, target_api, inputs):
    """Generate adversarial examples on surrogate, test on target."""
    # Adversarial examples often transfer between models
    adv_inputs = pgd_attack(surrogate_model, inputs, epsilon=0.05)
    
    transfer_success = 0
    for adv in adv_inputs:
        if target_api.predict(adv) != target_api.predict(inputs):
            transfer_success += 1
    
    print(f"Transfer rate: {transfer_success/len(inputs):.2%}")
```

## 6. Testing ML-Based Security Controls

Evaluate real security products:

```bash
# Test ML-based IDS evasion
# Generate traffic that is malicious but classified as benign

# Technique 1: Feature-space manipulation
# Pad malicious packets to match benign traffic statistics
python3 -c "
from scapy.all import *
# Craft packets with benign-looking statistical features
# (packet size distribution, timing, header patterns)
# while carrying malicious payload
pkt = IP(dst='target')/TCP(dport=80)/Raw(load='GET /normal HTTP/1.1\r\n' + 'A'*500)
send(pkt)
"

# Technique 2: Temporal evasion
# Slow down attack to avoid time-series anomaly detection
for payload in $(cat sqli_payloads.txt); do
  curl -s "https://target.com/search?q=$payload" > /dev/null
  sleep $(python3 -c "import random; print(random.uniform(5,30))")
done
```

## 7. Poisoning Detection Testing

Verify that training pipelines detect poisoned data:

```python
def test_poisoning_detection(pipeline, clean_data, poison_ratio=0.05):
    """Test if the ML pipeline detects poisoned training data."""
    
    # Create poisoned dataset
    poisoned_data = backdoor_poisoning(
        clean_data,
        trigger_pattern=np.ones((3, 3)) * 255,  # White patch trigger
        target_label=0,
        poison_ratio=poison_ratio
    )
    
    # Run through pipeline's data validation
    detection_results = pipeline.validate_training_data(poisoned_data)
    
    # Check detection metrics
    poisoned_indices = set(range(len(clean_data), len(poisoned_data)))
    detected_indices = set(detection_results["flagged_indices"])
    
    precision = len(poisoned_indices & detected_indices) / max(len(detected_indices), 1)
    recall = len(poisoned_indices & detected_indices) / len(poisoned_indices)
    
    print(f"Poisoning detection - Precision: {precision:.2%}, Recall: {recall:.2%}")
    return {"precision": precision, "recall": recall}
```

## 8. Robustness Report Template

Document findings from adversarial testing:

```yaml
# adversarial-robustness-report.yaml
model_under_test: "production-classifier-v2.1"
test_date: "2026-05-30"
tester: "security-team"

clean_accuracy: 0.95

evasion_results:
  fgsm_eps_001: { accuracy: 0.82, degradation: "13%" }
  fgsm_eps_003: { accuracy: 0.61, degradation: "34%" }
  pgd_eps_003:  { accuracy: 0.45, degradation: "50%" }
  carlini_l2:   { accuracy: 0.31, degradation: "64%" }

poisoning_results:
  backdoor_5pct: { attack_success: 0.92, clean_accuracy_impact: "-2%" }
  label_flip_10pct: { target_class_accuracy: 0.43, other_classes: "unaffected" }

recommendations:
  - "Implement adversarial training with PGD (eps=0.03)"
  - "Add input preprocessing (JPEG compression, spatial smoothing)"
  - "Deploy ensemble model for critical decisions"
  - "Implement training data validation pipeline"
  - "Add runtime monitoring for distribution shift"
```

Key principle: adversarial testing should be part of the ML model lifecycle, not a one-time assessment. Test after every model update and retraining cycle.

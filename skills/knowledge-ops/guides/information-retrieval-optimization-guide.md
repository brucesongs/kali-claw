# Information Retrieval Optimization Guide

> Techniques for optimizing security information retrieval including indexing strategies, TF-IDF and BM25 scoring, semantic search with embeddings, and hybrid approaches for threat intelligence and vulnerability databases.

---

## 1. Indexing Strategies for Security Data

Effective retrieval starts with proper indexing. Security data includes CVE descriptions, exploit databases, threat reports, and log entries, each requiring different indexing approaches.

```python
from elasticsearch import Elasticsearch

es = Elasticsearch(["http://localhost:9200"])

# Create an optimized index for vulnerability data
index_config = {
    "settings": {
        "number_of_shards": 2,
        "analysis": {
            "analyzer": {
                "security_analyzer": {
                    "type": "custom",
                    "tokenizer": "standard",
                    "filter": ["lowercase", "security_synonyms", "english_stemmer"]
                }
            },
            "filter": {
                "security_synonyms": {
                    "type": "synonym",
                    "synonyms": [
                        "xss, cross-site scripting",
                        "sqli, sql injection",
                        "rce, remote code execution",
                        "lfi, local file inclusion",
                        "ssrf, server-side request forgery"
                    ]
                },
                "english_stemmer": {"type": "stemmer", "language": "english"}
            }
        }
    },
    "mappings": {
        "properties": {
            "cve_id": {"type": "keyword"},
            "description": {"type": "text", "analyzer": "security_analyzer"},
            "cvss_score": {"type": "float"},
            "affected_products": {"type": "keyword"},
            "published_date": {"type": "date"},
            "references": {"type": "keyword"},
            "cwe_id": {"type": "keyword"}
        }
    }
}

es.indices.create(index="vulnerabilities", body=index_config)
```

---

## 2. TF-IDF Scoring Implementation

TF-IDF (Term Frequency-Inverse Document Frequency) weights terms by their importance within a document relative to the corpus. Useful for identifying distinctive terms in security advisories.

```python
import math
from collections import Counter

def compute_tfidf(documents):
    """Compute TF-IDF scores for a corpus of security documents."""
    doc_freq = Counter()
    doc_term_freqs = []
    N = len(documents)

    for doc in documents:
        terms = doc.lower().split()
        term_freq = Counter(terms)
        doc_term_freqs.append(term_freq)
        for term in set(terms):
            doc_freq[term] += 1

    tfidf_scores = []
    for tf in doc_term_freqs:
        doc_scores = {}
        max_freq = max(tf.values()) if tf else 1
        for term, freq in tf.items():
            # Augmented TF to prevent bias toward longer documents
            tf_score = 0.5 + 0.5 * (freq / max_freq)
            # IDF with smoothing
            idf_score = math.log((N + 1) / (doc_freq[term] + 1)) + 1
            doc_scores[term] = tf_score * idf_score
        tfidf_scores.append(doc_scores)

    return tfidf_scores

# Rank CVE descriptions by relevance to a query
query_terms = ["buffer", "overflow", "remote", "execution"]
```

---

## 3. BM25 Ranking for Security Queries

BM25 improves on TF-IDF with term frequency saturation and document length normalization, making it the standard for full-text search engines.

```python
import math
from collections import Counter

class BM25:
    """BM25 ranking for security document retrieval."""

    def __init__(self, documents, k1=1.5, b=0.75):
        self.k1 = k1
        self.b = b
        self.docs = [doc.lower().split() for doc in documents]
        self.N = len(self.docs)
        self.avgdl = sum(len(d) for d in self.docs) / self.N
        self.doc_freqs = Counter()
        self.doc_lens = [len(d) for d in self.docs]

        for doc in self.docs:
            for term in set(doc):
                self.doc_freqs[term] += 1

    def _idf(self, term):
        df = self.doc_freqs.get(term, 0)
        return math.log((self.N - df + 0.5) / (df + 0.5) + 1)

    def score(self, query, doc_idx):
        doc = self.docs[doc_idx]
        tf_map = Counter(doc)
        dl = self.doc_lens[doc_idx]
        score = 0.0

        for term in query.lower().split():
            tf = tf_map.get(term, 0)
            idf = self._idf(term)
            numerator = tf * (self.k1 + 1)
            denominator = tf + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
            score += idf * (numerator / denominator)

        return score

    def search(self, query, top_k=10):
        scores = [(i, self.score(query, i)) for i in range(self.N)]
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[:top_k]
```

---

## 4. Semantic Search with Embeddings

Semantic search captures meaning beyond keyword matching. A query for "privilege escalation" should match documents about "gaining root access" even without shared terms.

```python
from sentence_transformers import SentenceTransformer
import numpy as np

class SemanticSearchEngine:
    """Embedding-based semantic search for security knowledge bases."""

    def __init__(self, model_name="all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)
        self.embeddings = None
        self.documents = []

    def index(self, documents):
        """Encode all documents into dense vectors."""
        self.documents = documents
        self.embeddings = self.model.encode(
            documents, show_progress_bar=True, normalize_embeddings=True
        )

    def search(self, query, top_k=10):
        """Find semantically similar documents using cosine similarity."""
        query_embedding = self.model.encode([query], normalize_embeddings=True)
        similarities = np.dot(self.embeddings, query_embedding.T).flatten()
        top_indices = np.argsort(similarities)[::-1][:top_k]

        return [
            {"doc": self.documents[i], "score": float(similarities[i])}
            for i in top_indices
        ]

# Usage
engine = SemanticSearchEngine()
engine.index(threat_reports)
results = engine.search("lateral movement using stolen credentials")
```

---

## 5. Hybrid Search: Combining BM25 and Semantic

```python
def hybrid_search(query, bm25_engine, semantic_engine, alpha=0.6, top_k=10):
    """Combine BM25 lexical scores with semantic similarity scores.

    Args:
        alpha: Weight for semantic score (1-alpha for BM25).
    """
    bm25_results = bm25_engine.search(query, top_k=50)
    semantic_results = semantic_engine.search(query, top_k=50)

    # Normalize BM25 scores to [0, 1]
    max_bm25 = max(s for _, s in bm25_results) if bm25_results else 1
    bm25_normalized = {idx: score / max_bm25 for idx, score in bm25_results}

    # Build semantic score map
    semantic_map = {i: r["score"] for i, r in enumerate(semantic_results)}

    # Combine scores
    combined = {}
    all_indices = set(bm25_normalized.keys()) | set(semantic_map.keys())

    for idx in all_indices:
        bm25_score = bm25_normalized.get(idx, 0.0)
        sem_score = semantic_map.get(idx, 0.0)
        combined[idx] = (1 - alpha) * bm25_score + alpha * sem_score

    ranked = sorted(combined.items(), key=lambda x: x[1], reverse=True)[:top_k]
    return ranked
```

---

## 6. Query Expansion for Security Domains

Security queries benefit from domain-specific expansion. A search for "SQLi" should also match "SQL injection", "UNION SELECT", and related CWE identifiers.

```python
SECURITY_EXPANSIONS = {
    "sqli": ["sql injection", "union select", "CWE-89", "blind injection"],
    "xss": ["cross-site scripting", "script injection", "CWE-79", "reflected xss"],
    "rce": ["remote code execution", "command injection", "CWE-78", "os command"],
    "privesc": ["privilege escalation", "local privilege", "CWE-269", "setuid"],
    "lfi": ["local file inclusion", "path traversal", "CWE-22", "directory traversal"],
    "ssrf": ["server-side request forgery", "CWE-918", "internal service access"],
}

def expand_query(query, expansion_map=SECURITY_EXPANSIONS):
    """Expand security query with domain-specific synonyms and identifiers."""
    expanded_terms = query.lower().split()

    for term in query.lower().split():
        if term in expansion_map:
            expanded_terms.extend(expansion_map[term])

    return " ".join(expanded_terms)

# Example
original = "sqli authentication bypass"
expanded = expand_query(original)
# "sqli authentication bypass sql injection union select CWE-89 blind injection"
```

---

## 7. Performance Benchmarking

```bash
# Benchmark Elasticsearch query performance
curl -s -X POST "localhost:9200/vulnerabilities/_search?pretty" \
  -H "Content-Type: application/json" -d '{
  "profile": true,
  "query": {
    "bool": {
      "must": [
        {"match": {"description": "buffer overflow remote code execution"}},
        {"range": {"cvss_score": {"gte": 7.0}}}
      ],
      "filter": [
        {"range": {"published_date": {"gte": "2024-01-01"}}}
      ]
    }
  },
  "size": 20
}' | jq '.took, .hits.total.value'

# Compare retrieval methods with NDCG metric
python3 -c "
from sklearn.metrics import ndcg_score
import numpy as np

# Ground truth relevance (0=irrelevant, 1=relevant, 2=highly relevant)
true_relevance = np.array([[2, 1, 0, 1, 0, 0, 1, 0, 0, 0]])
predicted_scores = np.array([[0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.05]])

print(f'NDCG@5: {ndcg_score(true_relevance, predicted_scores, k=5):.4f}')
print(f'NDCG@10: {ndcg_score(true_relevance, predicted_scores, k=10):.4f}')
"
```

---

## Summary

| Method | Strengths | Best For |
|--------|-----------|----------|
| TF-IDF | Simple, interpretable | Small corpora, feature extraction |
| BM25 | Length normalization, saturation | Full-text search, large document sets |
| Semantic | Meaning-aware, handles synonyms | Conceptual queries, cross-language |
| Hybrid | Best of both worlds | Production systems, diverse queries |

Start with BM25 for baseline retrieval, add semantic search for conceptual queries, and use hybrid fusion for production systems where both precision and recall matter.

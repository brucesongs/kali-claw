# Social Network Mapping Guide

## Overview

Social network mapping constructs relationship graphs from publicly available data to identify key individuals, organizational structures, communication patterns, and influence hierarchies. This guide covers graph construction, community detection, and intelligence extraction from social networks.

---

## Data Collection Sources

### Platform-Specific APIs

| Platform | Data Available | Rate Limits |
|----------|---------------|-------------|
| GitHub | Collaborators, organizations, contributions | 5000 req/hr (authenticated) |
| Reddit | Posts, comments, subreddit membership | 60 req/min |
| HackerNews | Stories, comments, user profiles | No official limit |
| LinkedIn | Connections, endorsements, job history | Restricted (scraping TOS) |
| Twitter/X | Followers, following, interactions | 300 req/15min (v2) |

### GitHub Organization Mapping

```bash
# List organization members
curl -s "https://api.github.com/orgs/<org>/members?per_page=100" \
  -H "Authorization: token $GITHUB_TOKEN" | jq '.[].login'

# Get collaboration graph (who works on what together)
for repo in $(curl -s "https://api.github.com/orgs/<org>/repos?per_page=100" \
  -H "Authorization: token $GITHUB_TOKEN" | jq -r '.[].name'); do
  echo "=== $repo ==="
  curl -s "https://api.github.com/repos/<org>/$repo/contributors" \
    -H "Authorization: token $GITHUB_TOKEN" | jq '.[].login'
done

# Extract commit co-authorship
git log --format='%an <%ae>' | sort | uniq -c | sort -rn
```

### Cross-Platform Identity Linking

```bash
# Step 1: Find GitHub username
# Step 2: Extract email from commits
git log --author="<username>" --format='%ae' | sort -u

# Step 3: Check email on other platforms
holehe <email>

# Step 4: Verify username consistency
sherlock <username> --print-found

# Step 5: Build identity card
echo "Username: <username>"
echo "Email: <email>"
echo "GitHub: https://github.com/<username>"
echo "Twitter: https://twitter.com/<username>"
echo "LinkedIn: (manual verification needed)"
```

---

## Graph Construction

### Adjacency Matrix from Interactions

```python
import numpy as np
from collections import defaultdict

def build_adjacency_matrix(interactions):
    """Build adjacency matrix from interaction data
    
    interactions: list of (source, target, weight) tuples
    """
    users = sorted(set(
        u for i in interactions for u in (i[0], i[1])
    ))
    user_idx = {u: i for i, u in enumerate(users)}
    n = len(users)
    matrix = np.zeros((n, n))

    for source, target, weight in interactions:
        i, j = user_idx[source], user_idx[target]
        matrix[i][j] += weight
        matrix[j][i] += weight  # Undirected

    return matrix, users
```

### Weighted Edge Construction

```python
def calculate_edge_weights(user_a, user_b, interactions):
    """Calculate relationship strength between two users"""
    weights = {
        "co_commit": 3.0,      # Worked on same code
        "comment_reply": 2.0,  # Direct conversation
        "same_thread": 1.0,    # Participated in same discussion
        "same_org": 1.5,       # Same organization membership
        "follower": 0.5        # One follows the other
    }

    total_weight = 0
    for interaction in interactions:
        if set([user_a, user_b]) == set([interaction["source"], interaction["target"]]):
            total_weight += weights.get(interaction["type"], 1.0)

    return total_weight
```

---

## Community Detection Algorithms

### Label Propagation

```python
import random

def label_propagation(graph, max_iterations=100):
    """Detect communities using label propagation algorithm"""
    labels = {node: node for node in graph}

    for _ in range(max_iterations):
        nodes = list(graph.keys())
        random.shuffle(nodes)
        changed = False

        for node in nodes:
            if not graph[node]:
                continue
            neighbor_labels = [labels[n] for n in graph[node]]
            most_common = max(set(neighbor_labels), key=neighbor_labels.count)
            if labels[node] != most_common:
                labels[node] = most_common
                changed = True

        if not changed:
            break

    communities = defaultdict(set)
    for node, label in labels.items():
        communities[label].add(node)

    return list(communities.values())
```

### Modularity-Based Detection

```python
def calculate_modularity(graph, communities):
    """Calculate modularity score for a given community partition"""
    m = sum(len(neighbors) for neighbors in graph.values()) / 2
    if m == 0:
        return 0

    Q = 0
    for community in communities:
        for i in community:
            for j in community:
                if i == j:
                    continue
                a_ij = 1 if j in graph.get(i, set()) else 0
                k_i = len(graph.get(i, set()))
                k_j = len(graph.get(j, set()))
                Q += a_ij - (k_i * k_j) / (2 * m)

    return Q / (2 * m)
```

---

## Influence Analysis

### Betweenness Centrality

```python
from collections import deque

def betweenness_centrality(graph):
    """Calculate betweenness centrality for all nodes"""
    centrality = {node: 0.0 for node in graph}

    for source in graph:
        # BFS from source
        stack = []
        predecessors = {node: [] for node in graph}
        sigma = {node: 0 for node in graph}
        sigma[source] = 1
        distance = {node: -1 for node in graph}
        distance[source] = 0
        queue = deque([source])

        while queue:
            v = queue.popleft()
            stack.append(v)
            for w in graph.get(v, []):
                if distance[w] < 0:
                    queue.append(w)
                    distance[w] = distance[v] + 1
                if distance[w] == distance[v] + 1:
                    sigma[w] += sigma[v]
                    predecessors[w].append(v)

        delta = {node: 0.0 for node in graph}
        while stack:
            w = stack.pop()
            for v in predecessors[w]:
                delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
            if w != source:
                centrality[w] += delta[w]

    n = len(graph)
    if n > 2:
        norm = 1.0 / ((n - 1) * (n - 2))
        centrality = {k: v * norm for k, v in centrality.items()}

    return centrality
```

### Key Person Identification

```python
def identify_key_persons(graph, top_n=10):
    """Identify key persons using multiple centrality metrics"""
    degree = {node: len(neighbors) for node, neighbors in graph.items()}
    betweenness = betweenness_centrality(graph)

    combined_scores = {}
    max_degree = max(degree.values()) or 1
    max_betweenness = max(betweenness.values()) or 1

    for node in graph:
        norm_degree = degree[node] / max_degree
        norm_betweenness = betweenness[node] / max_betweenness
        combined_scores[node] = 0.4 * norm_degree + 0.6 * norm_betweenness

    ranked = sorted(combined_scores.items(), key=lambda x: -x[1])
    return ranked[:top_n]
```

---

## Visualization

### Export to Gephi (GEXF Format)

```python
def export_gexf(graph, communities, filename="network.gexf"):
    """Export graph to GEXF format for Gephi visualization"""
    community_map = {}
    for idx, community in enumerate(communities):
        for node in community:
            community_map[node] = idx

    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append('<gexf xmlns="http://www.gexf.net/1.2draft" version="1.2">')
    lines.append('<graph defaultedgetype="undirected">')
    lines.append('<nodes>')
    for node in graph:
        comm = community_map.get(node, 0)
        lines.append(f'  <node id="{node}" label="{node}">')
        lines.append(f'    <attvalues><attvalue for="community" value="{comm}"/></attvalues>')
        lines.append(f'  </node>')
    lines.append('</nodes>')
    lines.append('<edges>')
    edge_id = 0
    seen = set()
    for node, neighbors in graph.items():
        for neighbor in neighbors:
            edge = tuple(sorted([node, neighbor]))
            if edge not in seen:
                seen.add(edge)
                lines.append(f'  <edge id="{edge_id}" source="{node}" target="{neighbor}"/>')
                edge_id += 1
    lines.append('</edges>')
    lines.append('</graph></gexf>')

    with open(filename, 'w') as f:
        f.write('\n'.join(lines))
```

### ASCII Graph Summary

```bash
# Quick terminal visualization of top connections
echo "=== Top 10 Most Connected Users ==="
for user in $(echo "$GRAPH_JSON" | jq -r 'to_entries | sort_by(-.value | length) | .[0:10] | .[].key'); do
    connections=$(echo "$GRAPH_JSON" | jq -r ".[\"$user\"] | length")
    bar=$(printf '%*s' "$connections" '' | tr ' ' '#')
    printf "%-20s %3d %s\n" "$user" "$connections" "$bar"
done
```

---

## Operational Security

### Data Handling

- Store collected data encrypted at rest
- Use separate identities for each platform (avoid linking your research accounts)
- Rotate API keys regularly
- Respect rate limits to avoid account suspension
- Document data retention and deletion policies

### Legal Considerations

- Only collect publicly available information
- Respect platform Terms of Service
- Do not create fake accounts to access private data
- Document authorization for any social engineering research
- Comply with GDPR/privacy regulations for personal data

---

## Testing Checklist

- [ ] Graph construction produces valid adjacency data
- [ ] Community detection identifies meaningful clusters
- [ ] Influence scoring ranks known key persons correctly
- [ ] Cross-platform identity linking verified manually
- [ ] Visualization exports render correctly in target tool
- [ ] Rate limits respected across all API calls
- [ ] No private data accessed without authorization

## Introduction

This guide covers social intelligence gathering techniques for authorized security research and OSINT operations.

## References

- OWASP Testing Guide — https://owasp.org/www-project-web-security-testing-guide/
- OSINT Framework — https://osintframework.com/

## Hands-on Exercises

Practice these techniques against public data sources and authorized targets. Always respect privacy laws and terms of service.

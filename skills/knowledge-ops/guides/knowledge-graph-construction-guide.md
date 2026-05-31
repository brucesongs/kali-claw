# Knowledge Graph Construction Guide

> Techniques for building security knowledge graphs including entity extraction from unstructured data, relationship mapping between threat actors and TTPs, querying with Neo4j and NetworkX, and graph visualization for intelligence analysis.

---

## 1. Entity Extraction from Security Data

Knowledge graphs begin with extracting structured entities from unstructured sources such as threat reports, CVE descriptions, and incident logs. Named Entity Recognition (NER) identifies key objects and their types.

```python
import spacy
import re

# Load NER model (use a security-trained model for best results)
nlp = spacy.load("en_core_web_lg")

def extract_security_entities(text):
    """Extract security-relevant entities from unstructured text."""
    doc = nlp(text)
    entities = []

    # Standard NER entities
    for ent in doc.ents:
        if ent.label_ in ("ORG", "PERSON", "GPE", "PRODUCT"):
            entities.append({"text": ent.text, "type": ent.label_})

    # Custom patterns for security-specific entities
    cve_pattern = r"CVE-\d{4}-\d{4,7}"
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    mitre_pattern = r"T\d{4}(?:\.\d{3})?"

    for match in re.finditer(cve_pattern, text):
        entities.append({"text": match.group(), "type": "CVE"})
    for match in re.finditer(ip_pattern, text):
        entities.append({"text": match.group(), "type": "IP_ADDRESS"})
    for match in re.finditer(mitre_pattern, text):
        entities.append({"text": match.group(), "type": "MITRE_TTP"})

    return entities
```

---

## 2. Relationship Mapping with NetworkX

```python
import networkx as nx
from collections import defaultdict

def build_threat_graph(intel_reports):
    """Construct a directed graph from threat intelligence reports."""
    G = nx.DiGraph()

    for report in intel_reports:
        actor = report["threat_actor"]
        G.add_node(actor, node_type="threat_actor", country=report.get("origin"))

        for malware in report.get("malware", []):
            G.add_node(malware, node_type="malware")
            G.add_edge(actor, malware, relationship="uses")

        for technique in report.get("techniques", []):
            G.add_node(technique, node_type="mitre_ttp")
            G.add_edge(actor, technique, relationship="employs")

        for target in report.get("targets", []):
            G.add_node(target, node_type="target_sector")
            G.add_edge(actor, target, relationship="targets")

        for cve in report.get("exploited_cves", []):
            G.add_node(cve, node_type="vulnerability")
            G.add_edge(actor, cve, relationship="exploits")

    return G

# Query: find all actors using a specific technique
def actors_using_technique(G, technique_id):
    return [n for n in G.predecessors(technique_id)
            if G.nodes[n].get("node_type") == "threat_actor"]
```

---

## 3. Neo4j Graph Database Queries

Neo4j provides persistent storage and Cypher query language for complex graph traversals that scale beyond in-memory solutions.

```bash
# Import threat intelligence data into Neo4j
cypher-shell <<'CYPHER'
// Create threat actor nodes
LOAD CSV WITH HEADERS FROM 'file:///threat_actors.csv' AS row
MERGE (a:ThreatActor {name: row.name})
SET a.country = row.country, a.motivation = row.motivation;

// Create malware nodes and relationships
LOAD CSV WITH HEADERS FROM 'file:///malware.csv' AS row
MERGE (m:Malware {name: row.name})
SET m.family = row.family, m.first_seen = row.first_seen;

LOAD CSV WITH HEADERS FROM 'file:///actor_malware.csv' AS row
MATCH (a:ThreatActor {name: row.actor})
MATCH (m:Malware {name: row.malware})
MERGE (a)-[:USES {since: row.since}]->(m);

// Query: find attack paths from actor to target infrastructure
MATCH path = (a:ThreatActor)-[:USES]->(m:Malware)-[:EXPLOITS]->(v:Vulnerability)-[:AFFECTS]->(s:System)
WHERE s.org = 'TargetCorp'
RETURN path;

// Query: find shared TTPs between threat groups
MATCH (a1:ThreatActor)-[:EMPLOYS]->(t:Technique)<-[:EMPLOYS]-(a2:ThreatActor)
WHERE a1 <> a2
RETURN a1.name, a2.name, collect(t.id) AS shared_techniques
ORDER BY size(shared_techniques) DESC;
CYPHER
```

---

## 4. Graph Analysis for Threat Intelligence

```python
import networkx as nx

def analyze_threat_graph(G):
    """Compute graph metrics to identify key nodes and patterns."""
    analysis = {}

    # Centrality: most connected entities (high-value targets or prolific actors)
    analysis["degree_centrality"] = sorted(
        nx.degree_centrality(G).items(), key=lambda x: x[1], reverse=True
    )[:10]

    # Betweenness: nodes that bridge different clusters
    analysis["betweenness"] = sorted(
        nx.betweenness_centrality(G).items(), key=lambda x: x[1], reverse=True
    )[:10]

    # Community detection: identify threat actor clusters
    undirected = G.to_undirected()
    communities = nx.community.louvain_communities(undirected)
    analysis["communities"] = [
        {"size": len(c), "members": list(c)[:5]} for c in communities
    ]

    # Path analysis: shortest attack paths
    actors = [n for n, d in G.nodes(data=True) if d.get("node_type") == "threat_actor"]
    targets = [n for n, d in G.nodes(data=True) if d.get("node_type") == "target_sector"]

    attack_paths = []
    for actor in actors[:5]:
        for target in targets[:5]:
            if nx.has_path(G, actor, target):
                path = nx.shortest_path(G, actor, target)
                attack_paths.append({"actor": actor, "target": target, "path": path})
    analysis["attack_paths"] = attack_paths

    return analysis
```

---

## 5. Graph Visualization

```python
import networkx as nx
import matplotlib.pyplot as plt

def visualize_threat_graph(G, output_path="threat_graph.png"):
    """Generate a color-coded visualization of the threat knowledge graph."""
    color_map = {
        "threat_actor": "#e74c3c",
        "malware": "#9b59b6",
        "mitre_ttp": "#3498db",
        "vulnerability": "#e67e22",
        "target_sector": "#2ecc71",
        "ip_address": "#95a5a6",
    }

    node_colors = [
        color_map.get(G.nodes[n].get("node_type", ""), "#bdc3c7") for n in G.nodes()
    ]
    node_sizes = [300 + 200 * G.degree(n) for n in G.nodes()]

    plt.figure(figsize=(16, 12))
    pos = nx.spring_layout(G, k=2, iterations=50, seed=42)

    nx.draw_networkx_nodes(G, pos, node_color=node_colors, node_size=node_sizes, alpha=0.8)
    nx.draw_networkx_edges(G, pos, alpha=0.4, arrows=True, arrowsize=15)
    nx.draw_networkx_labels(G, pos, font_size=7, font_weight="bold")

    edge_labels = nx.get_edge_attributes(G, "relationship")
    nx.draw_networkx_edge_labels(G, pos, edge_labels, font_size=6)

    plt.title("Threat Intelligence Knowledge Graph")
    plt.axis("off")
    plt.tight_layout()
    plt.savefig(output_path, dpi=150, bbox_inches="tight")
    plt.close()
```

---

## 6. Incremental Graph Updates

Knowledge graphs must evolve as new intelligence arrives. Incremental updates avoid full rebuilds while maintaining consistency.

```python
from datetime import datetime

def update_graph_from_feed(G, new_indicators):
    """Incrementally update the knowledge graph with new threat indicators."""
    changes = {"added_nodes": 0, "added_edges": 0, "updated_nodes": 0}

    for indicator in new_indicators:
        node_id = indicator["id"]

        if G.has_node(node_id):
            G.nodes[node_id]["last_seen"] = datetime.utcnow().isoformat()
            G.nodes[node_id]["confidence"] = max(
                G.nodes[node_id].get("confidence", 0), indicator.get("confidence", 50)
            )
            changes["updated_nodes"] += 1
        else:
            G.add_node(node_id, node_type=indicator["type"],
                       first_seen=datetime.utcnow().isoformat(),
                       confidence=indicator.get("confidence", 50))
            changes["added_nodes"] += 1

        for rel in indicator.get("relationships", []):
            if not G.has_edge(node_id, rel["target"]):
                G.add_edge(node_id, rel["target"],
                           relationship=rel["type"],
                           source=indicator.get("source", "unknown"))
                changes["added_edges"] += 1

    return changes
```

---

## Summary

| Component | Tool | Use Case |
|-----------|------|----------|
| Entity extraction | spaCy + regex | Parse unstructured threat reports |
| In-memory graph | NetworkX | Prototyping, small datasets, analysis |
| Persistent graph | Neo4j | Production, large-scale, complex queries |
| Visualization | matplotlib/Gephi | Briefings, pattern identification |
| Analysis | Centrality metrics | Identify key nodes and attack paths |

Build knowledge graphs iteratively: start with entity extraction, establish relationships from structured feeds, then layer in unstructured intelligence as NER models improve.

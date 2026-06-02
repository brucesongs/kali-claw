# Social Network Graph Analysis Guide

## Introduction

Social network graph analysis maps relationships between entities (people, organizations, domains) to reveal hidden connections, influence structures, and community boundaries. In security assessments, graph analysis identifies key influencers, trusted insiders, and organizational choke points that are invisible in raw data. This guide covers building relationship graphs, detecting communities, mapping influence, and performing centrality analysis using both the Maltego graphical tool and the Python networkx library.

Graph analysis transforms flat data points like email addresses, social media handles, and corporate affiliations into a navigable intelligence map. Understanding who connects to whom, and through which intermediaries, enables targeted social engineering, insider threat detection, and organizational reconnaissance.

## Practical Steps

### 1. Building Relationship Graphs with Maltego

Maltego provides a graphical interface for entity relationship discovery:

```bash
# Start Maltego (CE or commercial)
maltego

# Core transform workflow:
# 1. Create a new graph -> Add "Person" entity with target name
# 2. Run "To Email Address" transform to discover associated emails
# 3. Run "To Social Media" transform to find profiles
# 4. Run "To Company" transform to identify employer
# 5. Run "To Domain" transform on company to find web assets
# 6. Run "To DNS Name" to enumerate subdomains
# 7. Run "To Netblock" to find IP ranges

# Key transforms for relationship mapping:
# - Person -> Email Address -> DNS Name
# - Company -> Employee -> Social Media Profile
# - Domain -> WHOIS -> Registrant Email -> Other Domains
# - Phone Number -> Person -> Location -> Company
```

Export the graph for further analysis:

```bash
# Export as GraphML for networkx processing
# File -> Export -> GraphML format
```

### 2. Building Graphs with Python Networkx

```python
import networkx as nx
import matplotlib.pyplot as plt

# Create a directed graph
G = nx.DiGraph()

# Add nodes with attributes
G.add_node("alice", type="person", role="engineer", company="corp")
G.add_node("bob", type="person", role="manager", company="corp")
G.add_node("carol", type="person", role="cto", company="corp")
G.add_node("corp_intranet", type="asset", asset_type="web_app")
G.add_node("corp_db", type="asset", asset_type="database")

# Add edges with relationship labels
G.add_edge("alice", "bob", relation="reports_to", weight=5)
G.add_edge("bob", "carol", relation="reports_to", weight=3)
G.add_edge("carol", "corp_intranet", relation="admin_access", weight=10)
G.add_edge("alice", "corp_db", relation="read_access", weight=4)
G.add_edge("bob", "corp_db", relation="write_access", weight=6)
G.add_edge("alice", "carol", relation="mentor", weight=2)

# Visualize the graph
pos = nx.spring_layout(G, k=2, iterations=50)
node_colors = ["#ff6b6b" if G.nodes[n].get("type") == "person" else "#4ecdc4"
               for n in G.nodes()]
nx.draw(G, pos, with_labels=True, node_color=node_colors,
        node_size=1500, font_size=10, arrows=True)
plt.savefig("social_graph.png", dpi=150, bbox_inches="tight")
```

### 3. Community Detection

Identify tightly connected subgroups within the network:

```python
# Detect communities using the Louvain method
import community as community_louvain

# For undirected community detection
U = G.to_undirected()
communities = community_louvain.best_partition(U)

# Print community assignments
for node, community_id in sorted(communities.items(), key=lambda x: x[1]):
    print(f"  {node} -> Community {community_id}")

# Count communities
num_communities = len(set(communities.values()))
print(f"\nTotal communities detected: {num_communities}")

# Visualize communities
colors = [communities[n] for n in U.nodes()]
nx.draw(U, pos, node_color=colors, cmap=plt.cm.Set3,
        with_labels=True, node_size=1500)
plt.savefig("communities.png", dpi=150, bbox_inches="tight")
```

### 4. Influence Mapping and Centrality Analysis

```python
# Degree centrality: who has the most connections
degree_cent = nx.degree_centrality(G)
print("Degree Centrality (most connected):")
for node, score in sorted(degree_cent.items(), key=lambda x: -x[1])[:5]:
    print(f"  {node}: {score:.3f}")

# Betweenness centrality: who bridges communities
betweenness_cent = nx.betweenness_centrality(G)
print("\nBetweenness Centrality (key brokers):")
for node, score in sorted(betweenness_cent.items(), key=lambda x: -x[1])[:5]:
    print(f"  {node}: {score:.3f}")

# Eigenvector centrality: who is connected to other influential nodes
eigen_cent = nx.eigenvector_centrality(G, max_iter=500)
print("\nEigenvector Centrality (influential connections):")
for node, score in sorted(eigen_cent.items(), key=lambda x: -x[1])[:5]:
    print(f"  {node}: {score:.3f}")

# Closeness centrality: who can reach everyone fastest
closeness_cent = nx.closeness_centrality(G)
print("\nCloseness Centrality (fastest reach):")
for node, score in sorted(closeness_cent.items(), key=lambda x: -x[1])[:5]:
    print(f"  {node}: {score:.3f}")

# Find shortest attack path from external node to critical asset
path = nx.shortest_path(G, source="alice", target="corp_intranet")
print(f"\nShortest path from alice to corp_intranet: {' -> '.join(path)}")
```

### 5. Automated Graph Building from OSINT Data

```python
import json
import networkx as nx

# Load collected OSINT data
with open("osint_data.json") as f:
    data = json.load(f)

G = nx.DiGraph()

for entity in data["entities"]:
    G.add_node(entity["id"], **entity["attributes"])

for link in data["relationships"]:
    G.add_edge(link["source"], link["target"],
               relation=link["type"], weight=link.get("strength", 1))

# Export for visualization in Gephi
nx.write_graphml(G, "osint_graph.graphml")

# Find all paths to a high-value target (max depth 4)
target = "cto@corp.com"
for source in G.nodes():
    if source != target:
        try:
            path = nx.shortest_path(G, source=source, target=target)
            if len(path) <= 4:
                print(f"Path: {' -> '.join(path)} (length: {len(path)})")
        except nx.NetworkXNoPath:
            pass
```

## References

- NetworkX Documentation: https://networkx.org/documentation/stable/
- Maltego CE: https://www.maltego.com/ce-registration/
- Gephi Graph Visualization: https://gephi.org/
- Python Community Detection: https://github.com/taynaud/python-louvain
- Social Network Analysis for Security: https://www.sans.org/white-papers/

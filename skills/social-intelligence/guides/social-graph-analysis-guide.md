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

### 6. Graph Theory Fundamentals for Social Analysis

Understanding core graph theory concepts is essential for effective social network analysis in security contexts. A graph (or network) consists of nodes (entities) and edges (relationships). In social intelligence, nodes represent people, organizations, domains, email addresses, or IP addresses, while edges represent communication, collaboration, employment, ownership, or any other meaningful relationship.

Key graph types relevant to OSINT:

- **Undirected graphs** model symmetric relationships: two people who appear in the same photo, mutual followers on social media, or co-authors on a paper. The relationship is bidirectional.
- **Directed graphs** model asymmetric relationships: person A reports to person B, user A follows user B (who does not follow back), or email was sent from A to B. Direction matters for influence flow analysis.
- **Weighted graphs** assign importance to edges: frequent communication gets a higher weight than a single interaction, or a direct management relationship gets a higher weight than a casual acquaintance.
- **Bipartite graphs** connect two distinct entity types: people and organizations, or users and the subreddits they post in. These are useful for affiliation analysis.

Graph density measures how interconnected a network is. A dense graph (density near 1.0) means most entities know each other directly, suggesting a tight-knit group. A sparse graph (density near 0.0) indicates loose connections with many potential intermediaries. In security assessments, dense subgraphs often indicate organizational units or trusted insider groups, while sparse bridges between dense clusters represent security boundaries or information flow choke points.

```python
import networkx as nx

# Calculate graph density
density = nx.density(G)
print(f"Graph density: {density:.4f}")

# Interpret density
if density > 0.7:
    interpretation = "Dense network - tight-knit community, fast information spread"
elif density > 0.3:
    interpretation = "Moderate density - mixed structure with some clusters"
else:
    interpretation = "Sparse network - hierarchical or decentralized, slow diffusion"

# Graph connectivity analysis
if nx.is_strongly_connected(G):
    print("Graph is strongly connected (all nodes reachable from all others)")
elif nx.is_weakly_connected(G):
    components = list(nx.weakly_connected_components(G))
    print(f"Graph has {len(components)} disconnected components")
    for i, component in enumerate(components):
        print(f"  Component {i}: {len(component)} nodes")

# Diameter: longest shortest path (indicates communication latency)
try:
    diameter = nx.diameter(G.to_undirected())
    print(f"Network diameter: {diameter} (max hops between any two nodes)")
except nx.NetworkXError:
    print("Graph is not connected - diameter is infinite")
```

### 7. Centrality Metrics and Their Intelligence Value

Each centrality metric reveals a different aspect of influence and access within a network. Understanding what each metric measures helps prioritize targets in security assessments.

**Degree centrality** counts the raw number of connections. A person with high degree centrality knows many people and can serve as an initial contact point for social engineering. However, quantity does not guarantee quality of access.

**Betweenness centrality** measures how often a node lies on the shortest path between other nodes. High-betweenness individuals are information brokers or gatekeepers. In organizational contexts, these are often executive assistants, IT administrators, or middle managers who control information flow between departments. Removing or compromising a high-betweenness node can disrupt communication between entire clusters.

**Eigenvector centrality** scores nodes based on the centrality of their neighbors. Being connected to other well-connected people amplifies influence. High eigenvector centrality identifies people with access to powerful networks, even if their direct connection count is modest. A junior employee who plays on the company sports team with executives may have higher eigenvector centrality than a senior engineer who only interacts with their immediate team.

**Closeness centrality** measures the average shortest path distance to all other nodes. High closeness means the person can reach (or influence) the entire network quickly. In attack path analysis, high-closeness nodes are optimal starting points because they minimize the number of hops needed to reach any target.

**PageRank** (the algorithm behind Google Search) models a random surfer walking through the network. It accounts for both connection quantity and quality, with a damping factor that simulates the probability of following a link versus jumping to a random node. PageRank is particularly useful for identifying influential accounts in follower/following networks where the graph is large and sparse.

```python
#!/usr/bin/env python3
"""Comprehensive centrality analysis with intelligence interpretation."""
import networkx as nx
import json

def full_centrality_analysis(G, top_n=10):
    """Calculate all centrality metrics and rank nodes."""
    results = {}

    # Use undirected version for some metrics
    U = G.to_undirected() if G.is_directed() else G

    metrics = {
        "degree": nx.degree_centrality(G),
        "betweenness": nx.betweenness_centrality(G, normalized=True),
        "eigenvector": nx.eigenvector_centrality(U, max_iter=1000),
        "closeness": nx.closeness_centrality(G),
        "pagerank": nx.pagerank(G, alpha=0.85)
    }

    # Build composite ranking
    node_scores = {}
    for node in G.nodes():
        node_scores[node] = {
            metric: scores.get(node, 0) for metric, scores in metrics.items()
        }
        # Composite score (weighted average)
        weights = {"degree": 0.15, "betweenness": 0.25, "eigenvector": 0.25,
                    "closeness": 0.15, "pagerank": 0.20}
        composite = sum(node_scores[node][m] * w for m, w in weights.items())
        node_scores[node]["composite"] = round(composite, 4)

    # Sort by composite score
    ranked = sorted(node_scores.items(), key=lambda x: -x[1]["composite"])
    return ranked[:top_n], metrics

def interpret_centrality(node, scores):
    """Provide intelligence interpretation of a node's centrality profile."""
    interpretations = []

    if scores["betweenness"] > 0.3:
        interpretations.append(
            "INFORMATION BROKER: This node controls information flow between clusters. "
            "High-value target for understanding organizational communication paths."
        )
    if scores["eigenvector"] > 0.3:
        interpretations.append(
            "CONNECTED INFLUENCER: Connected to other influential nodes. "
            "Access to this node may provide indirect access to key decision-makers."
        )
    if scores["degree"] > 0.5:
        interpretations.append(
            "HIGH VISIBILITY: Many direct connections. "
            "Useful as a starting point for social engineering due to broad recognition."
        )
    if scores["closeness"] > 0.5:
        interpretations.append(
            "RAPID REACH: Can reach most nodes in few hops. "
            "Optimal position for information dissemination or lateral movement."
        )
    if scores["pagerank"] > 0.3:
        interpretations.append(
            "AUTHORITY: High PageRank indicates trust and authority in the network. "
            "Impersonating this node would carry significant credibility."
        )

    return interpretations
```

### 8. Community Detection Algorithms

Community detection partitions a network into groups of densely interconnected nodes. Different algorithms suit different network structures and intelligence objectives.

**Louvain method** optimizes modularity through hierarchical aggregation. It is fast and works well on large networks. Best for finding natural organizational groupings.

**Label propagation** assigns each node the label most common among its neighbors, iterating until stable. Extremely fast but non-deterministic. Useful for initial exploration.

**Greedy modularity** sequentially merges communities to maximize modularity gain. Produces fewer, larger communities. Good for high-level organizational mapping.

**k-clique percolation** finds overlapping communities by identifying sets of nodes that form complete subgraphs (cliques) of size k. Unlike other methods, nodes can belong to multiple communities, which is realistic for people who bridge organizational boundaries.

**Girvan-Newman** iteratively removes the highest-betweenness edges to split communities. Computationally expensive but produces a hierarchical dendrogram showing community structure at every granularity.

```python
#!/usr/bin/env python3
"""Multi-algorithm community detection comparison."""
import networkx as nx
import community as community_louvain
from collections import defaultdict

def detect_communities_multi(G):
    """Run multiple community detection algorithms and compare results."""
    U = G.to_undirected() if G.is_directed() else G

    results = {}

    # Method 1: Louvain (fast, modularity-optimized)
    louvain_partition = community_louvain.best_partition(U)
    louvain_communities = defaultdict(list)
    for node, comm_id in louvain_partition.items():
        louvain_communities[comm_id].append(node)
    results["louvain"] = {
        "num_communities": len(louvain_communities),
        "communities": dict(louvain_communities),
        "modularity": community_louvain.modularity(louvain_partition, U)
    }

    # Method 2: Label propagation (fast, non-deterministic)
    label_partition = nx.algorithms.community.label_propagation_communities(U)
    label_communities = {i: list(comm) for i, comm in enumerate(label_partition)}
    results["label_propagation"] = {
        "num_communities": len(label_communities),
        "communities": label_communities
    }

    # Method 3: Greedy modularity
    greedy_partition = nx.algorithms.community.greedy_modularity_communities(U)
    greedy_communities = {i: list(comm) for i, comm in enumerate(greedy_partition)}
    results["greedy_modularity"] = {
        "num_communities": len(greedy_communities),
        "communities": greedy_communities
    }

    # Method 4: Girvan-Newman (top-level split only, due to cost)
    try:
        gn_top = next(nx.algorithms.community.girvan_newman(U))
        gn_communities = {i: list(comm) for i, comm in enumerate(gn_top)}
        results["girvan_newman"] = {
            "num_communities": len(gn_communities),
            "communities": gn_communities
        }
    except StopIteration:
        results["girvan_newman"] = {"num_communities": 1, "communities": {0: list(U.nodes())}}

    # Cross-reference: nodes that change community across methods
    node_assignments = defaultdict(dict)
    for method, data in results.items():
        for comm_id, members in data.get("communities", {}).items():
            for node in members:
                node_assignments[node][method] = comm_id

    unstable_nodes = []
    for node, assignments in node_assignments.items():
        unique_comms = len(set(assignments.values()))
        if unique_comms > 1:
            unstable_nodes.append(node)

    results["meta"] = {
        "unstable_nodes": unstable_nodes,
        "unstable_count": len(unstable_nodes),
        "interpretation": (
            f"{len(unstable_nodes)} nodes change community across methods. "
            "These are likely boundary-spanners who bridge multiple groups."
        )
    }

    return results
```

### 9. Visualization Tools and Techniques

Effective visualization transforms abstract graph data into actionable intelligence. Different visualization approaches serve different analytical goals.

**Gephi** is the primary tool for interactive graph exploration. It supports force-directed layouts that naturally cluster related nodes, filtering by attribute or metric, and real-time manipulation of large graphs (100K+ nodes). Import GraphML files exported from networkx.

**Pyvis** generates interactive HTML network visualizations viewable in any browser. It is ideal for sharing analysis results with team members who do not have specialized graph tools installed.

**Graphistry** provides GPU-accelerated visualization for very large graphs (millions of edges) and is well-suited for enterprise-scale social network analysis.

**Matplotlib + networkx** is the simplest approach for quick static visualizations embedded in reports.

```python
#!/usr/bin/env python3
"""Graph visualization techniques for social network analysis."""
import networkx as nx
import matplotlib.pyplot as plt
import json

def visualize_with_pyvis(G, output_file="social_graph.html", height="800px"):
    """Create an interactive HTML visualization using Pyvis."""
    from pyvis.network import Network

    net = Network(height=height, width="100%", directed=G.is_directed())
    net.barnes_hut()

    for node in G.nodes():
        attrs = G.nodes[node]
        label = attrs.get("label", str(node))
        title = f"{label}\n" + "\n".join(f"{k}: {v}" for k, v in attrs.items() if k != "label")
        net.add_node(node, label=label, title=title)

    for source, target in G.edges():
        edge_attrs = G.edges[source, target]
        weight = edge_attrs.get("weight", 1)
        label = edge_attrs.get("relation", "")
        net.add_edge(source, target, value=weight, title=label)

    net.show(output_file)
    print(f"Interactive graph saved to {output_file}")

def visualize_highlighted_paths(G, paths, output_file="attack_paths.png"):
    """Visualize a graph with specific paths highlighted."""
    fig, ax = plt.subplots(1, 1, figsize=(16, 12))
    pos = nx.spring_layout(G, k=2.5, iterations=80)

    # Draw base graph
    nx.draw_networkx_nodes(G, pos, node_color="#cccccc", node_size=500, ax=ax)
    nx.draw_networkx_labels(G, pos, font_size=8, ax=ax)

    # Draw all edges lightly
    nx.draw_networkx_edges(G, pos, alpha=0.15, arrows=True, ax=ax)

    # Highlight each path with a different color
    colors = ["#ff0000", "#00aa00", "#0000ff", "#ff8800", "#8800ff"]
    for i, path in enumerate(paths):
        color = colors[i % len(colors)]
        path_edges = list(zip(path[:-1], path[1:]))
        nx.draw_networkx_edges(G, pos, edgelist=path_edges, edge_color=color,
                               width=3, arrows=True, ax=ax)
        path_nodes = set(path)
        nx.draw_networkx_nodes(G, pos, nodelist=path, node_color=color,
                               node_size=700, ax=ax)

    plt.legend([plt.Line2D([0], [0], color=c, linewidth=3) for c in colors[:len(paths)]],
               [f"Path {i+1}: {' -> '.join(p)}" for i, p in enumerate(paths)],
               loc="upper left", fontsize=8)
    plt.savefig(output_file, dpi=150, bbox_inches="tight")
    print(f"Attack path visualization saved to {output_file}")
```

### 10. Automated Graph Construction from OSINT Data

Build graphs automatically from disparate OSINT data sources, normalizing entity types and relationship labels into a unified intelligence graph.

```python
#!/usr/bin/env python3
"""Automated graph construction from multiple OSINT data sources."""
import json
import networkx as nx
from pathlib import Path
from collections import defaultdict

class OSINTGraphBuilder:
    """Construct intelligence graphs from collected OSINT data."""

    def __init__(self):
        self.G = nx.DiGraph()
        self.entity_registry = {}  # Deduplicate entities

    def _add_entity(self, entity_id, entity_type, attributes=None):
        """Add an entity to the graph, merging attributes if it already exists."""
        if entity_id not in self.entity_registry:
            self.entity_registry[entity_id] = {
                "type": entity_type,
                "sources": [],
                **(attributes or {})
            }
            self.G.add_node(entity_id, **self.entity_registry[entity_id])
        elif attributes:
            # Merge new attributes without overwriting existing
            for key, value in attributes.items():
                if key not in self.entity_registry[entity_id]:
                    self.entity_registry[entity_id][key] = value
            self.G.nodes[entity_id].update(self.entity_registry[entity_id])
        return entity_id

    def ingest_linkedin_data(self, linkedin_file):
        """Ingest LinkedIn profile data into the graph."""
        with open(linkedin_file) as f:
            data = json.load(f)

        for profile in data.get("profiles", []):
            person_id = self._add_entity(
                profile["name"], "person",
                {"role": profile.get("title", ""), "location": profile.get("location", "")}
            )
            if profile.get("company"):
                company_id = self._add_entity(profile["company"], "organization")
                self.G.add_edge(person_id, company_id, relation="employed_at",
                                weight=5, source="linkedin")

            # Map colleague connections
            for colleague in profile.get("colleagues", []):
                coll_id = self._add_entity(colleague["name"], "person",
                                           {"role": colleague.get("title", "")})
                self.G.add_edge(person_id, coll_id, relation="colleague",
                                weight=3, source="linkedin")

    def ingest_github_data(self, github_file):
        """Ingest GitHub activity data into the graph."""
        with open(github_file) as f:
            data = json.load(f)

        for repo in data.get("repositories", []):
            repo_id = self._add_entity(
                repo["full_name"], "repository",
                {"language": repo.get("language", ""), "stars": repo.get("stargazers_count", 0)}
            )
            for contributor in repo.get("contributors", []):
                user_id = self._add_entity(
                    contributor["login"], "person",
                    {"github_user": contributor["login"],
                     "contributions": contributor.get("contributions", 0)}
                )
                self.G.add_edge(user_id, repo_id, relation="contributor_to",
                                weight=min(contributor.get("contributions", 1) // 10 + 1, 10),
                                source="github")

    def ingest_domain_data(self, domain_file):
        """Ingest domain/DNS WHOIS data into the graph."""
        with open(domain_file) as f:
            data = json.load(f)

        for domain in data.get("domains", []):
            domain_id = self._add_entity(
                domain["name"], "domain",
                {"registrar": domain.get("registrar", ""),
                 "created": domain.get("created_date", "")}
            )
            if domain.get("registrant_email"):
                email_id = self._add_entity(domain["registrant_email"], "email")
                self.G.add_edge(email_id, domain_id, relation="registered",
                                weight=8, source="whois")
            for subdomain in domain.get("subdomains", []):
                sub_id = self._add_entity(subdomain, "subdomain",
                                          {"parent_domain": domain["name"]})
                self.G.add_edge(domain_id, sub_id, relation="has_subdomain",
                                weight=2, source="dns")

    def build_and_export(self, output_file="osint_intelligence_graph.graphml"):
        """Build final graph and export for visualization."""
        stats = {
            "total_nodes": self.G.number_of_nodes(),
            "total_edges": self.G.number_of_edges(),
            "node_types": defaultdict(int),
            "edge_types": defaultdict(int)
        }
        for _, attrs in self.G.nodes(data=True):
            stats["node_types"][attrs.get("type", "unknown")] += 1
        for _, _, attrs in self.G.edges(data=True):
            stats["edge_types"][attrs.get("relation", "unknown")] += 1

        print(f"Graph built: {stats['total_nodes']} nodes, {stats['total_edges']} edges")
        print(f"Node types: {dict(stats['node_types'])}")
        print(f"Edge types: {dict(stats['edge_types'])}")

        nx.write_graphml(self.G, output_file)
        return self.G, stats
```

### 11. Identifying Hidden Connections

Discover non-obvious relationships by analyzing indirect paths, shared attributes, and structural patterns that suggest hidden connections between entities.

```python
#!/usr/bin/env python3
"""Hidden connection detection through structural analysis."""
import networkx as nx
from collections import defaultdict

class HiddenConnectionDetector:
    """Find non-obvious relationships in social graphs."""

    def __init__(self, G):
        self.G = G
        self.U = G.to_undirected() if G.is_directed() else G

    def find_structural_holes(self):
        """Identify structural holes - gaps between clusters that brokers bridge."""
        betweenness = nx.betweenness_centrality(self.U, normalized=True)
        # Nodes with high betweenness relative to their degree are brokers
        degree = dict(self.U.degree())
        brokers = []
        for node in self.U.nodes():
            if degree[node] > 0:
                broker_ratio = betweenness[node] / degree[node]
                brokers.append({
                    "node": node,
                    "betweenness": betweenness[node],
                    "degree": degree[node],
                    "broker_ratio": round(broker_ratio, 4)
                })
        brokers.sort(key=lambda b: -b["broker_ratio"])
        return brokers

    def find_common_neighbors(self, node_a, node_b):
        """Find entities connected to both targets (potential intermediaries)."""
        neighbors_a = set(self.U.neighbors(node_a))
        neighbors_b = set(self.U.neighbors(node_b))
        common = neighbors_a & neighbors_b
        return {
            "node_a": node_a,
            "node_b": node_b,
            "common_neighbors": list(common),
            "common_count": len(common),
            "jaccard_similarity": len(common) / len(neighbors_a | neighbors_b) if (neighbors_a | neighbors_b) else 0
        }

    def find_hidden_paths(self, source, target, max_length=4):
        """Find all paths up to max_length between two nodes, including indirect routes."""
        all_paths = []
        try:
            for path in nx.all_simple_paths(self.U, source, target, cutoff=max_length):
                all_paths.append({
                    "path": path,
                    "length": len(path) - 1,
                    "nodes": path
                })
        except nx.NetworkXNoPath:
            pass

        all_paths.sort(key=lambda p: p["length"])
        return all_paths

    def find_triadic_closures(self):
        """Find open triads (A-B, B-C but no A-C) that may represent hidden connections."""
        open_triads = []
        for node in self.U.nodes():
            neighbors = list(self.U.neighbors(node))
            for i in range(len(neighbors)):
                for j in range(i + 1, len(neighbors)):
                    a, b = neighbors[i], neighbors[j]
                    if not self.U.has_edge(a, b):
                        open_triads.append({
                            "broker": node,
                            "unconnected_pair": (a, b),
                            "broker_degree": len(neighbors),
                            "likelihood": "high" if len(neighbors) < 10 else "low"
                        })
        return open_triads

    def find_attribute_overlap(self, attribute="company"):
        """Find nodes that share an attribute value (potential hidden connection)."""
        groups = defaultdict(list)
        for node, attrs in self.G.nodes(data=True):
            value = attrs.get(attribute)
            if value:
                groups[value].append(node)

        hidden_connections = []
        for value, members in groups.items():
            if len(members) < 2:
                continue
            # Check which pairs are NOT directly connected
            for i in range(len(members)):
                for j in range(i + 1, len(members)):
                    if not self.U.has_edge(members[i], members[j]):
                        hidden_connections.append({
                            "shared_attribute": attribute,
                            "attribute_value": value,
                            "node_a": members[i],
                            "node_b": members[j],
                            "connection_type": "inferred_shared_" + attribute
                        })
        return hidden_connections
```

## References

- NetworkX Documentation: https://networkx.org/documentation/stable/
- Maltego CE: https://www.maltego.com/ce-registration/
- Gephi Graph Visualization: https://gephi.org/
- Python Community Detection: https://github.com/taynaud/python-louvain
- Social Network Analysis for Security: https://www.sans.org/white-papers/
- Pyvis Interactive Visualization: https://pyvis.readthedocs.io/
- Graphistry GPU Visualization: https://graphistry.com/
- Graph Theory and Complex Networks (Easley/Kleinberg): https://www.cs.cornell.edu/home/kleinber/networks-book/
- Community Detection Algorithms Survey: https://arxiv.org/abs/0906.0612

## Hands-on Exercises

Practice these techniques against public data sources and authorized targets. Always respect privacy laws and terms of service.

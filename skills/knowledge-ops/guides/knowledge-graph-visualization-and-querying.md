# Knowledge Graph Visualization and Querying Guide

Techniques for navigating, visualizing, and querying the knowledge graph to surface insights hidden in the data.

---

## Why Visualization Matters

A knowledge base with 100+ units becomes impossible to navigate linearly. Visualization reveals:
- Hidden attack chains
- Central high-value entities
- Orphaned knowledge units (not linked to anything)
- Confidence hotspots (areas of high/low certainty)

---

## Text-Based Graph Representation

### DOT Format (Graphviz)

Generate a `.dot` file from knowledge units:

```bash
#!/bin/bash
# generate_graph.sh — Create a DOT file from memory/

echo "digraph KnowledgeGraph {"
echo "  rankdir=LR;"
echo "  node [shape=box];"
echo ""

# Extract all KU IDs and create nodes
grep -rh "^id: KU-" memory/ | awk '{print $2}' | sort -u | while read ku_id; do
  # Get summary for label
  summary=$(grep -rn "id: $ku_id" memory/ -A3 | grep "^## Summary" -A1 | tail -1 | sed 's/^[ \t]*//')
  type=$(grep -rn "id: $ku_id" memory/ -A2 | grep "^type:" | awk '{print $2}')
  confidence=$(grep -rn "id: $ku_id" memory/ -A5 | grep "^confidence:" | awk '{print $2}')
  
  # Color by type
  case $type in
    entity) color="lightblue" ;;
    finding) color="orange" ;;
    pattern) color="purple" ;;
    hypothesis) color="yellow" ;;
    intelligence) color="green" ;;
    *) color="gray" ;;
  esac
  
  echo "  \"$ku_id\" [label=\"$ku_id\n$summary\", fillcolor=$color, style=filled];"
done

echo ""

# Extract all links and create edges
grep -rh "^linked:" memory/ | grep -v "\[\]" | while read line; do
  source_file=$(grep -l "$line" memory/)
  source_ku=$(grep "^id: KU-" "$source_file" | awk '{print $2}')
  
  # Extract linked KUs
  linked_kus=$(echo $line | grep -oP "KU-\d{4}-\d{2}-\d{3}" | tr '\n' ' ')
  
  for target_ku in $linked_kus; do
    echo "  \"$source_ku\" -> \"$target_ku\";"
  done
done

echo "}"
```

**Render**:
```bash
./generate_graph.sh > knowledge_graph.dot
dot -Tpng knowledge_graph.dot -o knowledge_graph.png
# OR
dot -Tsvg knowledge_graph.dot -o knowledge_graph.svg
```

### Mermaid Format (Markdown-Native)

```bash
#!/bin/bash
# generate_mermaid.sh — Create Mermaid diagram

echo "```mermaid"
echo "graph TD"

# Nodes
grep -rh "^id: KU-" memory/ | awk '{print $2}' | sort -u | while read ku_id; do
  summary=$(grep -rn "id: $ku_id" memory/ -A3 | grep "^## Summary" -A1 | tail -1 | xargs)
  echo "  $ku_id[$ku_id: $summary]"
done

# Edges
grep -rh "^linked:" memory/ | grep -v "\[\]" | while read line; do
  source_file=$(grep -l "$line" memory/)
  source_ku=$(grep "^id: KU-" "$source_file" | awk '{print $2}')
  linked_kus=$(echo $line | grep -oP "KU-\d{4}-\d{2}-\d{3}")
  
  for target_ku in $linked_kus; do
    echo "  $source_ku --> $target_ku"
  done
done

echo "\`\`\`"
```

**Usage**:
```bash
./generate_mermaid.sh > knowledge_graph.md
# View in any Markdown renderer that supports Mermaid
```

---

## Query Patterns

### Query 1: Find All Paths Between Two KUs

Use case: "Is there an attack chain from KU-001 (entry point) to KU-020 (target system)?"

```bash
#!/bin/bash
# find_path.sh — BFS to find path between two KUs

start_ku=$1
end_ku=$2

# Simplified BFS (depth-limited to 5 hops)
function find_path_recursive() {
  local current=$1
  local target=$2
  local depth=$3
  local path=$4
  
  if [ "$current" == "$target" ]; then
    echo "PATH FOUND: $path -> $target"
    return 0
  fi
  
  if [ $depth -le 0 ]; then
    return 1
  fi
  
  # Find all linked KUs from current
  linked=$(grep -rn "id: $current" memory/ -A10 | grep "^linked:" | \
    grep -oP "KU-\d{4}-\d{2}-\d{3}" | sort -u)
  
  for next_ku in $linked; do
    # Avoid cycles
    if [[ ! "$path" =~ $next_ku ]]; then
      find_path_recursive "$next_ku" "$target" $((depth - 1)) "$path -> $next_ku"
    fi
  done
}

find_path_recursive "$start_ku" "$end_ku" 5 "$start_ku"
```

### Query 2: Find Central Entities (Most Connected)

```bash
# Find KUs with most incoming + outgoing links
echo "=== Most Connected Knowledge Units ==="
grep -rh "^linked:\|^id: KU-" memory/ | \
  grep -oP "KU-\d{4}-\d{2}-\d{3}" | sort | uniq -c | sort -rn | head -20
# Output: [count] [KU-ID]
```

### Query 3: Find Orphaned Knowledge Units

```bash
# KUs with no links (neither linking nor being linked to)
echo "=== Orphaned Knowledge Units ==="
all_kus=$(grep -rh "^id: KU-" memory/ | awk '{print $2}' | sort -u)
linked_kus=$(grep -rh "^linked:" memory/ | grep -oP "KU-\d{4}-\d{2}-\d{3}" | sort -u)

for ku in $all_kus; do
  if ! echo "$linked_kus" | grep -q "$ku"; then
    # Check if this KU links to others
    has_links=$(grep -rn "id: $ku" memory/ -A10 | grep "^linked:" | grep -v "\[\]")
    if [ -z "$has_links" ]; then
      echo "$ku (orphaned)"
    fi
  fi
done
```

### Query 4: Confidence Heatmap

```bash
# Show distribution of confidence scores
echo "=== Confidence Distribution ==="
grep -rh "^confidence:" memory/ | awk '{print $2}' | sort -n | uniq -c
# Output:
#   3 40
#   5 60
#   8 75
#  12 85
#   4 95
```

### Query 5: Tag Co-occurrence Analysis

```bash
# Which tags frequently appear together?
echo "=== Tag Co-occurrence ==="
grep -rh "^tags:" memory/ | grep -oP "\[.*\]" | tr ',' '\n' | \
  sed 's/\[//g; s/\]//g; s/ //g' | sort | uniq -c | sort -rn | head -20
# Reveals common tag combinations (e.g., jwt + auth, sql-injection + high-risk)
```

---

## Subgraph Extraction

### Extract Target-Specific Subgraph

```bash
#!/bin/bash
# extract_target_subgraph.sh — Extract all KUs for one target

TARGET=$1
echo "digraph ${TARGET}_subgraph {"
echo "  rankdir=LR;"

# Find all KUs for this target
target_kus=$(grep -rn "^target: $TARGET" memory/ -B5 | grep "^id: KU-" | awk '{print $2}' | sort -u)

# Create nodes
for ku in $target_kus; do
  summary=$(grep -rn "id: $ku" memory/ -A3 | grep "^## Summary" -A1 | tail -1 | xargs)
  echo "  \"$ku\" [label=\"$ku\n$summary\"];"
done

# Create edges (only within this subgraph)
for ku in $target_kus; do
  linked=$(grep -rn "id: $ku" memory/ -A10 | grep "^linked:" | grep -oP "KU-\d{4}-\d{2}-\d{3}")
  for link in $linked; do
    # Only include edge if target KU is also in this subgraph
    if echo "$target_kus" | grep -q "$link"; then
      echo "  \"$ku\" -> \"$link\";"
    fi
  done
done

echo "}"
```

### Extract Type-Specific Subgraph

```bash
# Only show findings + their linked entities
./extract_type_subgraph.sh finding entity > findings_subgraph.dot
```

---

## Interactive Query Interface (Conceptual)

For advanced usage, build a simple CLI query tool:

```bash
#!/bin/bash
# kbquery — Knowledge Base Query Tool

case $1 in
  find)
    # kbquery find KU-2026-05-001
    ku_id=$2
    grep -rn "id: $ku_id" memory/ -A20
    ;;
  
  search)
    # kbquery search "SQL injection"
    query=$2
    grep -ri "$query" memory/ | head -20
    ;;
  
  path)
    # kbquery path KU-001 KU-020
    ./find_path.sh $2 $3
    ;;
  
  stats)
    # kbquery stats target-org
    target=$2
    echo "Total KUs: $(grep -rn "^target: $target" memory/ | wc -l)"
    echo "Findings: $(grep -rn "^type: finding" memory/*$target* | wc -l)"
    echo "Entities: $(grep -rn "^type: entity" memory/*$target* | wc -l)"
    echo "Avg Confidence: $(grep -rh "^confidence:" memory/*$target* | awk '{sum+=$2; n++} END {print sum/n}')"
    ;;
  
  graph)
    # kbquery graph target-org
    ./extract_target_subgraph.sh $2 | dot -Tpng -o ${2}_graph.png
    echo "Graph saved to ${2}_graph.png"
    ;;
  
  *)
    echo "Usage: kbquery [find|search|path|stats|graph] [args]"
    ;;
esac
```

---

## Visualization Best Practices

### Color Coding

- **Entities**: Light blue
- **Findings**: Orange (critical), Yellow (high), Gray (medium/low)
- **Patterns**: Purple
- **Hypotheses**: Dashed border (unconfirmed)
- **Intelligence**: Green (high-level synthesis)

### Node Shape

- **Entities**: Ellipse
- **Findings**: Box
- **Patterns**: Diamond
- **Relationships**: Arrow with label

### Edge Weight

- Thick lines: High-confidence relationships
- Thin lines: Low-confidence or inferred relationships
- Dashed lines: Hypothetical connections

---

## Export Formats

### JSON Export (for external tools)

```bash
#!/bin/bash
# export_json.sh — Export knowledge graph as JSON

echo "{"
echo "  \"nodes\": ["

first=true
grep -rh "^id: KU-" memory/ | awk '{print $2}' | sort -u | while read ku_id; do
  if [ "$first" = false ]; then echo ","; fi
  first=false
  
  type=$(grep -rn "id: $ku_id" memory/ -A2 | grep "^type:" | awk '{print $2}')
  confidence=$(grep -rn "id: $ku_id" memory/ -A5 | grep "^confidence:" | awk '{print $2}')
  summary=$(grep -rn "id: $ku_id" memory/ -A3 | grep "^## Summary" -A1 | tail -1 | xargs)
  
  echo "    {"
  echo "      \"id\": \"$ku_id\","
  echo "      \"type\": \"$type\","
  echo "      \"confidence\": $confidence,"
  echo "      \"summary\": \"$summary\""
  echo -n "    }"
done

echo ""
echo "  ],"
echo "  \"edges\": ["

first=true
grep -rh "^linked:" memory/ | grep -v "\[\]" | while read line; do
  source_file=$(grep -l "$line" memory/)
  source_ku=$(grep "^id: KU-" "$source_file" | awk '{print $2}')
  linked_kus=$(echo $line | grep -oP "KU-\d{4}-\d{2}-\d{3}")
  
  for target_ku in $linked_kus; do
    if [ "$first" = false ]; then echo ","; fi
    first=false
    
    echo "    {"
    echo "      \"source\": \"$source_ku\","
    echo "      \"target\": \"$target_ku\""
    echo -n "    }"
  done
done

echo ""
echo "  ]"
echo "}"
```

### CSV Export (for spreadsheet analysis)

```bash
# Export all findings as CSV
echo "KU_ID,Type,Target,Confidence,Tags,Summary" > findings.csv
grep -rn "^type: finding" memory/ | awk -F: '{print $1}' | while read file; do
  ku_id=$(grep "^id: KU-" "$file" | awk '{print $2}')
  type="finding"
  target=$(grep "^target:" "$file" | awk '{print $2}')
  confidence=$(grep "^confidence:" "$file" | awk '{print $2}')
  tags=$(grep "^tags:" "$file" | sed 's/tags: //')
  summary=$(grep "^## Summary" "$file" -A1 | tail -1 | xargs)
  
  echo "$ku_id,$type,$target,$confidence,\"$tags\",\"$summary\"" >> findings.csv
done
```

---

## Query Performance Tips

For large knowledge bases (500+ KUs):

1. **Index by tag**: Create tag-based index files
   ```bash
   mkdir -p memory/.index/
   for tag in sql-injection jwt xss; do
     grep -rl "tags:.*$tag" memory/ > memory/.index/$tag.txt
   done
   ```

2. **Cache frequently-used queries**: Store query results in temp files

3. **Use `--max-count=N` with grep**: Limit results for faster queries

4. **Parallelize searches**:
   ```bash
   find memory/ -name "*.md" | xargs -P 4 -I {} grep -l "pattern" {}
   ```

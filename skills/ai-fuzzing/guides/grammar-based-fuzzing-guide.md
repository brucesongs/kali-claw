# Grammar-Based Fuzzing Guide

> Companion to `skills/ai-fuzzing/SKILL.md`. This guide covers protocol-aware fuzzing using grammar specifications, structured input mutation with Nautilus and Gramatron, and techniques for generating valid-yet-malicious inputs that pass parsers.

---

## 1. Grammar-Based Fuzzing Concepts

Traditional mutation-based fuzzers (AFL++, libFuzzer) struggle with highly structured inputs like programming languages, network protocols, and file formats. Grammar-based fuzzing solves this by generating inputs that conform to a grammar specification while still exploring edge cases.

**When to use grammar-based fuzzing:**
- Target expects structured input (JSON, XML, SQL, HTML, protocol messages)
- Mutation fuzzing gets stuck at parser validation
- Coverage plateaus because random mutations produce syntactically invalid inputs
- Protocol state machines require valid message sequences

---

## 2. Nautilus Setup and Grammar Definition

Nautilus integrates grammar-aware generation with AFL++'s coverage feedback:

```bash
# Clone and build Nautilus
git clone https://github.com/nautilus-fuzz/nautilus.git
cd nautilus
cargo build --release

# Directory structure for a fuzzing campaign
mkdir -p campaign/{grammars,seeds,output}
```

Define grammars in Nautilus's JSON-based format:

```json
{
  "rules": {
    "START": ["{expr}"],
    "expr": [
      "{expr} {binop} {expr}",
      "{unop} {expr}",
      "({expr})",
      "{literal}"
    ],
    "binop": ["+", "-", "*", "/", "**", "<<", ">>", "&", "|", "^"],
    "unop": ["-", "~", "!"],
    "literal": ["{int}", "{float}", "{string}"],
    "int": ["0", "1", "-1", "2147483647", "-2147483648", "0x{hex}{hex}{hex}{hex}"],
    "hex": ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"],
    "float": ["0.0", "1.0", "-1.0", "inf", "-inf", "nan", "1e308", "5e-324"],
    "string": ["\"\"", "\"hello\"", "\"\\x00\\x00\"", "\"A\" * 4096"]
  }
}
```

```bash
# Run Nautilus with the grammar
./target/release/nautilus \
  -g campaign/grammars/expr.json \
  -o campaign/output \
  -i campaign/seeds \
  -- ./target_parser @@
```

---

## 3. Gramatron for Protocol Fuzzing

Gramatron uses grammar automata for faster generation and better coverage of grammar-based targets:

```bash
# Build Gramatron
git clone https://github.com/HexHive/Gramatron.git
cd Gramatron
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Convert grammar to automaton
python3 scripts/grammar_to_automaton.py \
  --grammar grammars/http_request.json \
  --output automaton.bin
```

Define an HTTP protocol grammar for Gramatron:

```json
{
  "START": ["<method> <path> HTTP/<version>\\r\\n<headers>\\r\\n\\r\\n<body>"],
  "method": ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE"],
  "path": ["/", "/<segment>", "/<segment>/<segment>", "/<segment>?<params>"],
  "segment": ["api", "v1", "v2", "users", "admin", "..%2f", "%00", "A*500"],
  "version": ["1.0", "1.1", "2.0", "9.9"],
  "headers": ["<header>", "<header>\\r\\n<headers>"],
  "header": [
    "Host: <host>",
    "Content-Type: <ctype>",
    "Content-Length: <int>",
    "Transfer-Encoding: chunked",
    "X-Forwarded-For: 127.0.0.1"
  ],
  "host": ["localhost", "127.0.0.1", "0.0.0.0", "[::1]", "evil.com"],
  "ctype": ["application/json", "text/xml", "multipart/form-data; boundary=AAAA"],
  "int": ["0", "-1", "99999999", "2147483647"],
  "params": ["id=1", "id=1&debug=true", "id=<sqli>"],
  "sqli": ["1 OR 1=1", "1; DROP TABLE users--", "1 UNION SELECT null"],
  "body": ["", "{}", "{\"key\":\"value\"}", "<xml_payload>"],
  "xml_payload": ["<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><x>&xxe;</x>"]
}
```

```bash
# Fuzz with Gramatron
./gramatron-fuzz \
  -automaton automaton.bin \
  -input seeds/ \
  -output findings/ \
  -- ./http_parser @@
```

---

## 4. Custom Grammar for SQL Parsers

Fuzzing database query parsers requires SQL-aware grammars:

```python
#!/usr/bin/env python3
"""Generate grammar-aware SQL inputs for fuzzing."""

from dataclasses import dataclass
from typing import Sequence
import random

@dataclass(frozen=True)
class GrammarRule:
    name: str
    expansions: tuple[str, ...]

SQL_GRAMMAR: Sequence[GrammarRule] = (
    GrammarRule("query", (
        "SELECT {columns} FROM {table} {where} {limit}",
        "INSERT INTO {table} ({columns}) VALUES ({values})",
        "UPDATE {table} SET {assignment} {where}",
        "DELETE FROM {table} {where}",
    )),
    GrammarRule("columns", ("*", "{col}", "{col}, {col}", "COUNT({col})")),
    GrammarRule("col", ("id", "name", "email", "1", "@@version", "sleep(5)")),
    GrammarRule("table", ("users", "orders", "information_schema.tables", "(SELECT 1)")),
    GrammarRule("where", ("", "WHERE {condition}", "WHERE 1=1", "WHERE {col} LIKE '%{inject}%'")),
    GrammarRule("condition", ("{col} = {value}", "{col} > {value}", "{col} IS NULL")),
    GrammarRule("value", ("1", "'test'", "NULL", "0x41414141", "'' OR ''=''")),
    GrammarRule("inject", ("' OR 1=1--", "'; EXEC xp_cmdshell('id')--", "%00")),
    GrammarRule("limit", ("", "LIMIT 1", "LIMIT 999999", "LIMIT -1")),
    GrammarRule("assignment", ("{col} = {value}", "{col} = {col} + 1")),
    GrammarRule("values", ("{value}", "{value}, {value}", "{value}, {value}, {value}")),
)

def expand(symbol: str, grammar: Sequence[GrammarRule], depth: int = 0) -> str:
    if depth > 10:
        return symbol
    for rule in grammar:
        if rule.name == symbol:
            expansion = random.choice(rule.expansions)
            result = expansion
            for r in grammar:
                while "{" + r.name + "}" in result:
                    result = result.replace(
                        "{" + r.name + "}", expand(r.name, grammar, depth + 1), 1
                    )
            return result
    return symbol

# Generate 1000 grammar-aware SQL inputs
for i in range(1000):
    query = expand("query", SQL_GRAMMAR)
    with open(f"corpus/sql_{i:04d}.txt", "w") as f:
        f.write(query)
```

---

## 5. Integrating Grammar Fuzzing with AFL++

Use AFL++ custom mutators to combine grammar awareness with coverage guidance:

```bash
# Build AFL++ with custom mutator support
cd AFLplusplus
make -j$(nproc)

# Use the grammar mutator plugin
cd custom_mutators/grammar_mutator
make GRAMMAR_FILE=/path/to/grammar.json

# Run AFL++ with grammar mutator
AFL_CUSTOM_MUTATOR_LIBRARY=./grammar_mutator.so \
AFL_CUSTOM_MUTATOR_ONLY=1 \
afl-fuzz -i seeds/ -o output/ \
  -- ./target_instrumented @@
```

For targets that need both grammar-aware and random mutations:

```bash
# Hybrid mode: grammar mutator + standard AFL++ mutations
AFL_CUSTOM_MUTATOR_LIBRARY=./grammar_mutator.so \
afl-fuzz -i seeds/ -o output/ \
  -P exploit \
  -- ./target_instrumented @@
```

---

## 6. Grammar Extraction from Existing Parsers

When no formal grammar exists, extract one from the target's source code or sample inputs:

```bash
# Use ANTLR grammar repository as starting point
git clone https://github.com/antlr/grammars-v4.git
ls grammars-v4/ | head -20
# Contains grammars for: json, xml, sql, css, html, javascript, python...

# Convert ANTLR grammar to Nautilus format
python3 tools/antlr_to_nautilus.py \
  --input grammars-v4/json/JSON.g4 \
  --output nautilus_json_grammar.json

# Alternatively, infer grammar from sample inputs using GLADE
git clone https://github.com/pag-iiitd/GLADE.git
python3 GLADE/infer.py \
  --samples /path/to/valid_inputs/ \
  --output inferred_grammar.json
```

---

## 7. Measuring Grammar Fuzzing Effectiveness

Track whether grammar-based fuzzing outperforms blind mutation:

```bash
# Compare coverage: grammar-based vs mutation-based (24-hour run)
# Terminal 1: Grammar fuzzer
AFL_CUSTOM_MUTATOR_LIBRARY=./grammar_mutator.so \
AFL_CUSTOM_MUTATOR_ONLY=1 \
afl-fuzz -i seeds/ -o output_grammar/ -- ./target @@

# Terminal 2: Standard AFL++ mutation
afl-fuzz -i seeds/ -o output_mutation/ -- ./target @@

# After 24 hours, compare coverage
afl-showmap -C -i output_grammar/default/queue -o /dev/null -- ./target @@ 2>&1 | tail -1
afl-showmap -C -i output_mutation/default/queue -o /dev/null -- ./target @@ 2>&1 | tail -1

# Compare unique crashes found
echo "Grammar crashes: $(ls output_grammar/default/crashes/id:* 2>/dev/null | wc -l)"
echo "Mutation crashes: $(ls output_mutation/default/crashes/id:* 2>/dev/null | wc -l)"
```

Grammar-based fuzzing typically achieves 30-60% more code coverage on parser-heavy targets within the first hour, and finds deeper bugs that mutation fuzzing misses entirely because it cannot generate syntactically valid inputs that reach post-parsing logic.

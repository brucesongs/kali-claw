# MCP Protocol Debugging Guide

> Practical reference for inspecting MCP protocol messages, tracing communication flows, diagnosing errors, and troubleshooting common issues. Covers message format analysis, logging strategies, and debugging tools.

## 1. MCP Protocol Message Structure

Understanding the JSON-RPC 2.0 message format used by MCP.

```json
// MCP Request (client → server)
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "read_file",
    "arguments": {
      "path": "/workspace/src/main.py"
    }
  }
}

// MCP Response (server → client)
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "content": [
      {
        "type": "text",
        "text": "# File contents here..."
      }
    ]
  }
}

// MCP Error Response
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32602,
    "message": "Invalid params",
    "data": {
      "details": "Parameter 'path' is required"
    }
  }
}

// MCP Notification (no id, no response expected)
{
  "jsonrpc": "2.0",
  "method": "notifications/progress",
  "params": {
    "progressToken": "abc123",
    "progress": 50,
    "total": 100
  }
}
```

## 2. Message Tracing with Logging Proxy

```python
#!/usr/bin/env python3
"""MCP protocol debugging proxy — intercepts and logs all messages."""
import asyncio
import json
import sys
import logging
from datetime import datetime, timezone

logging.basicConfig(
    filename="/tmp/mcp_trace.jsonl",
    level=logging.DEBUG,
    format="%(message)s"
)
logger = logging.getLogger("mcp_proxy")

async def trace_message(direction: str, data: bytes) -> bytes:
    """Log MCP message with timestamp and direction."""
    try:
        message = json.loads(data)
        trace_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction,  # "client→server" or "server→client"
            "method": message.get("method", "response"),
            "id": message.get("id"),
            "has_error": "error" in message,
            "size_bytes": len(data),
            "message": message
        }
        logger.info(json.dumps(trace_entry))
    except json.JSONDecodeError:
        logger.warning(json.dumps({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "direction": direction,
            "error": "Invalid JSON",
            "raw": data.decode("utf-8", errors="replace")[:500]
        }))
    
    return data

async def proxy_stdio(reader_in, writer_out, direction: str):
    """Proxy stdio streams with message tracing."""
    while True:
        # MCP uses Content-Length header framing
        header = await reader_in.readline()
        if not header:
            break
        
        if header.startswith(b"Content-Length:"):
            length = int(header.split(b":")[1].strip())
            await reader_in.readline()  # Empty line separator
            body = await reader_in.readexactly(length)
            
            # Trace the message
            body = await trace_message(direction, body)
            
            # Forward to output
            writer_out.write(f"Content-Length: {len(body)}\r\n\r\n".encode())
            writer_out.write(body)
            await writer_out.drain()
```

## 3. Common Error Codes and Diagnosis

```bash
# MCP JSON-RPC error codes reference
# -32700  Parse error       — Invalid JSON received
# -32600  Invalid Request   — Not a valid JSON-RPC request
# -32601  Method not found  — Tool/method doesn't exist
# -32602  Invalid params    — Wrong parameters for tool
# -32603  Internal error    — Server-side failure
# -32000 to -32099          — Server-defined errors

# Diagnose common issues from error codes
diagnose_error() {
    local code="$1"
    case "$code" in
        -32700) echo "Parse error: Check JSON syntax. Common: trailing commas, unquoted keys" ;;
        -32600) echo "Invalid request: Missing jsonrpc/method field. Check message structure" ;;
        -32601) echo "Method not found: Tool not registered. Check server capabilities" ;;
        -32602) echo "Invalid params: Wrong argument types/names. Check tool schema" ;;
        -32603) echo "Internal error: Server crash. Check server logs for stack trace" ;;
        *)      echo "Server error ($code): Check server-specific error documentation" ;;
    esac
}

# Parse MCP trace log for errors
jq 'select(.has_error == true)' /tmp/mcp_trace.jsonl

# Find slow tool calls (>5 seconds)
jq -s 'sort_by(.timestamp) | 
  [.[] | select(.direction == "client→server" and .method == "tools/call")] as $requests |
  [.[] | select(.direction == "server→client" and .id != null)] as $responses |
  [$requests[] as $req | 
    ($responses[] | select(.id == $req.id)) as $resp |
    {method: $req.method, id: $req.id, duration: "check timestamps"}
  ]' /tmp/mcp_trace.jsonl
```

## 4. Interactive Protocol Inspector

```python
#!/usr/bin/env python3
"""Interactive MCP protocol inspector for debugging sessions."""
import json
import sys
from pathlib import Path
from collections import defaultdict

def analyze_trace(trace_file: str) -> None:
    """Analyze MCP trace file for patterns and issues."""
    messages = []
    with open(trace_file) as f:
        for line in f:
            try:
                messages.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    
    # Statistics
    methods = defaultdict(int)
    errors = []
    request_times = {}
    
    for msg in messages:
        direction = msg.get("direction", "")
        message = msg.get("message", {})
        
        if "method" in message:
            methods[message["method"]] += 1
        
        if "error" in message:
            errors.append(msg)
        
        # Track request/response pairs
        msg_id = message.get("id")
        if msg_id and "method" in message:
            request_times[msg_id] = msg["timestamp"]
    
    print("=== MCP Protocol Analysis ===")
    print(f"\nTotal messages: {len(messages)}")
    print(f"Errors: {len(errors)}")
    
    print("\nMethod frequency:")
    for method, count in sorted(methods.items(), key=lambda x: -x[1]):
        print(f"  {method}: {count}")
    
    if errors:
        print("\nErrors found:")
        for err in errors[:10]:
            error_data = err["message"].get("error", {})
            print(f"  [{error_data.get('code')}] {error_data.get('message')}")
            if "data" in error_data:
                print(f"    Details: {error_data['data']}")

if __name__ == "__main__":
    analyze_trace(sys.argv[1] if len(sys.argv) > 1 else "/tmp/mcp_trace.jsonl")
```

## 5. Server Capability Negotiation Debugging

```python
"""Debug MCP server initialization and capability exchange."""
import json
import subprocess
import sys

def test_server_init(server_command: list) -> dict:
    """Send initialize request and inspect server capabilities."""
    
    init_request = json.dumps({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "roots": {"listChanged": True}
            },
            "clientInfo": {
                "name": "mcp-debugger",
                "version": "1.0.0"
            }
        }
    })
    
    # Frame with Content-Length header
    framed = f"Content-Length: {len(init_request)}\r\n\r\n{init_request}"
    
    proc = subprocess.Popen(
        server_command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    proc.stdin.write(framed)
    proc.stdin.flush()
    
    # Read response
    header = proc.stdout.readline()
    proc.stdout.readline()  # empty line
    length = int(header.split(":")[1].strip())
    response = proc.stdout.read(length)
    
    result = json.loads(response)
    
    print("=== Server Capabilities ===")
    print(json.dumps(result.get("result", {}), indent=2))
    
    # Check for common issues
    caps = result.get("result", {}).get("capabilities", {})
    if "tools" not in caps:
        print("\n[WARN] Server does not advertise tool support")
    if "resources" not in caps:
        print("\n[INFO] Server does not support resources")
    
    proc.terminate()
    return result
```

```bash
# Quick capability check
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"debug","version":"1.0"}}}' | \
  python3 -c "
import sys, json
msg = sys.stdin.read()
print(f'Content-Length: {len(msg)}\r\n\r\n{msg}', end='')
" | python3 -m my_mcp_server 2>/dev/null | tail -1 | python3 -m json.tool
```

## 6. Transport Layer Debugging

```bash
# Debug stdio transport — capture raw bytes
strace -e trace=read,write -p $(pgrep -f mcp_server) 2>&1 | \
  grep -E "^(read|write)" | head -50

# Debug SSE transport — inspect HTTP stream
curl -N -H "Accept: text/event-stream" http://localhost:8080/sse -v 2>&1 | \
  tee /tmp/mcp_sse_debug.txt

# Debug WebSocket transport
websocat ws://localhost:8080/ws --text -v 2>&1 | tee /tmp/mcp_ws_debug.txt

# Monitor MCP server process health
watch -n 1 "ps aux | grep mcp_server; echo '---'; \
  lsof -p \$(pgrep -f mcp_server) | grep -c 'ESTABLISHED'; echo 'connections'; \
  cat /proc/\$(pgrep -f mcp_server)/status 2>/dev/null | grep -E 'VmRSS|Threads'"

# Check for stuck/zombie processes
ps aux | grep mcp | grep -v grep
# If server is unresponsive, check file descriptors
ls -la /proc/$(pgrep -f mcp_server)/fd/ 2>/dev/null | wc -l
```

## 7. Tool Registration and Schema Validation

```python
"""Validate MCP tool schemas and test tool invocations."""
import json
from typing import Any

def validate_tool_schema(tool_definition: dict) -> list:
    """Check tool definition for common schema issues."""
    issues = []
    
    # Required fields
    if "name" not in tool_definition:
        issues.append("Missing 'name' field")
    if "description" not in tool_definition:
        issues.append("Missing 'description' field")
    
    # Input schema validation
    schema = tool_definition.get("inputSchema", {})
    if schema.get("type") != "object":
        issues.append("inputSchema.type should be 'object'")
    
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    
    # Check required fields exist in properties
    for req in required:
        if req not in properties:
            issues.append(f"Required field '{req}' not in properties")
    
    # Check property definitions
    for prop_name, prop_def in properties.items():
        if "type" not in prop_def and "$ref" not in prop_def:
            issues.append(f"Property '{prop_name}' missing type")
        if "description" not in prop_def:
            issues.append(f"Property '{prop_name}' missing description")
    
    return issues

# Test tool listing
def debug_tools_list(trace_file: str) -> None:
    """Extract and validate all tools from trace."""
    with open(trace_file) as f:
        for line in f:
            msg = json.loads(line)
            message = msg.get("message", {})
            if message.get("id") and "result" in message:
                tools = message["result"].get("tools", [])
                if tools:
                    print(f"Found {len(tools)} tools:")
                    for tool in tools:
                        issues = validate_tool_schema(tool)
                        status = "OK" if not issues else f"ISSUES: {issues}"
                        print(f"  - {tool['name']}: {status}")
```

## 8. End-to-End Debugging Workflow

```bash
#!/bin/bash
# mcp_debug_session.sh — Complete debugging workflow
set -e

SERVER_CMD="${1:-python3 -m my_mcp_server}"
LOG_DIR="/tmp/mcp_debug_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$LOG_DIR"

echo "=== MCP Debug Session ==="
echo "Server: $SERVER_CMD"
echo "Logs: $LOG_DIR"

# Start server with debug logging
MCP_LOG_LEVEL=debug $SERVER_CMD 2>"$LOG_DIR/server_stderr.log" &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Wait for server to start
sleep 2

# Test 1: Initialize
echo "[Test 1] Initialize handshake..."
python3 -c "
import json, subprocess, sys

proc = subprocess.Popen(
    '$SERVER_CMD'.split(),
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
)

msg = json.dumps({'jsonrpc':'2.0','id':1,'method':'initialize','params':{'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'debug','version':'1.0'}}})
proc.stdin.write(f'Content-Length: {len(msg)}\r\n\r\n{msg}')
proc.stdin.flush()

# Read response
import time; time.sleep(1)
proc.terminate()
out = proc.stdout.read()
print(out)
" > "$LOG_DIR/init_response.txt" 2>&1

echo "[Test 1] Response saved to $LOG_DIR/init_response.txt"

# Test 2: List tools
echo "[Test 2] Listing tools..."

# Test 3: Call a tool
echo "[Test 3] Tool invocation test..."

# Cleanup
kill $SERVER_PID 2>/dev/null || true

# Summary
echo ""
echo "=== Debug Summary ==="
echo "Server stderr: $LOG_DIR/server_stderr.log"
echo "Init response: $LOG_DIR/init_response.txt"
echo ""
echo "Common issues to check:"
echo "  1. Server stderr for startup errors"
echo "  2. Protocol version mismatch in init response"
echo "  3. Missing tools in capabilities"
echo "  4. Timeout on tool calls (check server processing)"
```

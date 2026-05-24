# MCP Tool Implementation Guide

> Skill: mcp-server-patterns | Type: practical
> Created: 2026-05-23 | Estimated Study Time: 45 minutes

## Overview

Learn to implement Model Context Protocol (MCP) tools for OpenClaw agents. Covers tool definition, parameter validation, error handling, and integration with Kali Linux security tools.

## Prerequisites

- MCP server concepts
- Kali Linux tool familiarity
- Basic Python/TypeScript

## 1. MCP Tool Structure

### Tool Definition Template

```typescript
// tools/security-tool.ts
import { z } from 'zod';

export const nmapTool = {
  name: 'nmap_scan',
  description: 'Execute nmap port scan on specified target',
  inputSchema: z.object({
    target: z.string().describe('Target IP or hostname'),
    ports: z.string().optional().describe('Port range (e.g., "1-1000" or "22,80,443")'),
    scan_type: z.enum(['sS', 'sT', 'sU']).optional().describe('Scan type: SYN, TCP, UDP'),
    timing: z.enum(['0', '1', '2', '3', '4', '5']).optional().describe('Timing template (0-5)'),
    output_format: z.enum(['normal', 'xml', 'grepable']).optional().describe('Output format'),
  }).strict(),
};
```

### Tool Handler Template

```typescript
// handlers/nmap-handler.ts
import { nmapTool } from '../tools/security-tool';

export async function handleNmapScan(params: any) {
  // Validate input
  const validated = nmapTool.inputSchema.parse(params);

  // Build command
  const args = [
    `-${validated.scan_type || 'sS'}`,
    `-T${validated.timing || '3'}`,
  ];

  if (validated.ports) {
    args.push(`-p ${validated.ports}`);
  }

  if (validated.output_format === 'xml') {
    args.push('-oX -');
  }

  args.push(validated.target);

  const cmd = `nmap ${args.join(' ')}`;

  // Execute
  try {
    const result = await executeCommand(cmd);
    return {
      success: true,
      target: validated.target,
      scan_type: validated.scan_type || 'sS',
      output: result.stdout,
      duration: result.duration,
      open_ports: parseOpenPorts(result.stdout),
    };
  } catch (error) {
    return {
      success: false,
      target: validated.target,
      error: error.message,
      suggestion: getSuggestion(error),
    };
  }
}

function parseOpenPorts(output: string): string[] {
  const matches = output.matchAll(/(\d+)\/tcp\s+open/g);
  return Array.from(matches, m => m[1]);
}
```

## 2. Parameter Validation

### Zod Schema Patterns

```typescript
import { z } from 'zod';

// IP address validation
const ipSchema = z.string().regex(
  /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  'Must be a valid IPv4 address'
);

// Port range validation
const portSchema = z.string().regex(
  /^(?:\d+|\d+-\d+|\d+,\d+)(?:,(?:\d+|\d+-\d+))*$/,
  'Must be a valid port specification'
);

// Network scan target validation
const targetSchema = z.string().min(1).refine(
  (val) => {
    return ipSchema.safeParse(val).success ||
           val.includes('/') || // CIDR
           val.match(/^[a-zA-Z0-9.-]+$/); // Hostname
  },
  'Must be a valid IP, CIDR, or hostname'
);

// Username validation for privilege escalation
const usernameSchema = z.string().min(1).max(32).regex(
  /^[a-z_][a-z0-9_-]*$/,
  'Must be a valid username'
);
```

### Advanced Validation

```typescript
// Conditional validation
const sshBruteForceSchema = z.object({
  target: ipSchema,
  username: z.string(),
  password_file: z.string(),
  username_list: z.string().optional(),
}).refine(
  (data) => data.username || data.username_list,
  'Must provide either username or username_list'
);

// File existence validation
const fileExists = z.string().refine(
  async (path) => {
    try {
      await fs.access(path);
      return true;
    } catch {
      return false;
    }
  },
  'File does not exist'
);
```

## 3. Error Handling Patterns

### Standardized Error Response

```typescript
interface ToolError {
  success: false;
  error_code: string;
  error_message: string;
  suggestion?: string;
  context?: Record<string, any>;
}

enum ErrorCode {
  INVALID_INPUT = 'INVALID_INPUT',
  TOOL_NOT_FOUND = 'TOOL_NOT_FOUND',
  EXECUTION_FAILED = 'EXECUTION_FAILED',
  PERMISSION_DENIED = 'PERMISSION_DENIED',
  TIMEOUT = 'TIMEOUT',
  NETWORK_ERROR = 'NETWORK_ERROR',
}

function createError(
  code: ErrorCode,
  message: string,
  suggestion?: string,
  context?: Record<string, any>
): ToolError {
  return {
    success: false,
    error_code: code,
    error_message: message,
    suggestion,
    context,
  };
}
```

### Specific Error Handlers

```typescript
// Tool not installed
function handleToolNotAvailable(tool: string, installCmd: string): ToolError {
  return createError(
    ErrorCode.TOOL_NOT_FOUND,
    `Tool '${tool}' is not available on this system`,
    `Install with: ${installCmd}`,
    { tool }
  );
}

// Permission denied
function handlePermissionDenied(command: string): ToolError {
  return createError(
    ErrorCode.PERMISSION_DENIED,
    `Insufficient permissions to execute: ${command}`,
    'Try running with elevated privileges (sudo)',
    { command }
  );
}

// Network timeout
function handleTimeout(command: string, duration: number): ToolError {
  return createError(
    ErrorCode.TIMEOUT,
    `Command timed out after ${duration} seconds: ${command}`,
    'Try increasing timeout or reducing scan scope',
    { command, duration }
  );
}
```

## 4. Tool Categories

### Network Scanning Tools

```typescript
// nmap
export const nmapScanTool = {
  name: 'nmap_scan',
  description: 'Port and service discovery scan',
  inputSchema: z.object({
    target: targetSchema,
    ports: portSchema.optional(),
    scan_type: z.enum(['sS', 'sT', 'sU', 'sV', 'sO']).optional(),
  }),
};

// masscan
export const masscanTool = {
  name: 'masscan',
  description: 'Fast port scanner for large networks',
  inputSchema: z.object({
    target: z.string().describe('IP range in CIDR format'),
    ports: z.string().describe('Port range (e.g., "0-65535")'),
    rate: z.string().optional().describe('Packets per second'),
  }),
};

// netcat
export const netcatTool = {
  name: 'netcat',
  description: 'TCP/UDP port listener and connector',
  inputSchema: z.object({
    host: z.string(),
    port: z.number().min(1).max(65535),
    mode: z.enum(['listen', 'connect', 'scan']),
    payload: z.string().optional(),
  }),
};
```

### Web Application Tools

```typescript
// burp
export const burpScanTool = {
  name: 'burp_scan',
  description: 'Burp Suite vulnerability scanner',
  inputSchema: z.object({
    target: z.string().url('Must be a valid URL'),
    scan_type: z.enum(['active', 'passive', 'crawl']),
    profile: z.string().optional().describe('Scan profile name'),
  }),
};

// nikto
export const niktoTool = {
  name: 'nikto_scan',
  description: 'Web server vulnerability scanner',
  inputSchema: z.object({
    target: z.string().url(),
    options: z.array(z.string()).optional(),
  }),
};

// sqlmap
export const sqlmapTool = {
  name: 'sqlmap',
  description: 'SQL injection detection and exploitation',
  inputSchema: z.object({
    url: z.string().url(),
    parameter: z.string(),
    technique: z.enum(['B', 'E', 'U', 'S', 'T', 'Q']).optional(),
    dbms: z.string().optional(),
  }),
};
```

### Password Attack Tools

```typescript
// hydra
export const hydraTool = {
  name: 'hydra_brute',
  description: 'Parallel login cracker',
  inputSchema: z.object({
    target: ipSchema,
    service: z.enum(['ssh', 'ftp', 'http-post-form', 'http-get']),
    username: z.string(),
    password_list: z.string(),
    port: z.number().min(1).max(65535).optional(),
    threads: z.number().min(1).max(16).optional(),
  }),
};

// john
export const johnTool = {
  name: 'john_crack',
  description: 'John the Ripper password cracker',
  inputSchema: z.object({
    hash_file: fileExists,
    wordlist: z.string().optional(),
    format: z.string().optional().describe('Hash format (e.g., md5crypt, sha256crypt)'),
  }),
};

// hashcat
export const hashcatTool = {
  name: 'hashcat_crack',
  description: 'GPU-accelerated password recovery',
  inputSchema: z.object({
    hash_file: fileExists,
    hash_type: z.number().min(0).max= 'Hash type number (see --help)'),
    wordlist: z.string().optional(),
    attack_mode: z.enum(['0', '1', '3', '6', '7']).optional(),
  }),
};
```

### Post-Exploitation Tools

```typescript
// linpeas
export const linpeasTool = {
  name: 'linpeas',
  description: 'Linux privilege escalation audit script',
  inputSchema: z.object({
    output_file: z.string().optional(),
    options: z.array(z.string()).optional(),
  }),
};

// winpeas
export const winpeasTool = {
  name: 'winpeas',
  description: 'Windows privilege escalation audit',
  inputSchema: z.object({
    output_file: z.string().optional(),
  }),
};

// mimikatz
export const mimikatzTool = {
  name: 'mimikatz',
  description: 'Extract credentials from Windows memory',
  inputSchema: z.object({
    command: z.string().describe('Mimikatz command (e.g., "privilege::debug", "sekurlsa::logonpasswords")'),
    output_format: z.enum(['text', 'json']).optional(),
  }),
};
```

## 5. Output Parsing

### Structured Output

```typescript
// Parse nmap XML output
function parseNmapXml(xmlOutput: string) {
  // Use xml2js or similar
  const result = {
    target: '',
    start_time: '',
    end_time: '',
    hosts: [] as Array<{
      ip: string;
      state: string;
      ports: Array<{
        port: number;
        protocol: 'tcp' | 'udp';
        state: string;
        service: string;
        version?: string;
      }>;
    }>,
  };

  // Parse and populate result
  return result;
}

// Parse nikto output
function parseNikto(output: string) {
  const findings = output.split('\n')
    .filter(line => line.includes('+'))
    .map(line => {
      const match = line.match(/\+ (.+?): (.+)/);
      return match ? { type: match[1], detail: match[2] } : null;
    })
    .filter(Boolean);

  return { findings, total: findings.length };
}
```

## 6. Security Considerations

### Input Sanitization

```typescript
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Secure command building - escape user input
function sanitizeShellArg(arg: string): string {
  return `"${arg.replace(/"/g, '\\"')}"`;
}

// Alternative: Use execFile with array arguments
async function safeExecute(tool: string, args: string[]) {
  return execFile(tool, args);
}
```

### Rate Limiting

```typescript
class RateLimiter {
  private lastExecution = 0;
  private minInterval: number;

  constructor(minIntervalMs: number = 1000) {
    this.minInterval = minIntervalMs;
  }

  async execute(fn: () => Promise<any>) {
    const now = Date.now();
    const elapsed = now - this.lastExecution;

    if (elapsed < this.minInterval) {
      await new Promise(resolve =>
        setTimeout(resolve, this.minInterval - elapsed)
      );
    }

    this.lastExecution = Date.now();
    return fn();
  }
}

// Usage
const limiter = new RateLimiter(2000); // 2 second minimum interval
await limiter.execute(() => handleNmapScan({ target: '192.168.1.1' }));
```

### Operation Logging

```typescript
async function executeWithLogging(
  tool: string,
  params: any,
  handler: Function
) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    tool,
    params: redactSensitive(params),
    status: 'started',
  };

  logOperation(logEntry);

  try {
    const result = await handler(params);
    logEntry.status = 'success';
    logEntry.result = redactSensitive(result);
    return result;
  } catch (error) {
    logEntry.status = 'error';
    logEntry.error = error.message;
    throw error;
  } finally {
    logOperation(logEntry);
  }
}

function redactSensitive(data: any): any {
  // Redact passwords, tokens, keys
  const sensitive = ['password', 'token', 'key', 'secret', 'credential'];
  const redacted = { ...data };

  for (const key in redacted) {
    if (sensitive.some(s => key.toLowerCase().includes(s))) {
      redacted[key] = '[REDACTED]';
    }
  }

  return redacted;
}
```

## Quick Reference

```typescript
// Tool definition
export const tool = {
  name: 'tool_name',
  description: 'What it does',
  inputSchema: z.object({ /* params */ }).strict(),
};

// Handler template
export async function handleTool(params: any) {
  const validated = tool.inputSchema.parse(params);
  const result = await executeCommand(...);
  return { success: true, data: result };
}

// Error response
return {
  success: false,
  error_code: 'INVALID_INPUT',
  error_message: '...',
  suggestion: '...',
};

// Input validation
const ipSchema = z.string().regex(/^[\d\.]+$/);
const targetSchema = z.object({ target: ipSchema });
```

## Integration with Other Skills

- **mcp-server-patterns**: Security server design
- **network-pentest**: Network scanning tools
- **web-assessment**: Web application tools
- **password-attack**: Password cracking tools
- **post-exploitation**: Privilege escalation tools
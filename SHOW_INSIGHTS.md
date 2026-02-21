# Understanding `-ShowInsights`

This project’s `Get-TerraformPlanReport.ps1` script can optionally generate “intelligent insights” with the `-ShowInsights` switch.

`-ShowInsights` is **not** a security scanner and it does not evaluate real cloud runtime state. It is a **heuristic** analysis of what the Terraform plan text *suggests* is changing.

---

## What `-ShowInsights` does

When enabled, the script analyzes the parsed plan resources and prints these sections:

- **Cost Impact Analysis**: classifies resources as high/medium/low cost impact and estimates a monthly cost delta.
- **Security Impact Analysis**: flags security-relevant changes as improvements vs concerns.
- **Governance & Compliance Analysis**: looks for evidence of governance controls (tags, naming conventions, policies, RBAC, locks, etc.).
- **Carbon Impact Analysis**: estimates a monthly CO2e delta based on resource type and inferred region.
- **Executive Summary**: totals, trend summaries, and a coarse “risk level”.

All of the above are based on:

- the **resource type/name** found in the plan output, and
- the **captured diff lines** for that resource (when present).

---

## Inputs & filtering

You can combine `-ShowInsights` with filters to keep the analysis focused:

```powershell
# Insights for everything
.\Get-TerraformPlanReport.ps1 -LogFile .\plan.out -ShowInsights

# Only Security-category resources
.\Get-TerraformPlanReport.ps1 -LogFile .\plan.out -Category Security -ShowInsights

# Only resources matching a name pattern
.\Get-TerraformPlanReport.ps1 -LogFile .\plan.out -ResourceName '*prod*' -ShowInsights

# Only a resource type pattern
.\Get-TerraformPlanReport.ps1 -LogFile .\plan.out -ResourceType '*storage*' -ShowInsights
```

Attribute diff lines are always captured for every resource. For console output, add `-ShowChanges` to see them inline:

```powershell
.\Get-TerraformPlanReport.ps1 -LogFile .\plan.out -ShowInsights -ShowChanges
```

The HTML report (`-OutputHtml`) always includes attribute diffs for Update and Replace actions. Create and Destroy actions are excluded from the diff viewer because they show full attribute dumps rather than meaningful changes.

### Capturing results programmatically

Most of the report output is written with `Write-Host`, which is great for humans but awkward to parse in automation.

If you want **structured output**, use `-PassThru` to emit an object that includes summary counts and (when `-ShowInsights` is set) the full `Insights` object:

```powershell
$report = .\Get-TerraformPlanReport.ps1 -LogFile .\plan.out -ShowInsights -PassThru

$report.Summary
$report.Insights.Security.Negative.Count
$report.Insights.Security.Negative | Select-Object -First 10
```

---

## How the Security analysis works (and why results can look odd)

The security section is keyword-driven:

1. The script has a list of **security indicators** (examples: `public_network_access_enabled`, `enable_rbac`, `identity`, `key_vault`, `secret`, `password`, etc.).
2. It also has two keyword lists:
   - **Positive keywords**: things that usually indicate tightening security (examples: `enabled`, `required`, `true`, `encrypted`).
   - **Negative keywords**: things that often indicate weakening security or exposure (examples: `public`, `0.0.0.0/0`, `disabled`, `false`).
3. For each resource, it checks whether any indicator appears in the captured change text.
4. If an indicator matches, it then tries to decide whether the change is:
   - an **Improvement**,
   - a **Concern**, or
   - a **Modification** (neutral).

### Classification logic (simplified)

Pseudocode of the intent:

- If **indicator** matched AND **positive** matched AND **negative** did NOT match:
  - If action is `Destroy` → **Concern** (removing a “secure thing” can reduce security)
  - Else → **Improvement**

- If **indicator** matched AND **negative** matched:
  - If action is `Destroy` → **Improvement** (removing a “risky thing” can improve security)
  - Else → **Concern**

- Else:
  - **Modification**

### Interpreting the “identity” example

These two messages come from two different branches of that logic:

- `… - Improved: identity`
  - The resource’s diff contained `identity` plus at least one “positive” keyword (and no negative keyword).

- `… - Security improvement: Removing identity risk`
  - The resource’s diff contained `identity` plus at least one “negative” keyword, and Terraform is destroying the resource.

This does **not** mean “Managed Identity is bad” or that Azure Policy assignments are insecure. It means the heuristic saw `identity` in the diff and also saw keywords that it associates with improvement or risk.

---

## Common causes of false positives

Because the analysis is based on plan text, it can be noisy in real plans.

Typical false-positive patterns include:

- **Words appear in names**: e.g., a management group named `*-identity*` can cause unrelated resources to look identity-related if a heuristic matches the name instead of the diff.
- **Policy-heavy plans**: large Azure Landing Zone / policy-as-code plans can contain lots of governance and identity-related fields, and can trigger a high count of “security-related changes” even when nothing risky is being introduced.
- **Generic words in policy names**: words like `public` can appear in policy names such as `Deny-Public-IP`. If the heuristic treats `public` as a generic “risk token”, it can incorrectly flag the policy assignment as a concern even though the policy is hardening security.

In general, the security analysis uses **literal keyword matching** against the plan text, so it can’t reliably understand intent from names like `Deny-*`, `Audit-*`, etc.

To reduce noise, the script primarily evaluates “positive/negative” keywords against the **same change line(s) where the indicator was found**, instead of scanning the entire resource diff.

**Public exposure flags** (like `public_network_access_enabled`) are treated specially:

- `= true` / `enabled` → considered a **risk**
- `= false` / `disabled` → considered an **improvement**

If a result looks surprising, the best check is:

1) check the attribute diff (always captured; use `-ShowChanges` for console display, or open the HTML report) with a narrow filter (`-ResourceName` / `-ResourceType`), and
2) verify the actual semantic change (e.g., does the plan enable public access, loosen NSGs, disable TLS enforcement, etc.).

---

## How the Cost analysis works (high level)

- Uses a mapping of resource types → high/medium/low cost impact.
- Estimates monthly deltas with simple lookup tables (e.g., VM sizes, common service baselines).
- Replacements/updates generally treat monthly cost delta as 0 because the plan text often doesn’t carry enough detail to confidently compute a delta.

---

## How Governance & Compliance works (high level)

This section evaluates 12 governance criteria using **type-aware matching** (not substring matching on full addresses):

- **Tags** — scanned from attribute change text for `tags`, `cost_center`, `environment`, `owner`, etc.
- **Naming Conventions** — validates the **actual Azure resource name** (from the plan's `name` attribute) against CAF prefixes (`rg-`, `vnet-`, etc.), environment/region indicators, numbered instances, and multi-segment structure (≥3 parts). Excludes policy/RBAC/management group resources and auto-generated names (UUIDs, timestamps).
- **Policies/Monitoring** — detected by resource type (`policy_assignment`, `diagnostic_setting`, `log_analytics_workspace`, etc.)
- **Backup/Retention** — for infrastructure resources, scans change text; for policy resources, only matches policy names indicating backup (e.g., `Deploy-VM-Backup`)
- **Resource Locks** — management lock resource types or lock attributes
- **RBAC/IAM** — role assignment/definition resource types or IAM attributes
- **Network Isolation** (+2 weight) — private endpoints, VNet integration resource types
- **Audit Logging** — diagnostic settings, log analytics resource types
- **Compliance Frameworks** (+2 weight) — policy/definition resource types, Security Center. For ALZ plans, policies are categorized against well-known Enterprise-Scale patterns (Security, Identity, Networking, Logging, Monitoring, DataProtection, Compliance, KeyManagement, Storage)
- **Cost Management** — budget and cost export resources

### azapi_resource handling

All governance checks use `Test-GovernanceResourceMatch`, which matches against the **Terraform resource type** (from `Get-TfResourceType`), not substrings of the full address. For `azapi_resource`, the instance name part (e.g., `policy_assignments`, `role_definitions`) is matched with singular/plural handling.

Bulk `azapi_resource` matches (common in Azure Landing Zone plans) are **automatically summarized** into grouped entries (e.g., "132 azapi_resource.policy_role_assignments detected — RBAC/IAM configured") instead of listing hundreds of individual resources.

This is primarily "presence detection" (what patterns exist in the plan), not a full compliance evaluation.

Note: the script separates **Backup** (backup/restore tooling) from **Retention & Resiliency** (e.g., retention policies, replication). Many policy definitions (especially diagnostics policies) can show up under retention even if they are not “backup & restore”.

Also, for Azure Policy resources (policy assignments/definitions/initiatives), the script intentionally treats **Backup** as **name-based** (e.g., `Deploy-VM-Backup`, `Enforce-Backup`) rather than scanning the full policy JSON/body for the word “backup”. This avoids common false positives where unrelated policies mention “backup” somewhere in their embedded definitions.

---

## How Carbon analysis works (high level)

- Infers region/carbon intensity when it can (based on plan text).
- Uses coarse estimates by resource type and then scales by regional carbon intensity.
- Treats create/destroy as adding/removing emissions; updates/replaces are typically treated as 0 delta.

---

## Where to tweak the behavior

All heuristics are implemented in `Get-TerraformPlanReport.ps1` under the “Knowledge base for intelligent insights” section (keywords and mappings) and in the analysis loops inside the `if ($ShowInsights) { ... }` block.

If you want the output to be stricter/less noisy, the most impactful changes are:

- Narrow or split security indicators (e.g., treat `identity` differently from `password`).
- Reduce “negative keyword” matches to truly risky patterns (e.g., `0.0.0.0/0`, explicit `public_network_access_enabled = true`).
- Only consider negative keywords when they occur on the *same changed line* as an indicator.
---

## HTML Report: Legend & Methodology section

The HTML report (generated with `-OutputHtml`) includes a collapsible **"How This Report Works — Legend & Methodology"** section. This self-documenting section covers:

| Topic | What It Explains |
|-------|------------------|
| Resource Table | How each column (Resource Type, Resource Name, Azure Name, Resource Group, Subscription) is determined from the plan |
| Action Symbols & Colors | Meaning of ⇪ Import, ✓ Create, ≈ Update, ✗ Destroy, ⟳ Replace and their colors |
| Cost Impact | Lookup table methodology, per-resource estimates, VM size parsing, and limitations |
| Security Impact | Indicator + keyword classification matrix, special handling for public access, and false positive guidance |
| Carbon Impact | Regional carbon intensity scaling, base emissions per resource type, and limitations |
| Governance Scoring | All 12 criteria with weights, detection methods, azapi_resource summarization, and presence-detection caveats |
| Risk Level | Factor thresholds (destroy count, cost, security concerns, governance score) for Low/Medium/High |
| Attribute Changes | Diff color coding (+green, -red, ~yellow, gray context) |

The legend is always included in every HTML report for self-documentation — no external documentation needed to interpret the report.
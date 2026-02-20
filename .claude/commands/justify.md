Use the vm-agent MCP tool `lookup_cve` to fetch data for $ARGUMENTS (treat as a CVE ID).

Then generate a business justification for remediation that includes:

- **What it is**: Plain-language summary of the vulnerability and affected components
- **Business impact**: What could happen if exploited (data breach, downtime, compliance violation, etc.)
- **Exploitation reality**: Interpret the EPSS score and KEV status — is this being actively exploited in the wild?
- **Compliance implications**: Call out any regulatory relevance (PCI-DSS, SOC2, HIPAA, etc.) if inferable from the affected packages
- **Priority vs. other work**: Why this should be scheduled now rather than deferred — use severity, EPSS percentile, and KEV status to make the case
- **Suggested SLA**: Recommend a remediation timeline based on severity and exploitation likelihood (e.g. CRITICAL + KEV = 24h, HIGH + high EPSS = 7 days)
- **Remediation path**: What the fix looks like (version upgrade, config change, mitigation)

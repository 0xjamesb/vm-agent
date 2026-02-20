Parse $ARGUMENTS as: `<CVE-ID> --type <slack|email|ticket|escalation> [--team <name>] [--urgency <low|normal|high>]`

Use the vm-agent MCP tool `lookup_cve` to fetch vulnerability data, then draft the requested communication.

**slack** — Brief, actionable Slack message:
- Lead with a severity emoji (🔴 CRITICAL, 🟠 HIGH, 🟡 MEDIUM)
- One-line summary of what's affected and the risk
- EPSS/KEV context in one sentence
- Clear ask with a deadline
- Link to CVE

**email** — Professional remediation email:
- Subject line with CVE ID, severity, and affected component
- Executive summary paragraph (non-technical)
- Technical details section with CVSS, EPSS, affected versions, and fix version
- Recommended remediation steps
- Deadline and escalation path

**ticket** — Jira/GitHub issue body:
- Title: `[CVE-YYYY-NNNNN] <component> — <severity>`
- Description with vulnerability summary
- Acceptance criteria (what "done" looks like)
- Linked references (NVD, OSV, vendor advisory)
- Labels/priority mapping from severity

**escalation** — Formal escalation message:
- Reference previous remediation attempts (if `--team` provided, address to them)
- State the current risk exposure clearly
- Request a decision or resource commitment
- Include a deadline and consequence of inaction

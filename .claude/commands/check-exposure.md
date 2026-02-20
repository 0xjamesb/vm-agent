New vulnerability workflow for $ARGUMENTS (treat as a CVE ID).

Run these MCP tools in sequence:

1. `lookup_cve` — get full vulnerability details (severity, CVSS, EPSS, KEV status)
2. `get_affected_assets` — which assets in the environment are exposed
3. For each affected asset, `calculate_risk_score` — contextual business risk
4. For each affected asset, `get_exception` — is there an active risk acceptance?
5. For each affected asset, `find_ticket` — does a remediation ticket already exist?

Then present a prioritized exposure report:

**Summary:** One-paragraph plain-language description of the vulnerability and its risk.

**Affected Assets:** Table of exposed assets sorted by risk_score, showing:
- Asset name, criticality, owner team
- Risk score (0-100) with brief explanation
- SLA deadline
- Ticket status (exists / missing) and exception status (active / none)

**Recommended Actions:** Per-asset action items:
- If exception active → note expiry date, no action needed
- If ticket exists and in SLA → note ticket ID, monitor
- If ticket exists but overdue → flag for escalation
- If no ticket → recommend creating one with suggested priority and assignee
- If risk_score ≥ 80 → flag for immediate escalation to asset owner

Keep the tone factual and actionable. Avoid alarmism but be direct about urgency.

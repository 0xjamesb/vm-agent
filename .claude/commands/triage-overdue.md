Out-of-SLA vulnerability triage workflow. Parse $ARGUMENTS for an optional `--team "Team Name"` filter.

Run these MCP tools in sequence:

1. `get_overdue_findings` — list all open tickets past their SLA due date (pass team filter if provided)
2. For each finding, `get_exception` — is there an active risk acceptance that covers this?
3. For each finding without an exception, `lookup_cve` — re-assess current threat intelligence
4. For each finding without an exception, `calculate_risk_score` — current business risk

Then present a prioritized triage report:

**Overview:** Total count of overdue findings, how many have exceptions, how many need action.

**Findings Requiring Action:** Table sorted by days_overdue descending, showing:
- CVE ID, asset name, owner team
- Days overdue
- Current risk score (re-assessed)
- EPSS score and KEV status (has threat landscape changed?)
- Assignee and ticket ID

**Exceptions on File:** Brief list of findings covered by active risk acceptances with expiry dates.

**Recommended Escalation Path:**
- Group findings by owner team
- For each team: summarize their overdue count and highest risk item
- Suggest using `/draft <CVE-ID> --type escalation --team "<Team>"` for the highest-priority item per team

Keep the tone professional and solution-focused. The goal is to help the analyst decide what to escalate, what to re-accept, and what to close — not just list problems.

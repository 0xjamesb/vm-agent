# VM-Agent

AI-powered vulnerability management MCP server for Claude Code. VM-Agent gives Claude the data tools to run your entire vulnerability remediation workflow — from CVE triage to SLA tracking to escalation drafts — while you stay in one place.

---

## Why VM-Agent

Vulnerability management is time-consuming not because the decisions are hard, but because the data is scattered. An analyst triaging a single CVE typically touches 5–8 different systems: a scanner portal, a ticketing system, a CVE database, a KEV catalog, asset inventory, a communication tool, and approval records. That context-switching kills focus and introduces errors.

VM-Agent consolidates all of that into a single conversational interface. Claude Code calls the right data sources, correlates the information, and generates outputs (risk assessments, tickets, Slack messages, escalation emails) — while the analyst makes the decisions.

**Business impact:**

- **Faster triage:** A new CVE goes from alert to prioritized, owner-assigned ticket in minutes instead of hours
- **Consistent risk scoring:** Every finding is scored with the same formula (CVSS + EPSS + KEV) regardless of who's on shift
- **SLA compliance:** Automated SLA calculation and overdue tracking means nothing slips through quietly
- **Audit trail:** Every tool call is logged for compliance and retrospective review
- **Reduced analyst burnout:** Routine tasks (communication drafts, exception lookups, ticket creation) are handled automatically so analysts focus on judgment calls

---

## How It Works

VM-Agent runs as an [MCP server](https://modelcontextprotocol.io) that Claude Code connects to. The server handles all data — fetching CVEs, querying scanners, reading asset inventory, managing tickets and exceptions — and Claude handles all reasoning and generation. You interact through Claude Code's chat or via slash commands built into this project.

```
You → Claude Code → VM-Agent MCP tools → OSV / CISA KEV / EPSS / Scanner / Ticketing
                 ↓
            Analyst-ready output (risk reports, tickets, communications, triage plans)
```

---

## Installation

```bash
git clone <repo>
cd vm-agent

uv venv
source .venv/bin/activate
uv pip install -e .
```

### Using a Local Model

Claude Code can be pointed at a local [Ollama](https://ollama.com) instance — useful for air-gapped environments or when data sensitivity prevents cloud API use.

```bash
brew install ollama
ollama serve
ollama pull qwen3-coder   # recommended; also: llama3.3, mistral-small3.1
```

```bash
# Current session
export ANTHROPIC_BASE_URL=http://localhost:11434/v1
export ANTHROPIC_AUTH_TOKEN=ollama
claude

# Or persist in ~/.claude/settings.json
```
```json
{
  "env": {
    "ANTHROPIC_BASE_URL": "http://localhost:11434/v1",
    "ANTHROPIC_AUTH_TOKEN": "ollama"
  }
}
```

> Claude Code requires a minimum 64k token context window. See [Ollama's Claude Code docs](https://docs.ollama.com/integrations/claude-code) for tested models.

---

## Connecting to Claude Code

### Option 1: Direct (development)

The project includes `.mcp.json` at the root — Claude Code picks it up automatically when you open the project folder.

```bash
# Or register manually
claude mcp add --transport stdio vm-agent -- python mcp_server.py
```

### Option 2: Docker (recommended for production)

```bash
docker build -t vm-agent-mcp .
claude mcp add --transport stdio vm-agent -- docker run --rm -i vm-agent-mcp
```

### Option 3: Shared HTTP server (team deployment)

```bash
# Start a persistent server
docker compose up

# Each team member registers it once
claude mcp add --transport http vm-agent http://vm-agent-server:8080/mcp
```

---

## Analyst Workflows

### New Vulnerability Workflow

When a CVE drops, run `/check-exposure` to go from alert to prioritized action plan:

```
/check-exposure CVE-2021-23337
```

Claude will:
1. Fetch full CVE details, EPSS score, and KEV status
2. Query the scanner to find every internal asset running the affected package
3. Calculate business risk per asset (vuln severity × asset criticality)
4. Check for existing tickets or active risk exceptions
5. Produce a prioritized exposure summary with recommended next action per asset

**Example output:**
```
CVE-2021-23337 (lodash) — CRITICAL, EPSS 0.89, in CISA KEV

Exposed Assets (2):
  1. asset-auth-service [CRITICAL asset] — Risk score: 95/100
     Owner: Auth Team | No ticket | No exception
     Recommendation: Create ticket immediately, SLA: 1 day (KEV)
  2. asset-customer-portal [HIGH asset] — Risk score: 71/100
     Owner: Frontend Team | No ticket | No exception
     Recommendation: Create ticket, SLA: 3 days (KEV)
```

---

### Out-of-SLA Triage Workflow

For weekly SLA reviews, `/triage-overdue` surfaces everything past due and tells you what to do with it:

```
/triage-overdue
/triage-overdue --team "Payments"
```

Claude will:
1. Pull all open tickets past their SLA due date (optionally filtered by team)
2. Check each for active risk exceptions
3. Re-assess current threat intelligence on findings without exceptions
4. Produce a prioritized action plan grouped by team with escalation suggestions

---

## Slash Commands

| Command | Purpose |
|---------|---------|
| `/check-exposure <CVE-ID>` | Full exposure analysis for a new CVE |
| `/triage-overdue [--team "Name"]` | Prioritized report of all out-of-SLA findings |
| `/justify <CVE-ID>` | Business justification for remediation (for leadership) |
| `/draft <CVE-ID> --type <slack\|email\|ticket\|escalation>` | Draft a targeted communication |

**Example `/draft` usage:**
```
/draft CVE-2024-3094 --type slack --team "Backend Team" --urgency high
/draft CVE-2024-3094 --type email --team "Engineering Lead"
/draft CVE-2024-3094 --type ticket
/draft CVE-2024-3094 --type escalation --team "VP Engineering"
```

---

## MCP Tools Reference

### CVE Intelligence

| Tool | Description |
|------|-------------|
| `lookup_cve(cve_id)` | Fetch CVE from OSV.dev enriched with CISA KEV status and EPSS score |
| `check_package(ecosystem, package, version?)` | All vulnerabilities affecting a package, sorted by priority |
| `get_high_priority_vulns(limit?)` | Recent KEV additions and high-EPSS CVEs, sorted by priority score |
| `get_kev_recent(days?)` | CVEs recently added to the CISA Known Exploited Vulnerabilities catalog |

### Exposure Analysis

| Tool | Description |
|------|-------------|
| `get_affected_assets(cve_id)` | Assets exposed to a CVE, enriched with criticality and owner info |
| `get_asset_vulnerabilities(asset_id, min_severity?)` | All open findings on an asset with SLA deadlines |
| `calculate_risk_score(cve_id, asset_id)` | Business risk score (0–100) combining vuln priority and asset criticality |

### Asset Registry

| Tool | Description |
|------|-------------|
| `get_asset(asset_id)` | Asset details: name, criticality, owner team, compliance scope |
| `list_assets(team?, ecosystem?)` | List assets with optional filters |
| `register_asset(...)` | Add or update an asset in the registry |

### Remediation Workflow

| Tool | Description |
|------|-------------|
| `get_sla_deadline(severity, in_kev?)` | SLA deadline for a given severity, with policy explanation |
| `find_ticket(cve_id, asset_id)` | Check if a remediation ticket already exists |
| `create_remediation_ticket(cve_id, asset_id, priority?)` | Create a ticket (deduplicates automatically) |
| `get_overdue_findings(team?, days_overdue?)` | All open tickets past SLA, sorted by most overdue |
| `get_exception(cve_id, asset_id)` | Check for an active risk acceptance exception |
| `record_exception(cve_id, asset_id, reason, approved_by, expires_days?)` | Record an approved risk exception |

---

## SLA Policy

| Severity | Standard | In CISA KEV |
|----------|----------|-------------|
| CRITICAL | 7 days | 24 hours |
| HIGH | 14 days | 3 days |
| MEDIUM | 30 days | 7 days |
| LOW | 90 days | 14 days |

SLA defaults follow industry standard (CIS, NIST 800-40). The policy is configurable in `config/sla.py`.

---

## Priority Scoring

Each vulnerability gets a 0–100 `priority_score`:

| Component | Max Points |
|-----------|-----------|
| CVSS score × 4 | 40 |
| EPSS score × 30 | 30 |
| CISA KEV membership | +30 |

Business risk score further multiplies by asset criticality (CRITICAL=2.0×, HIGH=1.5×, MEDIUM=1.0×, LOW=0.5×), capped at 100.

---

## Architecture

```
mcp_server.py                   FastMCP entry point (stdio or HTTP)
tools/
  cve.py                        CVE intelligence tools
  scanner.py                    Exposure analysis tools
  assets.py                     Asset registry tools
  remediation.py                Remediation workflow tools
integrations/
  cve_sources/
    osv.py                      OSV.dev API client
    cisa_kev.py                 CISA KEV catalog (1-hour cache)
    epss.py                     EPSS exploitation probability
  scanners/
    mock_scanner.py             Mock scanner (seeded with realistic data)
    base.py                     Scanner ABC
  assets/
    registry.py                 Asset inventory (JSON persistence)
  exceptions/
    registry.py                 Risk exception registry (JSON persistence)
  ticketing/
    mock_tickets.py             Mock ticketing system
    base.py                     Ticketing ABC
models/                         Vulnerability, Asset, RemediationTask data models
security/
  validation.py                 Input validation and ecosystem canonical casing
  sanitization.py               Output sanitization and prompt injection defense
  audit.py                      JSON Lines audit logging
config/
  settings.py                   Configuration
  sla.py                        SLA policy (configurable)
data/                           Persistent JSON stores (assets, exceptions, tickets)
.claude/commands/               Slash command definitions
```

---

## Data Sources

| Source | Purpose | Auth |
|--------|---------|------|
| [OSV.dev](https://osv.dev) | Primary vulnerability data | None |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Active exploitation catalog | None |
| [EPSS](https://www.first.org/epss) | Exploitation probability scores | None |

---

## Running the Server Directly

```bash
# stdio (default — used by Claude Code)
python mcp_server.py

# HTTP (persistent server)
python mcp_server.py --transport streamable-http --port 8080

# Environment variable
MCP_TRANSPORT=streamable-http MCP_PORT=8080 python mcp_server.py
```

---

## Security

All external data is validated, sanitized, and audit-logged before use. See [docs/SECURITY.md](docs/SECURITY.md) for details on input validation, output sanitization, prompt injection defenses, and audit logging.

---

## Development

```bash
# Run tests
pytest

# Lint
ruff check .

# Verify MCP tools are registered
claude mcp list
```

### Project Structure

The codebase is intentionally layered so each piece can be tested and replaced independently:

- **`tools/`** — thin MCP wrappers: validate input, call integrations, sanitize output
- **`integrations/`** — data clients: scanners, ticketing, asset registry, CVE sources
- **`models/`** — shared data models (Pydantic/dataclasses)
- **`security/`** — validation and sanitization (not tied to any tool or integration)
- **`config/`** — settings and SLA policy

---

## Contributing

VM-Agent is built to be extended. The gap between a mock scanner and real scanner data is a single class implementing `ScannerBase` — same for ticketing. If your team uses Qualys, Nessus, Wiz, Jira, or ServiceNow, a PR adding that integration makes this useful for everyone.

**Where to contribute:**

- **Real scanner integrations:** `integrations/scanners/` — implement `ScannerBase`, add credentials to `config/settings.py`
- **Real ticketing integrations:** `integrations/ticketing/` — implement `TicketingBase`
- **New MCP tools:** Add to `tools/`, register in `mcp_server.py`, add tests
- **New slash commands:** Add `.md` files to `.claude/commands/`
- **SLA policy variants:** `config/sla.py` — organizations often have different defaults by compliance regime

**To get started:**

```bash
git clone <repo>
cd vm-agent
uv pip install -e ".[dev]"
pytest          # all tests should pass before and after your change
```

Open a PR with tests for any new integration or tool. The bar is: does it pass `pytest`, and does `claude mcp list` still show all tools?

---

## Roadmap

- [x] CVE intelligence (OSV, CISA KEV, EPSS)
- [x] Mock scanner with seeded exposure data
- [x] Asset registry with criticality and owner tracking
- [x] SLA policy and overdue detection
- [x] Risk exception registry
- [x] End-to-end analyst workflow (new CVE + out-of-SLA)
- [ ] Qualys / Nessus / Wiz scanner integrations
- [ ] Jira / ServiceNow ticketing integrations
- [ ] Notification integrations (Slack, PagerDuty)
- [ ] Trend analysis and patch velocity metrics
- [ ] SBOM ingestion and dependency graph

---

## License

AGPL-3.0 — See LICENSE for details.

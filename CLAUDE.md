# VM-Agent — MCP Server

AI-powered vulnerability management MCP server. Exposes CVE intelligence, exposure analysis, asset registry, and remediation workflow tools that Claude Code calls directly. Claude handles all reasoning, justification, and communication drafting.

## Architecture

```
mcp_server.py               → FastMCP server entry point (stdio or HTTP)
tools/
  cve.py                    → CVE intelligence tools
  scanner.py                → Exposure analysis tools
  assets.py                 → Asset registry tools
  remediation.py            → Ticket, SLA, exception tools
integrations/
  cve_sources/osv.py        → OSV.dev API client
  cve_sources/cisa_kev.py   → CISA KEV catalog (1-hour cache)
  cve_sources/epss.py       → EPSS exploitation probability API
  assets/registry.py        → JSON-persisted asset registry (data/assets.json)
  exceptions/registry.py    → JSON-persisted exception registry (data/exceptions.json)
  scanners/mock_scanner.py  → Mock scanner with seeded findings (real clients: future)
  ticketing/mock_tickets.py → Mock ticketing with JSON persistence (data/tickets.json)
models/
  vulnerability.py          → Vulnerability dataclass + priority scoring (CVSS+EPSS+KEV → 0-100)
  asset.py                  → Asset dataclass with criticality levels
  remediation.py            → RemediationTask tracking model
security/
  validation.py             → Input validation (CVE IDs, package names, ecosystems)
  sanitization.py           → Output sanitization (HTML stripping, URL validation)
  prompt_defense.py         → Prompt injection defense with trust boundary markers
  audit.py                  → JSON Lines audit log at ./data/audit.log
config/
  settings.py               → Settings dataclass, get_settings() singleton
  sla.py                    → SLA policy (severity + KEV → days to remediate)
```

## MCP Tools (16 total)

### CVE Intelligence
| Tool | Description |
|------|-------------|
| `lookup_cve(cve_id)` | Fetch a CVE from OSV + enrich with CISA KEV and EPSS |
| `check_package(ecosystem, package, version?)` | All vulns for a package, sorted by priority |
| `get_high_priority_vulns(limit?)` | Recent KEV + high-EPSS CVEs |
| `get_kev_recent(days?)` | Recent CISA KEV additions |

### Exposure Analysis
| Tool | Description |
|------|-------------|
| `get_affected_assets(cve_id)` | Which assets in the environment are exposed to this CVE |
| `get_asset_vulnerabilities(asset_id, min_severity?)` | All open findings on an asset with SLA deadlines |
| `calculate_risk_score(cve_id, asset_id)` | CVE priority × asset criticality → business risk score (0-100) |

### Asset Registry
| Tool | Description |
|------|-------------|
| `get_asset(asset_id)` | Fetch asset details (owner, criticality, compliance scope) |
| `list_assets(team?, ecosystem?)` | List all assets with optional filters |
| `register_asset(id, name, criticality, ...)` | Add or update an asset |

### Remediation Workflow
| Tool | Description |
|------|-------------|
| `find_ticket(cve_id, asset_id)` | Check for existing remediation ticket |
| `create_remediation_ticket(cve_id, asset_id, priority?, assignee?)` | Create ticket (skips if exists) |
| `get_sla_deadline(severity, in_kev?)` | Compute SLA due date from policy |
| `get_overdue_findings(team?, days_overdue?)` | Open tickets past SLA — entry point for out-of-SLA workflow |
| `get_exception(cve_id, asset_id)` | Check for active risk acceptance |
| `record_exception(cve_id, asset_id, reason, approved_by, expires_days?)` | Record risk acceptance |

## Skills (Slash Commands)

| Skill | Workflow |
|-------|----------|
| `/check-exposure <CVE-ID>` | **New vulnerability workflow** — lookup → find exposed assets → risk score → ticket/exception status → recommended actions |
| `/triage-overdue [--team "Name"]` | **Out-of-SLA workflow** — list overdue findings → re-assess risk → escalation path per team |
| `/justify <CVE-ID>` | Business justification for remediation prioritization |
| `/draft <CVE-ID> --type <slack\|email\|ticket\|escalation> [--team <name>]` | Draft communication to asset owner |

## SLA Policy (configurable in config/sla.py)

| Severity | KEV? | SLA |
|----------|------|-----|
| CRITICAL | Yes  | 24 hours |
| CRITICAL | No   | 7 days |
| HIGH     | Yes  | 3 days |
| HIGH     | No   | 14 days |
| MEDIUM   | Yes  | 7 days |
| MEDIUM   | No   | 30 days |
| LOW      | Yes  | 14 days |
| LOW      | No   | 90 days |

## Priority & Risk Scoring

**Vulnerability priority score (0-100):**
- CVSS score × 4 → 0–40 pts
- EPSS score × 30 → 0–30 pts
- CISA KEV membership → +30 pts

**Business risk score (0-100):**
- `min(vuln_priority × asset_criticality_multiplier, 100)`
- Criticality multipliers: CRITICAL=2.0, HIGH=1.5, MEDIUM=1.0, LOW=0.5

## Sample Data

The system seeds realistic data on first run:
- **5 sample assets** (Payment API, Auth Service, Data Pipeline, Customer Portal, Internal Tools)
- **8 scanner findings** linking real CVEs to sample assets across npm and PyPI

## Running the Server

```bash
python mcp_server.py                                      # stdio
python mcp_server.py --transport streamable-http          # HTTP :8080
docker run --rm -i vm-agent-mcp                           # Docker stdio
docker compose up                                         # Docker HTTP (persistent)
```

## Development Setup

```bash
uv venv && source .venv/bin/activate
uv pip install -e ".[dev]"
```

## Testing

```bash
pytest                           # All tests
pytest tests/test_security.py    # Security controls
pytest tests/test_models.py      # Data models
pytest tests/test_osv_client.py  # OSV integration (async)
ruff check .                     # Lint
```

## External APIs (all free, no auth)

| API | URL |
|-----|-----|
| OSV.dev | `https://api.osv.dev/v1` |
| CISA KEV | CISA JSON feed |
| EPSS | `https://api.first.org/data/v1/epss` |

## Roadmap

- [ ] Real scanner clients: Qualys, Nessus/Tenable, OpenVAS, Wiz
- [ ] Real ticketing clients: Jira, ServiceNow, GitHub Issues
- [ ] SQLite cache layer (replace in-memory/JSON caches)
- [ ] Passive intelligence from lookup history
- [ ] Asset owner lookup (Backstage, PagerDuty service catalog)
- [ ] Exploit availability enrichment (ExploitDB, Metasploit)

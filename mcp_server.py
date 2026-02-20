"""VM-Agent MCP Server.

Exposes vulnerability management tools as MCP tools that Claude Code can call directly:
- CVE intelligence: lookup, package scan, KEV triage
- Exposure analysis: affected assets, asset vulnerabilities, risk scoring
- Asset registry: get, list, register assets
- Remediation: tickets, SLA deadlines, exceptions, overdue findings

Transports:
  stdio (default)         — Claude Code spawns this as a subprocess
  streamable-http         — Persistent server for shared/team use

Usage:
  python mcp_server.py                                         # stdio
  python mcp_server.py --transport streamable-http --port 8080 # HTTP
  docker run --rm -i vm-agent-mcp                              # stdio via Docker
  docker run -p 8080:8080 vm-agent-mcp --transport streamable-http  # HTTP via Docker
"""

from __future__ import annotations

import argparse
import os

from fastmcp import FastMCP

from tools.cve import check_package, get_high_priority_vulns, get_kev_recent, lookup_cve
from tools.scanner import calculate_risk_score, get_affected_assets, get_asset_vulnerabilities
from tools.assets import get_asset, list_assets, register_asset
from tools.remediation import (
    create_remediation_ticket,
    find_ticket,
    get_exception,
    get_overdue_findings,
    get_sla_deadline,
    record_exception,
)

mcp = FastMCP(
    "vm-agent",
    description=(
        "Vulnerability management MCP server. CVE intelligence (OSV, CISA KEV, EPSS), "
        "exposure analysis, asset registry, SLA tracking, and remediation workflow tools."
    ),
)

# CVE intelligence
mcp.tool()(lookup_cve)
mcp.tool()(check_package)
mcp.tool()(get_high_priority_vulns)
mcp.tool()(get_kev_recent)

# Exposure analysis
mcp.tool()(get_affected_assets)
mcp.tool()(get_asset_vulnerabilities)
mcp.tool()(calculate_risk_score)

# Asset registry
mcp.tool()(get_asset)
mcp.tool()(list_assets)
mcp.tool()(register_asset)

# Remediation workflow
mcp.tool()(find_ticket)
mcp.tool()(create_remediation_ticket)
mcp.tool()(get_sla_deadline)
mcp.tool()(get_overdue_findings)
mcp.tool()(get_exception)
mcp.tool()(record_exception)


def main() -> None:
    parser = argparse.ArgumentParser(description="VM-Agent MCP Server")
    parser.add_argument(
        "--transport",
        default=os.getenv("MCP_TRANSPORT", "stdio"),
        choices=["stdio", "streamable-http"],
        help="Transport type (default: stdio)",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_HOST", "0.0.0.0"),
        help="Host for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.getenv("MCP_PORT", "8080")),
        help="Port for HTTP transport (default: 8080)",
    )
    args = parser.parse_args()

    if args.transport == "streamable-http":
        mcp.run(transport="streamable-http", host=args.host, port=args.port)
    else:
        mcp.run()  # stdio


if __name__ == "__main__":
    main()

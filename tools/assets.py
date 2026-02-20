"""MCP tools for asset registry management."""

from __future__ import annotations

from integrations.assets.registry import AssetRegistry
from models.asset import Asset, AssetCriticality
from security.audit import AuditLogger
from security.validation import InputValidator, ValidationError

_validator = InputValidator()
_audit = AuditLogger.get_instance()


def _asset_to_dict(asset: Asset) -> dict:
    return {
        "id": asset.id,
        "name": asset.name,
        "description": asset.description,
        "owner_team": asset.owner_team,
        "owner_contact": asset.owner_contact,
        "criticality": asset.criticality.value,
        "criticality_multiplier": asset.criticality_multiplier,
        "ecosystem": asset.ecosystem,
        "dependencies": asset.dependencies,
        "compliance_scope": asset.compliance_scope,
        "data_classification": asset.data_classification,
    }


async def get_asset(asset_id: str) -> dict:
    """
    Fetch details for a specific asset from the registry.

    Returns asset metadata including owner team, criticality, ecosystem,
    compliance scope, and data classification.

    Args:
        asset_id: Asset identifier (e.g. asset-payment-api)
    """
    _audit.log_user_input("tool_call", "get_asset", validation_passed=True, input_length=len(asset_id))

    registry = AssetRegistry()
    asset = registry.get_asset(asset_id)

    if not asset:
        return {"error": f"Asset '{asset_id}' not found", "asset_id": asset_id}

    return _asset_to_dict(asset)


async def list_assets(team: str = "", ecosystem: str = "") -> list[dict]:
    """
    List all assets in the registry, optionally filtered by team or ecosystem.

    Results are sorted by criticality (CRITICAL first).

    Args:
        team: Filter by owner team name (partial match, case-insensitive)
        ecosystem: Filter by package ecosystem (npm, PyPI, Go, etc.)
    """
    _audit.log_user_input("tool_call", "list_assets", validation_passed=True, input_length=len(team + ecosystem))

    registry = AssetRegistry()
    assets = registry.list_assets(team=team, ecosystem=ecosystem)
    return [_asset_to_dict(a) for a in assets]


async def register_asset(
    id: str,
    name: str,
    criticality: str = "MEDIUM",
    owner_team: str = "",
    owner_contact: str = "",
    ecosystem: str = "",
    compliance_scope: list[str] | None = None,
    data_classification: str = "",
    description: str = "",
) -> dict:
    """
    Add or update an asset in the registry.

    Use this to track a service, application, or infrastructure component
    that is in scope for vulnerability management.

    Args:
        id: Unique identifier (e.g. asset-payment-api, use kebab-case)
        name: Human-readable name (e.g. Payment API)
        criticality: CRITICAL, HIGH, MEDIUM, or LOW
        owner_team: Team responsible for this asset (e.g. Payments)
        owner_contact: Email or Slack handle for the owner
        ecosystem: Primary package ecosystem (npm, PyPI, Go, etc.)
        compliance_scope: Compliance frameworks in scope (e.g. ["PCI-DSS", "SOC2"])
        data_classification: Data sensitivity (e.g. PII, Financial, Internal)
        description: Brief description of what this asset does
    """
    try:
        criticality_enum = AssetCriticality(criticality.upper())
    except ValueError:
        valid = [c.value for c in AssetCriticality]
        return {"error": f"Invalid criticality '{criticality}'. Valid values: {valid}"}

    if ecosystem:
        try:
            ecosystem = _validator.validate_ecosystem(ecosystem)
        except ValidationError as e:
            return {"error": str(e)}

    _audit.log_user_input("tool_call", "register_asset", validation_passed=True, input_length=len(id + name))

    asset = Asset(
        id=id,
        name=name,
        description=description,
        owner_team=owner_team or None,
        owner_contact=owner_contact or None,
        criticality=criticality_enum,
        ecosystem=ecosystem or None,
        compliance_scope=compliance_scope or [],
        data_classification=data_classification or None,
    )

    registry = AssetRegistry()
    saved = registry.upsert_asset(asset)
    return {**_asset_to_dict(saved), "saved": True}

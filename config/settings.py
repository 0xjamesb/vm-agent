"""Application settings and configuration."""

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class Settings:
    """Application settings."""

    # Data directories
    data_dir: Path = field(default_factory=lambda: Path("./data"))
    cache_dir: Path = field(default_factory=lambda: Path("./data/cache"))

    # Integration settings
    osv_timeout: float = 30.0
    cisa_kev_cache_ttl: int = 3600  # 1 hour
    epss_timeout: float = 30.0

    # MCP server settings
    mcp_host: str = field(default_factory=lambda: os.getenv("MCP_HOST", "0.0.0.0"))
    mcp_port: int = field(default_factory=lambda: int(os.getenv("MCP_PORT", "8080")))

    def __post_init__(self):
        """Ensure directories exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @property
    def tickets_path(self) -> Path:
        """Path to mock tickets storage."""
        return self.data_dir / "tickets.json"

    @property
    def assets_path(self) -> Path:
        """Path to assets storage."""
        return self.data_dir / "assets.json"


_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create application settings."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings

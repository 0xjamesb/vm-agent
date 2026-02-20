FROM python:3.13-slim

WORKDIR /app

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv

# Copy dependency spec first for layer caching
COPY pyproject.toml .

# Copy source
COPY . .

# Install package and dependencies
RUN uv pip install --system -e .

# Create data directory for audit logs and cache
RUN mkdir -p /app/data/cache

# Default: stdio transport (Claude Code spawns this as a subprocess)
# Override for HTTP: docker run -p 8080:8080 vm-agent-mcp --transport streamable-http
ENTRYPOINT ["python", "mcp_server.py"]

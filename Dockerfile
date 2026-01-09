FROM python:3.12-slim

WORKDIR /app

# Install basic dependencies
RUN pip install requests

# Copy source code
COPY src /app/src
COPY config /app/config

# Set environment variables
ENV AGENT_ID="cli-agent-01"
ENV PROXY_URL="http://egress-proxy:8080"

# Default command (can be overridden)
CMD ["python", "src/demo_cli_agent.py"]

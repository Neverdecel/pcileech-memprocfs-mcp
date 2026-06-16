# Container image for the pcileech-memprocfs-mcp server.
#
# The MCP server speaks over stdio, so an MCP client launches the container
# with `docker run -i`. DMA over a USB FPGA needs USB access from the host,
# so pass the device through (or use --privileged for full access).
#
# Build:
#   docker build -t pcileech-memprocfs-mcp .
#
# Run with a USB FPGA (hardware):
#   docker run --rm -i --device=/dev/bus/usb pcileech-memprocfs-mcp
#
# Run against a memory dump (no hardware):
#   docker run --rm -i \
#     -e PCILEECH_MCP_CONFIG=/data/config.json \
#     -v /path/on/host:/data:ro \
#     pcileech-memprocfs-mcp

FROM python:3.12-slim

# Runtime shared libraries that memprocfs / leechcorepyc load at runtime.
RUN apt-get update && apt-get install -y --no-install-recommends \
        libusb-1.0-0 \
        libfuse2 \
        liblz4-1 \
        libssl3 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

RUN pip install --no-cache-dir .

# stdio MCP server entry point (see [project.scripts] in pyproject.toml).
ENTRYPOINT ["pcileech-memprocfs-mcp"]

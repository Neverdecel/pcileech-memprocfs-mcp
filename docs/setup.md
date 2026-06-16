# Setup Guide

## Prerequisites

### Hardware

You need a PCILeech-compatible FPGA DMA device:
- [LambdaConcept Screamer](https://shop.lambdaconcept.com/)
- ZDMA / Squirrel
- Or any other [supported device](https://github.com/ufrisk/pcileech#supported-devices)

The device must be connected via USB to the Linux machine running this MCP server.

### Software

- **Linux x86_64** (tested on Ubuntu 22.04+)
- **Python 3.10+**
- **USB access** — your user must have permission to access the FPGA USB device

### USB Permissions

If you get permission errors, create a udev rule:

```bash
# Find your device's vendor/product ID
lsusb | grep -i "FTDI\|Future"

# Create udev rule (adjust idVendor/idProduct)
sudo tee /etc/udev/rules.d/99-fpga-dma.rules << 'EOF'
SUBSYSTEM=="usb", ATTR{idVendor}=="0403", ATTR{idProduct}=="601f", MODE="0666"
EOF

sudo udevadm control --reload-rules
sudo udevadm trigger
```

## Installation

```bash
# Clone
git clone https://github.com/Neverdecel/pcileech-memprocfs-mcp.git
cd pcileech-memprocfs-mcp

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### System libraries (if pip install fails)

```bash
sudo apt install libusb-1.0-0-dev libfuse-dev openssl libssl-dev liblz4-dev
```

## Configuration

Edit `config.json`:

```json
{
  "device": {
    "type": "fpga",
    "remote": "",
    "extra_args": []
  }
}
```

### Device types

| Type | Use case |
|---|---|
| `"fpga"` | Local FPGA device via USB (most common) |
| `"file:///path/to/dump.raw"` | Analyze a memory dump file |
| `"fpga"` + `"remote": "rpc://user@host"` | Remote device via LeechAgent |

### Extra args

Passed directly to `memprocfs.Vmm()`. Useful options:

| Arg | Description |
|---|---|
| `"-v"` | Verbose output |
| `"-printf"` | Enable printf output |
| `"-waitinitialize"` | Wait for full OS analysis before returning |

## Adding to Claude Code

### Option 1: CLI (recommended)

```bash
claude mcp add -s user pcileech-memprocfs-mcp -- \
  /full/path/to/.venv/bin/python \
  /full/path/to/main.py
```

### Option 2: Manual config

Add to `~/.claude.json`:

```json
{
  "mcpServers": {
    "pcileech-memprocfs-mcp": {
      "command": "/full/path/to/.venv/bin/python",
      "args": ["/full/path/to/main.py"]
    }
  }
}
```

Restart Claude Code after adding.

## Verify

After restarting Claude Code, the 15 tools should appear. Ask Claude:

```
Use system_info to check if the DMA device is connected
```

If no hardware is connected, you'll see:
```
PCILeech error: Failed to initialize MemProcFS: Vmm.init(): Initialization of vmm failed.
```

This confirms the MCP server is running — it just can't reach hardware.

## Testing without hardware

```bash
source .venv/bin/activate
python test_server.py
```

Runs 66 unit tests using mocks. No DMA device needed.

## Troubleshooting

### "Failed to initialize MemProcFS"
- Check that your FPGA device is connected and powered
- Check USB permissions (see udev rules above)
- Try `lsusb` to confirm the device is visible

### "memprocfs package not installed"
- Make sure you're using the venv Python: `.venv/bin/python main.py`
- Re-run `pip install -r requirements.txt` inside the venv

### "leechcorepyc package not installed"
- Same as above — ensure venv is activated

### Tools not showing in Claude Code
- Verify the MCP is registered: `claude mcp list`
- Check paths are absolute in the MCP config
- Restart Claude Code after any config changes

# nevercheese-pcileech-memprocfs-mcp

[![CI](https://github.com/Neverdecel/nevercheese-pcileech-memprocfs-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/Neverdecel/nevercheese-pcileech-memprocfs-mcp/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/nevercheese-pcileech-memprocfs-mcp.svg)](https://pypi.org/project/nevercheese-pcileech-memprocfs-mcp/)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: AGPL-3.0](https://img.shields.io/badge/license-AGPL--3.0-green.svg)](LICENSE)

A Linux-native [Model Context Protocol](https://modelcontextprotocol.io/) server that gives AI assistants direct access to DMA-based memory operations through [PCILeech](https://github.com/ufrisk/pcileech) / [MemProcFS](https://github.com/ufrisk/MemProcFS).

**37 tools** for memory inspection, process analysis, reverse engineering, and game engine SDK extraction — all through natural language.

## Why this exists

DMA hardware lets you read and write the memory of a target system from an external machine over PCIe. This project turns that capability into an MCP server so AI assistants can operate it directly — no manual CLI interaction, no copy-pasting hex dumps.

**What you can do with it:**

- **Inspect live memory** — read, write, search, dump, and diff memory regions on a target system
- **Analyze processes** — enumerate processes, modules, exports, imports, PE sections, memory regions
- **Reverse engineer binaries** — scan for byte patterns, resolve code signatures, discover RTTI class hierarchies
- **Discover pointer chains** — find stable paths from module bases to dynamic addresses
- **Find cross-references** — locate all code and data references to any address in a module
- **Dump game engine SDKs** — extract full C++ SDKs from Unreal Engine 4/5 games via reflection
- **Extract Unity metadata** — dump IL2CPP class definitions from Unity games automatically
- **Control FPGA hardware** — benchmark DMA speed, send raw PCIe TLPs, read/write config space

## Key features

### Native Linux implementation

Built on the `memprocfs` and `leechcorepyc` Python packages directly — no subprocess wrapping, no text parsing, no Windows dependency.

| | [Original](https://github.com/evan7198/mcp_server_pcileech) | This project |
|---|---|---|
| Platform | Windows only | Linux native |
| Backend | Subprocess → `pcileech.exe` | Native Python API |
| Read size | 256-byte chunks | Up to 1MB direct |
| Connection | New process per op | Persistent handle |
| Tools | 9 | 37 |

### Game reverse engineering

Go from "I have a DMA device connected to a game" to a full SDK without touching a disassembler:

```
1. "List processes"                           → find the game PID
2. "List modules for game.exe"                → find module bases
3. "Scan for RTTI classes in game.exe"        → discover class names + vtables
4. "Find the GNames signature in game.exe"    → locate UE globals
5. "Dump the UE5 SDK with GNames and GObjects"→ generate C++ headers
```

### Pointer chain discovery

Found a dynamic address that changes every restart? Find the static chain:

```
"Find pointer chains from module bases to 0x1a2b3c4d in game.exe"
→ [[game.exe+0x1234]+0x10]+0x48   (depth 2)
→ [[game.exe+0x5678]+0x20]+0x100  (depth 2)
```

### Cross-reference scanning

Find every instruction and data pointer that references an address:

```
"Find all xrefs to 0x7ff6a013580 in game.exe"
→ Code: 0x7ff6a012345 [rip_rel_7] 48 8b 05 35 12 00 00  (.text)
→ Data: 0x7ff6a101000 (.rdata)
```

### Engine-specific tools

| Engine | Tools | What you get |
|---|---|---|
| **Unreal Engine 4/5** | `ue_dump_names` → `ue_dump_objects` → `ue_dump_sdk` | FName table, UObject list, C++ SDK headers with field offsets |
| **Unity (IL2CPP)** | `unity_il2cpp_dump` | C# class definitions with fields, methods, and offsets — fully automatic |

## Tools (37)

| Category | Count | Tools |
|---|---|---|
| **Core Memory** | 4 | `memory_read` `memory_write` `memory_format` `scatter_read` |
| **System** | 6 | `system_info` `memory_probe` `memory_dump` `memory_search` `memory_patch`\* `process_list` |
| **Address Translation** | 2 | `translate_virt2phys` `process_virt2phys` |
| **Modules** | 5 | `module_list` `module_dump` `module_exports` `module_imports` `pe_sections` |
| **Game / RE** | 4 | `aob_scan` `signature_resolve` `pointer_read` `process_regions` |
| **Advanced RE** | 4 | `rtti_scan` `struct_analyze` `string_scan` `memory_diff` |
| **Pointer / XRef** | 2 | `pointer_scan` `xref_scan` |
| **Engine Tools** | 4 | `ue_dump_names` `ue_dump_objects` `ue_dump_sdk` `unity_il2cpp_dump` |
| **FPGA** | 3 | `benchmark` `tlp_send` `fpga_config` |
| **Device** | 3 | `device_disconnect` `device_reconnect` `device_status` |

\* `memory_patch` is stubbed — `.sig` files are a CLI-only feature. Use `memory_search` + `memory_write` instead.

Full parameter reference: [`docs/tools.md`](docs/tools.md)
UE signature reference: [`docs/ue_signatures.md`](docs/ue_signatures.md)

## Requirements

- **Linux** (x86_64)
- **Python 3.10+**
- **PCILeech-compatible FPGA hardware** (Screamer, ZDMA, etc.)
- USB drivers configured ([MemProcFS Linux setup](https://github.com/ufrisk/MemProcFS/wiki/_Linux))

## Installation

### Quick start with `uvx` (recommended)

No clone, no virtualenv — run the latest release directly with
[`uv`](https://docs.astral.sh/uv/):

```bash
uvx nevercheese-pcileech-memprocfs-mcp
```

Or install it as a persistent command with `pipx`:

```bash
pipx install nevercheese-pcileech-memprocfs-mcp
```

This uses the default FPGA device config. To point at a custom config (file
dump, remote agent, extra args), set the `PCILEECH_MCP_CONFIG` environment
variable to a JSON file — see [Configuration](#configuration).

### From source

```bash
git clone https://github.com/Neverdecel/nevercheese-pcileech-memprocfs-mcp.git
cd nevercheese-pcileech-memprocfs-mcp

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

System dependencies (if needed):

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

| Field | Description | Examples |
|---|---|---|
| `type` | Device type | `"fpga"`, `"file:///path/to/dump.raw"` |
| `remote` | Remote LeechAgent | `""`, `"rpc://user@host"` |
| `extra_args` | Extra memprocfs args | `["-v", "-printf"]` |

When installed via `uvx`/`pipx`, the bundled `config.json` is read-only. Point
at your own config instead by setting `PCILEECH_MCP_CONFIG=/path/to/config.json`
in the environment (see the env block in the manual MCP config below).

## Adding to Claude Code

**With `uvx`** (no path wrangling):

```bash
claude mcp add -s user nevercheese-pcileech-memprocfs-mcp -- \
  uvx nevercheese-pcileech-memprocfs-mcp
```

**From a source checkout:**

```bash
claude mcp add -s user nevercheese-pcileech-memprocfs-mcp -- \
  /path/to/nevercheese-pcileech-memprocfs-mcp/.venv/bin/python \
  /path/to/nevercheese-pcileech-memprocfs-mcp/main.py
```

Or add to your MCP config manually:

```json
{
  "mcpServers": {
    "nevercheese-pcileech-memprocfs-mcp": {
      "command": "uvx",
      "args": ["nevercheese-pcileech-memprocfs-mcp"],
      "env": {
        "PCILEECH_MCP_CONFIG": "/path/to/config.json"
      }
    }
  }
}
```

## Usage examples

Once connected, use natural language:

**Memory operations**
```
Read 256 bytes from physical address 0x1000
Write 90909090 (NOPs) to 0x7ff7f3a90000 in PID 1234
Search for the MZ header in the first 16MB of memory
Take a snapshot of 256 bytes at 0x1a000000, then diff after taking damage
```

**Process analysis**
```
List all processes on the target system
Show me modules loaded by explorer.exe
Show the exports of engine2.dll in cs2.exe
List PE sections of game.exe with protection flags
```

**Reverse engineering**
```
Scan for AOB pattern "48 8B 05 ?? ?? ?? ?? 48 85 C0" in game.exe
Resolve the signature "48 8D 05 ?? ?? ?? ?? EB 27" to find GNames
Scan for RTTI classes in client.dll
Analyze the struct at address 0x1a000000 — identify field types
```

**Pointer & xref scanning**
```
Find pointer chains from module bases to address 0x1a2b3c4d in PID 1234
Find all code and data references to 0x7ff6a013580 in game.exe
Follow the pointer chain [[game.exe+0x1A8B230]+0x50]+0x100 and read 4 bytes
```

**Engine SDK extraction**
```
Dump the UE5 GNames table at 0x7ff6a500000 from the game process
Generate a C++ SDK from the UE game with GObjects at 0x... and GNames at 0x...
Dump IL2CPP metadata from the Unity game process to /tmp/dump.cs
```

## Testing

```bash
source .venv/bin/activate
python test_server.py
```

164 tests — all use mocks, no hardware needed. Covers tool registration, handler output formatting, and algorithm correctness (pointer scanning, xref scanning with crafted PE binaries). The same suite runs in [CI](.github/workflows/ci.yml) on Python 3.10–3.12.

## Architecture

```
Claude Code / MCP Client
    |
    | (MCP stdio transport)
    |
main.py                 ← 34 tool schemas + async handlers + output formatting
    |
vmm_wrapper.py          ← Device init, memory ops, process/module enumeration
    |
    ├── pointer_scanner.py  ← Pointer chain discovery + cross-reference scanning
    ├── engine_tools.py     ← UE4/UE5 SDK dump + Unity IL2CPP extraction
    |
    ├── memprocfs           ← High-level API: processes, virtual memory, modules
    |     └── vmmpyc.so → libvmm.so → libleechcore.so
    |
    └── leechcorepyc        ← Low-level API: physical memory, FPGA, TLP
          └── leechcore.so
```

## Credits

- **PCILeech / MemProcFS / LeechCore:** [Ulf Frisk](https://github.com/ufrisk)
- **Original MCP concept:** [evan7198/mcp_server_pcileech](https://github.com/evan7198/mcp_server_pcileech)
- **Model Context Protocol:** [Anthropic](https://modelcontextprotocol.io/)

## License

Released under the [GNU AGPL-3.0](LICENSE), matching the copyleft terms of the
**PCILeech / MemProcFS / LeechCore** stack this server builds on. See the
[MemProcFS License](https://github.com/ufrisk/MemProcFS/blob/master/LICENSE) and
[LeechCore License](https://github.com/ufrisk/LeechCore/blob/master/LICENSE).

## Disclaimer

This tool is intended for authorized security research, debugging, and educational purposes only. Do not use it for unauthorized access. You are responsible for complying with all applicable laws.

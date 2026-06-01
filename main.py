#!/usr/bin/env python3
"""
Linux-native MCP Server for PCILeech / MemProcFS.

Uses memprocfs and leechcorepyc Python packages directly instead of
wrapping the pcileech CLI. Provides 37 MCP tools for DMA-based
memory operations via the Model Context Protocol.
"""

import asyncio
import logging
from datetime import datetime
from typing import Any

from mcp.server import Server
from mcp.types import Tool, TextContent

from vmm_wrapper import (
    VmmWrapper,
    PCILeechError,
    DeviceNotFoundError,
    MemoryAccessError,
    SignatureNotFoundError,
    ProbeNotSupportedError,
    KMDError,
    parse_hex_address,
    format_hex_dump,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nevercheese-pcileech-memprocfs-mcp")

wrapper: VmmWrapper | None = None
server = Server("nevercheese-pcileech-memprocfs-mcp")


def get_wrapper() -> VmmWrapper:
    global wrapper
    if wrapper is None:
        try:
            wrapper = VmmWrapper()
        except Exception as e:
            logger.error(f"Failed to initialize wrapper: {e}")
            raise
    return wrapper


def validate_mutually_exclusive(args: dict, *param_names: str) -> str | None:
    provided = [name for name in param_names if args.get(name) is not None]
    if len(provided) > 1:
        return (
            f"Parameters {', '.join(provided)} are mutually exclusive - only one can be specified"
        )
    return None


def format_byte_array(data: bytes) -> str:
    return str(list(data))


def format_dword_array(data: bytes) -> str:
    dwords = []
    for i in range(0, len(data), 4):
        if i + 4 <= len(data):
            dword = int.from_bytes(data[i : i + 4], byteorder="little", signed=False)
            dwords.append(f"0x{dword:08x}")
    return str(dwords)


def format_ascii_view(data: bytes) -> str:
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


def mode_string(pid, process_name) -> str:
    if pid is not None:
        return f"virtual (PID: {pid})"
    if process_name is not None:
        return f"virtual (Process: {process_name})"
    return "physical"


# ==================== Tool Definitions ====================


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        # ==================== Core Memory ====================
        Tool(
            name="memory_read",
            description=(
                "Read raw bytes from the target system's memory via DMA. Returns hex-encoded data. "
                "Use this for programmatic access when you need the raw bytes (e.g. to parse structures, "
                "compare values, or feed into further processing). "
                "For human-readable inspection, prefer memory_format instead. "
                "Reads PHYSICAL memory by default. To read a process's VIRTUAL memory, provide either "
                "pid or process_name (use process_list first to find these)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address in hex format. Examples: '0x1000', '0x7ff6a000'. Physical address unless pid/process_name is set.",
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to read (1 to 1048576 / 1MB)",
                        "minimum": 1,
                        "maximum": 1048576,
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID — switches to virtual address mode. Mutually exclusive with process_name. Use process_list to find PIDs.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name (e.g. 'explorer.exe') — switches to virtual address mode. Mutually exclusive with pid.",
                    },
                },
                "required": ["address", "length"],
            },
        ),
        Tool(
            name="memory_write",
            description=(
                "Write bytes to the target system's memory via DMA. Use this to patch memory, "
                "modify game values, overwrite instructions (e.g. NOP out checks with 0x90), etc. "
                "Writes to PHYSICAL memory by default. To write to a process's VIRTUAL memory, "
                "provide either pid or process_name. "
                "CAUTION: Writing to wrong addresses can crash the target system."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Target memory address in hex. Physical address unless pid/process_name is set.",
                    },
                    "data": {
                        "type": "string",
                        "description": "Data to write as a hex string (2 chars per byte). Examples: '90909090' (4 NOP bytes), '48656c6c6f' ('Hello')",
                        "maxLength": 2097152,
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID for virtual address writes. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name for virtual address writes. Mutually exclusive with pid.",
                    },
                },
                "required": ["address", "data"],
            },
        ),
        Tool(
            name="memory_format",
            description=(
                "Read memory and display it in human-readable formatted views: hex dump with ASCII sidebar, "
                "plain ASCII text, byte arrays, DWORD arrays, or raw hex. "
                "Use this when you want to INSPECT or ANALYZE memory contents visually — it's the best tool "
                "for understanding what's at an address. For raw data to process programmatically, use memory_read instead. "
                "Max 4KB per call. Supports physical and virtual addresses (via pid/process_name)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Memory address in hex. Physical unless pid/process_name is set.",
                    },
                    "length": {
                        "type": "integer",
                        "description": "Number of bytes to read and format (1 to 4096)",
                        "minimum": 1,
                        "maximum": 4096,
                    },
                    "formats": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "enum": ["hexdump", "ascii", "bytes", "dwords", "raw"],
                        },
                        "description": "Which views to include. 'hexdump' = hex + ASCII sidebar, 'ascii' = printable text only, 'bytes' = decimal array, 'dwords' = 32-bit LE integers, 'raw' = continuous hex string. Default: all.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID for virtual address mode. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name for virtual address mode. Mutually exclusive with pid.",
                    },
                },
                "required": ["address", "length"],
            },
        ),
        # ==================== System / Discovery ====================
        Tool(
            name="system_info",
            description=(
                "Get information about the DMA connection, target system, and FPGA device. "
                "Call this FIRST to verify the DMA device is connected and working, identify "
                "the target OS version, and check hardware capabilities. "
                "Set verbose=true to include FPGA hardware details (firmware version, device ID)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "verbose": {
                        "type": "boolean",
                        "description": "Include FPGA firmware version, device ID, and hardware details. Default: false.",
                        "default": False,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="memory_probe",
            description=(
                "Discover which physical memory ranges are readable on the target system. "
                "Use this to understand the target's memory layout before reading — shows RAM regions, "
                "MMIO gaps, and reserved areas. Useful when you don't know what addresses are valid."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "min_address": {
                        "type": "string",
                        "description": "Start of range to probe in hex. Default: '0x0'.",
                        "default": "0x0",
                    },
                    "max_address": {
                        "type": "string",
                        "description": "End of range to probe in hex. Default: auto-detect from memory map.",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="memory_dump",
            description=(
                "Dump a range of physical memory to a file on disk. Use this for large reads that "
                "need to be saved for offline analysis (e.g. dumping a full module, forensic capture). "
                "For small reads you want to inspect inline, use memory_read or memory_format instead. "
                "Max 256MB per dump."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "min_address": {
                        "type": "string",
                        "description": "Start address of dump range in hex",
                    },
                    "max_address": {
                        "type": "string",
                        "description": "End address of dump range in hex",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "File path to save the dump. Auto-generated as dump_<min>-<max>.raw if omitted.",
                    },
                    "force": {
                        "type": "boolean",
                        "description": "If true, zero-pads unreadable regions instead of failing. Useful for dumping ranges that include MMIO holes.",
                        "default": False,
                    },
                },
                "required": ["min_address", "max_address"],
            },
        ),
        Tool(
            name="memory_search",
            description=(
                "Search physical memory for a hex byte pattern. Scans memory in 1MB chunks. "
                "Use this to find signatures, strings, or known byte sequences in the target's memory. "
                "Examples: search for PE headers ('4D5A'), strings (convert ASCII to hex first), "
                "or specific instruction patterns. "
                "To patch what you find, note the address and use memory_write."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Hex byte pattern to search for. No spaces, even length. Examples: '4D5A9000' (MZ header), '48656C6C6F' ('Hello')",
                    },
                    "min_address": {
                        "type": "string",
                        "description": "Start of search range in hex. Default: 0x0.",
                    },
                    "max_address": {
                        "type": "string",
                        "description": "End of search range in hex. Default: 0x100000000 (4GB). Reduce for faster searches.",
                    },
                    "find_all": {
                        "type": "boolean",
                        "description": "If true, find ALL matches. If false (default), stop at first match.",
                        "default": False,
                    },
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="memory_patch",
            description=(
                "NOT YET IMPLEMENTED. Signature-based patching (.sig files) is a pcileech CLI feature "
                "not available through the native API. "
                "INSTEAD: Use memory_search to find the target bytes, then memory_write to overwrite them."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "signature": {
                        "type": "string",
                        "description": "Signature file name (NOT SUPPORTED — use memory_search + memory_write instead)",
                    },
                    "min_address": {"type": "string"},
                    "max_address": {"type": "string"},
                    "patch_all": {"type": "boolean", "default": False},
                },
                "required": ["signature"],
            },
        ),
        Tool(
            name="process_list",
            description=(
                "List all running processes on the TARGET system (the machine connected via DMA, not the local machine). "
                "Returns PID, parent PID, name, and state for each process. "
                "Use this to find a process before reading its virtual memory — you'll need the PID or "
                "process name for memory_read, memory_write, memory_format, and module_list. "
                "Requires the target to be running Windows (MemProcFS performs OS-level analysis)."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        # ==================== Address Translation ====================
        Tool(
            name="translate_virt2phys",
            description=(
                "Translate a virtual address to a physical address using a raw CR3 page table base. "
                "This is a LOW-LEVEL tool — you need to already know the CR3 value. "
                "In most cases, use process_virt2phys instead (it looks up CR3 automatically from the PID)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "virtual_address": {
                        "type": "string",
                        "description": "Virtual address to translate, in hex",
                    },
                    "cr3": {
                        "type": "string",
                        "description": "Page table base register (CR3/DTB) value in hex. Get this from process_list DTB field.",
                    },
                },
                "required": ["virtual_address", "cr3"],
            },
        ),
        Tool(
            name="process_virt2phys",
            description=(
                "Translate a process's virtual address to the corresponding physical address. "
                "Use this when you have a virtual address from a module or disassembly and need the "
                "physical address for direct physical memory access. "
                "Automatically resolves the process page tables — just provide PID and virtual address."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Use process_list to find this.",
                    },
                    "virtual_address": {
                        "type": "string",
                        "description": "Virtual address within the process to translate, in hex",
                    },
                },
                "required": ["pid", "virtual_address"],
            },
        ),
        # ==================== Module Enumeration ====================
        Tool(
            name="module_list",
            description=(
                "List all loaded modules (DLLs/EXEs) for a specific process on the target system. "
                "Shows module name, base address, and size. Use this to find where a module is loaded "
                "in memory before reading or patching it. "
                "Requires pid or process_name — use process_list first to find these."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID to list modules for. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name to list modules for (e.g. 'explorer.exe'). Mutually exclusive with pid.",
                    },
                },
                "required": [],
            },
        ),
        # ==================== Game / RE Tools ====================
        Tool(
            name="aob_scan",
            description=(
                "Array-of-bytes pattern scan with ?? wildcard support in a process's virtual memory. "
                "This is the primary tool for finding code signatures, byte patterns, and instruction "
                "sequences in game/application memory. Supports wildcards for bytes that vary between runs. "
                "Scans all committed memory regions by default, or a specific module if specified. "
                "Example pattern: '48 8B 05 ?? ?? ?? ?? 48 85 C0' to find a mov rax,[rip+??] with test. "
                "Use process_list to find the PID, then optionally module_list to find a module name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Space-separated hex bytes with ?? wildcards. Examples: '4D 5A ?? ?? 50 45', '48 89 5C 24 ?? 57'. Use ?? for unknown bytes.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name. Mutually exclusive with pid.",
                    },
                    "module": {
                        "type": "string",
                        "description": "Restrict scan to this module only (e.g. 'game.exe', 'client.dll'). Much faster than scanning all memory.",
                    },
                    "find_all": {
                        "type": "boolean",
                        "description": "Find all matches. Default: false (stop at first match).",
                        "default": False,
                    },
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="module_dump",
            description=(
                "Dump a complete PE module (EXE/DLL) from a process's memory to disk. "
                "Use this for SDK extraction, reverse engineering in IDA/Ghidra, or offline analysis. "
                "Reads the full module image including PE headers, sections, and data. "
                "Zero-pads any unreadable pages. Use module_list first to find available modules."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name. Mutually exclusive with pid.",
                    },
                    "module_name": {
                        "type": "string",
                        "description": "Name of the module to dump (e.g. 'game.exe', 'client.dll', 'kernel32.dll'). Use module_list to find names.",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Output file path. Default: '<module>_<base>.bin'.",
                    },
                },
                "required": ["module_name"],
            },
        ),
        Tool(
            name="module_exports",
            description=(
                "List all exported functions (Export Address Table) from a loaded module. "
                "Shows function name, ordinal, and virtual address. Essential for finding SDK "
                "function entry points, hooking targets, or understanding a DLL's public API. "
                "Use module_list first to find the module name."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name. Mutually exclusive with pid.",
                    },
                    "module_name": {
                        "type": "string",
                        "description": "Module to read exports from (e.g. 'kernel32.dll', 'ntdll.dll').",
                    },
                },
                "required": ["module_name"],
            },
        ),
        Tool(
            name="module_imports",
            description=(
                "List all imported functions (Import Address Table) from a loaded module. "
                "Shows which DLLs the module depends on and which functions it calls. "
                "Useful for understanding module dependencies, finding cross-references, "
                "and identifying potential hook targets."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name. Mutually exclusive with pid.",
                    },
                    "module_name": {
                        "type": "string",
                        "description": "Module to read imports from (e.g. 'game.exe', 'client.dll').",
                    },
                },
                "required": ["module_name"],
            },
        ),
        Tool(
            name="pointer_read",
            description=(
                "Follow a multi-level pointer chain and read the value at the final address. "
                "Given a base address and a list of offsets, reads: [[base]+offset0]+offset1]+... "
                "This is essential for reading game values that use pointer chains "
                "(e.g. player health at [[game.exe+0x1234]+0x10]+0x48). "
                "Returns the resolved chain, final address, and value."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "base_address": {
                        "type": "string",
                        "description": "Starting address of the pointer chain in hex. Can be a module base + offset (calculate it first using module_list).",
                    },
                    "offsets": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "List of offsets to follow at each pointer level. Example: [0x10, 0x48, 0x20] for a 3-level chain.",
                    },
                    "read_size": {
                        "type": "integer",
                        "description": "Bytes to read at the final address (default: 8). Use 4 for int/float, 8 for int64/double/pointer.",
                        "default": 8,
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name. Mutually exclusive with pid.",
                    },
                },
                "required": ["base_address", "offsets"],
            },
        ),
        Tool(
            name="process_regions",
            description=(
                "List all virtual memory regions (VAD entries) for a process with protection flags. "
                "Shows address, size, protection (RWX), type (Image/Mapped/Private), and associated file. "
                "Use this to understand a process's memory layout, find executable regions, "
                "locate mapped files, or identify suspicious RWX allocations."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Target process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Target process name. Mutually exclusive with pid.",
                    },
                },
                "required": [],
            },
        ),
        # ==================== Advanced RE Tools ====================
        Tool(
            name="scatter_read",
            description=(
                "Batch-read multiple disjoint memory regions in a single DMA operation (~10x faster than "
                "individual reads). Use this when you need to read many separate addresses at once, e.g. "
                "reading multiple struct fields, entity list entries, or pointer chain values. "
                "Each read is specified as {address, size}. Supports physical and virtual memory."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "reads": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "address": {
                                    "type": "string",
                                    "description": "Memory address in hex",
                                },
                                "size": {
                                    "type": "integer",
                                    "description": "Bytes to read (1 to 1MB)",
                                    "minimum": 1,
                                },
                            },
                            "required": ["address", "size"],
                        },
                        "description": "List of memory regions to read. Max 1024 entries.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID for virtual address reads.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name for virtual address reads.",
                    },
                },
                "required": ["reads"],
            },
        ),
        Tool(
            name="pe_sections",
            description=(
                "Enumerate PE sections (.text, .rdata, .data, .bss, etc.) of a loaded module. "
                "Returns section name, virtual address, size, and flags (CODE, READ, WRITE, EXECUTE). "
                "Essential prerequisite for RTTI scanning (needs .rdata), signature scanning (needs .text), "
                "and string scanning (needs .data). Use module_list first to find module names."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "module_name": {
                        "type": "string",
                        "description": "Module to enumerate sections from (e.g. 'game.exe').",
                    },
                },
                "required": ["module_name"],
            },
        ),
        Tool(
            name="signature_resolve",
            description=(
                "Find a byte pattern and resolve the operand to a target address — all in one step. "
                "This is the primary tool for finding game offsets from signatures. "
                "Combines AOB scan + operand extraction + RIP-relative resolution. "
                "Example: pattern '48 8B 05 ?? ?? ?? ??' with op_offset=3, op_length=4, instruction_length=7 "
                "finds a 'mov rax,[rip+disp32]' and resolves the target address. "
                "For non-RIP-relative patterns, set rip_relative=false to get the raw operand value."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "AOB pattern with ?? wildcards (e.g. '48 8B 05 ?? ?? ?? ??')",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "module": {
                        "type": "string",
                        "description": "Module to scan (e.g. 'game.exe'). Highly recommended for speed.",
                    },
                    "op_offset": {
                        "type": "integer",
                        "description": "Byte offset within the matched pattern where the operand starts. Default: 3 (common for RIP-relative instructions).",
                        "default": 3,
                    },
                    "op_length": {
                        "type": "integer",
                        "enum": [1, 2, 4, 8],
                        "description": "Size of the operand in bytes. Default: 4 (32-bit displacement).",
                        "default": 4,
                    },
                    "rip_relative": {
                        "type": "boolean",
                        "description": "If true, resolve as RIP-relative: match_addr + instruction_length + operand. Default: true.",
                        "default": True,
                    },
                    "instruction_length": {
                        "type": "integer",
                        "description": "Total instruction length for RIP-relative resolution. Default: op_offset + op_length.",
                    },
                },
                "required": ["pattern"],
            },
        ),
        Tool(
            name="rtti_scan",
            description=(
                "Scan a module for MSVC C++ RTTI (Run-Time Type Information) to discover class names, "
                "vtable addresses, and inheritance hierarchies — all externally via DMA. "
                "This is one of the most powerful RE tools: it reveals the game's class hierarchy without "
                "needing IDA or static analysis. Works with x64 MSVC-compiled binaries. "
                "Returns: class name, demangled name, TypeDescriptor address, vtable address, base classes. "
                "Use pe_sections first to verify the module has a .rdata section."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "module": {
                        "type": "string",
                        "description": "Module to scan for RTTI (e.g. 'game.exe', 'client.dll'). Required.",
                    },
                    "max_classes": {
                        "type": "integer",
                        "description": "Maximum classes to return (default: 500). Large modules may have thousands.",
                        "default": 500,
                    },
                },
                "required": ["module"],
            },
        ),
        Tool(
            name="struct_analyze",
            description=(
                "Heuristically analyze a memory region to identify likely data types at each offset. "
                "Reads memory and classifies each field as: pointer, vtable_ptr, float, vec2, vec3, "
                "int32, null/padding, or unknown. Follows pointers to detect string targets and vtables. "
                "This is like ReClass.NET but with AI interpretation — use it to reverse-engineer "
                "game structs (player, entity, weapon, etc.) by reading their memory layout."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Start address of the struct/region to analyze, in hex.",
                    },
                    "size": {
                        "type": "integer",
                        "description": "Bytes to analyze (8-4096). Default: 256.",
                        "default": 256,
                        "minimum": 8,
                        "maximum": 4096,
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                },
                "required": ["address"],
            },
        ),
        Tool(
            name="string_scan",
            description=(
                "Scan process memory for ASCII and/or UTF-16LE strings. "
                "Use this to find debug strings, class names, config values, file paths, "
                "and other readable text in game memory. Can scan a specific module or all process memory. "
                "Supports regex filtering (e.g. pattern='Player|Entity' to find game-related strings)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "module": {
                        "type": "string",
                        "description": "Restrict scan to this module (e.g. 'game.exe'). Much faster than full process scan.",
                    },
                    "min_length": {
                        "type": "integer",
                        "description": "Minimum string length to report. Default: 4.",
                        "default": 4,
                        "minimum": 3,
                    },
                    "encoding": {
                        "type": "string",
                        "enum": ["ascii", "unicode", "both"],
                        "description": "'ascii' = 8-bit strings, 'unicode' = UTF-16LE, 'both' = scan for both. Default: 'both'.",
                        "default": "both",
                    },
                    "pattern": {
                        "type": "string",
                        "description": "Regex to filter results (e.g. 'Player|Health|Ammo'). Case-insensitive.",
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum results to return. Default: 500.",
                        "default": 500,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="memory_diff",
            description=(
                "Snapshot and diff a memory region to detect changes. Replaces the manual Cheat Engine "
                "'changed/unchanged value' scan workflow. "
                "First call: takes a snapshot and returns immediately. "
                "Second call (after a game action like taking damage, moving, etc.): diffs against the "
                "snapshot and reports all changed bytes with type interpretations (int32, float, etc.). "
                "Each subsequent call diffs against the previous snapshot. "
                "Use the 'label' parameter to maintain multiple independent snapshots."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "address": {
                        "type": "string",
                        "description": "Start address of the region to snapshot/diff, in hex.",
                    },
                    "size": {
                        "type": "integer",
                        "description": "Size of the region in bytes (1-1MB).",
                        "minimum": 1,
                        "maximum": 1048576,
                    },
                    "label": {
                        "type": "string",
                        "description": "Label for this snapshot group. Use different labels for different regions. Default: 'default'.",
                        "default": "default",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID for virtual address mode.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name for virtual address mode.",
                    },
                },
                "required": ["address", "size"],
            },
        ),
        # ==================== Pointer / XRef Scanning ====================
        Tool(
            name="pointer_scan",
            description=(
                "Discover unknown pointer chains from static module bases to a target address. "
                "Given a known dynamic address (e.g. player object at 0x1a2b3c4d), finds all paths "
                "from module bases through pointer dereferences that reach it. "
                "Use this when you have a dynamic address but need a stable pointer chain for automation. "
                "WARNING: Can be slow for deep scans — start with max_depth=3."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_address": {
                        "type": "string",
                        "description": "Dynamic address to find chains to, in hex.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum pointer chain depth. Default: 5. Start with 3 for speed.",
                        "default": 5,
                        "minimum": 1,
                        "maximum": 10,
                    },
                    "max_offset": {
                        "type": "integer",
                        "description": "Maximum offset at each pointer level. Default: 4096.",
                        "default": 4096,
                        "minimum": 0,
                        "maximum": 65536,
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum chains to return. Default: 100.",
                        "default": 100,
                    },
                    "module_filter": {
                        "type": "string",
                        "description": "Only consider this module as chain root (e.g. 'game.exe'). Faster than scanning all modules.",
                    },
                },
                "required": ["target_address"],
            },
        ),
        Tool(
            name="xref_scan",
            description=(
                "Find all code instructions and data pointers that reference a target address. "
                "Scans a module's .text section for RIP-relative instructions (mov, lea, call, jmp) "
                "and .rdata/.data sections for raw pointer values that point to the target. "
                "Essential for understanding how a function or variable is used — find all callers "
                "of a function, all readers of a global variable, or all vtable entries."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "target_address": {
                        "type": "string",
                        "description": "Address to find references to, in hex.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "module": {
                        "type": "string",
                        "description": "Module to scan for references (e.g. 'game.exe'). Required.",
                    },
                    "scan_code": {
                        "type": "boolean",
                        "description": "Scan code sections for instruction references. Default: true.",
                        "default": True,
                    },
                    "scan_data": {
                        "type": "boolean",
                        "description": "Scan data sections for pointer values. Default: true.",
                        "default": True,
                    },
                    "max_results": {
                        "type": "integer",
                        "description": "Maximum references to return. Default: 200.",
                        "default": 200,
                    },
                },
                "required": ["target_address", "module"],
            },
        ),
        # ==================== Engine Tools ====================
        Tool(
            name="ue_dump_names",
            description=(
                "Read Unreal Engine FNamePool and dump all name entries from a running UE game. "
                "Requires the GNames/FNamePool address — find it using signature_resolve with known "
                "UE signatures (see docs/ue_signatures.md). Returns name index→string mappings. "
                "This is step 1 of UE SDK dumping: dump names → dump objects → dump SDK."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "gnames_address": {
                        "type": "string",
                        "description": "Address of GNames/FNamePool in hex. Find via signature_resolve.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "max_names": {
                        "type": "integer",
                        "description": "Maximum names to dump. Default: 200000.",
                        "default": 200000,
                    },
                    "ue_version": {
                        "type": "string",
                        "enum": ["ue4", "ue5"],
                        "description": "Unreal Engine version. Default: 'ue5'.",
                        "default": "ue5",
                    },
                },
                "required": ["gnames_address"],
            },
        ),
        Tool(
            name="ue_dump_objects",
            description=(
                "Read Unreal Engine FUObjectArray and dump all UObject entries from a running UE game. "
                "Requires the GObjects/FUObjectArray address — find it using signature_resolve. "
                "Optionally provide GNames address to resolve object names (otherwise names show as indices). "
                "This is step 2 of UE SDK dumping: dump names → dump objects → dump SDK."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "gobjects_address": {
                        "type": "string",
                        "description": "Address of GUObjectArray in hex. Find via signature_resolve.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "gnames_address": {
                        "type": "string",
                        "description": "Address of GNames/FNamePool for name resolution. Highly recommended.",
                    },
                    "max_objects": {
                        "type": "integer",
                        "description": "Maximum objects to dump. Default: 200000.",
                        "default": 200000,
                    },
                    "ue_version": {
                        "type": "string",
                        "enum": ["ue4", "ue5"],
                        "description": "Unreal Engine version. Default: 'ue5'.",
                        "default": "ue5",
                    },
                },
                "required": ["gobjects_address"],
            },
        ),
        Tool(
            name="ue_dump_sdk",
            description=(
                "Generate C++ SDK headers from UE reflection system. Walks the class hierarchy, "
                "enumerates properties with offsets, and outputs struct definitions usable in C++. "
                "Requires both GNames and GObjects addresses. Optionally writes to a file (can be large). "
                "This is step 3 of UE SDK dumping: dump names → dump objects → dump SDK."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "gobjects_address": {
                        "type": "string",
                        "description": "Address of GUObjectArray in hex.",
                    },
                    "gnames_address": {
                        "type": "string",
                        "description": "Address of GNames/FNamePool in hex.",
                    },
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "File path to write SDK headers. If omitted, returns summary only.",
                    },
                    "max_classes": {
                        "type": "integer",
                        "description": "Maximum classes to process. Default: 5000.",
                        "default": 5000,
                    },
                    "ue_version": {
                        "type": "string",
                        "enum": ["ue4", "ue5"],
                        "description": "Unreal Engine version. Default: 'ue5'.",
                        "default": "ue5",
                    },
                },
                "required": ["gobjects_address", "gnames_address"],
            },
        ),
        Tool(
            name="unity_il2cpp_dump",
            description=(
                "Find and parse IL2CPP metadata from a running Unity game. Automatically locates "
                "GameAssembly.dll, finds the metadata blob (magic 0xFAB11BAF), and extracts class "
                "definitions with fields, methods, and offsets. Supports metadata versions 27-31. "
                "Outputs C#-style class definitions. No addresses needed — fully automatic discovery."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "pid": {
                        "type": "integer",
                        "description": "Process ID. Mutually exclusive with process_name.",
                    },
                    "process_name": {
                        "type": "string",
                        "description": "Process name. Mutually exclusive with pid.",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "File path to write C# class definitions. If omitted, returns summary only.",
                    },
                    "max_classes": {
                        "type": "integer",
                        "description": "Maximum classes to process. Default: 5000.",
                        "default": 5000,
                    },
                },
                "required": [],
            },
        ),
        # ==================== Advanced / FPGA ====================
        Tool(
            name="benchmark",
            description=(
                "Measure DMA read/write throughput in MB/s. Use this to verify the FPGA device "
                "performance and diagnose speed issues. Runs 1000 iterations of 4KB transfers."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "test_type": {
                        "type": "string",
                        "enum": ["read", "readwrite", "full"],
                        "description": "'read' = read-only benchmark, 'readwrite' or 'full' = read + write benchmark. Default: 'read'.",
                        "default": "read",
                    },
                    "address": {
                        "type": "string",
                        "description": "Physical address to benchmark against in hex. Default: '0x1000'.",
                        "default": "0x1000",
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="tlp_send",
            description=(
                "Send and/or receive raw PCIe Transaction Layer Packets (TLPs). FPGA devices only. "
                "This is an ADVANCED low-level tool for PCIe protocol analysis, device enumeration, "
                "or custom packet crafting. Most users won't need this — use memory_read/write instead. "
                "Omit tlp_data to passively listen for TLPs."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tlp_data": {
                        "type": "string",
                        "description": "Raw TLP packet bytes in hex. Omit to just listen for incoming TLPs without sending.",
                    },
                    "wait_seconds": {
                        "type": "number",
                        "description": "How long to listen for TLP responses in seconds (0.1 to 60). Default: 0.5.",
                        "default": 0.5,
                        "minimum": 0.1,
                        "maximum": 60,
                    },
                    "verbose": {
                        "type": "boolean",
                        "description": "Include decoded TLP header info alongside raw hex. Default: true.",
                        "default": True,
                    },
                },
                "required": [],
            },
        ),
        Tool(
            name="fpga_config",
            description=(
                "Read or write the FPGA's PCIe configuration space registers. FPGA devices only. "
                "Use 'read' to dump the full 4KB PCIe config space (vendor ID, device ID, BARs, capabilities). "
                "Use 'write' to modify specific config registers (e.g. change device ID for spoofing). "
                "This configures the FPGA itself, NOT the target system's memory."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "enum": ["read", "write"],
                        "description": "'read' dumps the full PCIe config space. 'write' modifies a specific register. Default: 'read'.",
                        "default": "read",
                    },
                    "address": {
                        "type": "string",
                        "description": "Config register offset in hex (required for 'write'). E.g. '0x00' = Device/Vendor ID.",
                    },
                    "data": {
                        "type": "string",
                        "description": "Data to write in hex (required for 'write').",
                    },
                    "output_file": {
                        "type": "string",
                        "description": "Save config space to this file path (for 'read' action).",
                    },
                },
                "required": [],
            },
        ),
        # ==================== Device Lifecycle ====================
        Tool(
            name="device_disconnect",
            description=(
                "Disconnect from the DMA/FPGA device, freeing it for external use. "
                "Call this when you're done with memory analysis and the user wants to test "
                "their own DMA solution against the FPGA device. The device handle is released "
                "so other programs can claim it. Use device_reconnect to resume MCP operations later."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="device_reconnect",
            description=(
                "Reconnect to the DMA/FPGA device after a previous device_disconnect. "
                "Re-establishes the MemProcFS and LeechCore handles so MCP tools work again. "
                "Call this when the user is done testing their own DMA code and wants to "
                "resume using MCP tools for memory analysis."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
        Tool(
            name="device_status",
            description=(
                "Check the current DMA/FPGA device connection status. "
                "Reports whether MemProcFS (VMM) and LeechCore (LC) handles are active, "
                "and basic device info if connected."
            ),
            inputSchema={
                "type": "object",
                "properties": {},
                "required": [],
            },
        ),
    ]


# ==================== Tool Handlers ====================


@server.call_tool()
async def call_tool(name: str, arguments: Any) -> list[TextContent]:
    try:
        handlers = {
            "memory_read": handle_memory_read,
            "memory_write": handle_memory_write,
            "memory_format": handle_memory_format,
            "system_info": handle_system_info,
            "memory_probe": handle_memory_probe,
            "memory_dump": handle_memory_dump,
            "memory_search": handle_memory_search,
            "memory_patch": handle_memory_patch,
            "process_list": handle_process_list,
            "translate_virt2phys": handle_translate_virt2phys,
            "process_virt2phys": handle_process_virt2phys,
            "module_list": handle_module_list,
            "aob_scan": handle_aob_scan,
            "module_dump": handle_module_dump,
            "module_exports": handle_module_exports,
            "module_imports": handle_module_imports,
            "pointer_read": handle_pointer_read,
            "process_regions": handle_process_regions,
            "scatter_read": handle_scatter_read,
            "pe_sections": handle_pe_sections,
            "signature_resolve": handle_signature_resolve,
            "rtti_scan": handle_rtti_scan,
            "struct_analyze": handle_struct_analyze,
            "string_scan": handle_string_scan,
            "memory_diff": handle_memory_diff,
            "pointer_scan": handle_pointer_scan,
            "xref_scan": handle_xref_scan,
            "ue_dump_names": handle_ue_dump_names,
            "ue_dump_objects": handle_ue_dump_objects,
            "ue_dump_sdk": handle_ue_dump_sdk,
            "unity_il2cpp_dump": handle_unity_il2cpp_dump,
            "benchmark": handle_benchmark,
            "tlp_send": handle_tlp_send,
            "fpga_config": handle_fpga_config,
            "device_disconnect": handle_device_disconnect,
            "device_reconnect": handle_device_reconnect,
            "device_status": handle_device_status,
        }
        handler = handlers.get(name)
        if handler is None:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]
        return await handler(arguments or {})
    except PCILeechError as e:
        logger.error(f"PCILeech error in {name}: {e}")
        return [TextContent(type="text", text=f"PCILeech error: {e}")]
    except Exception as e:
        logger.error(f"Unexpected error in {name}: {e}", exc_info=True)
        return [TextContent(type="text", text=f"Internal error: {e}")]


async def handle_memory_read(args: dict) -> list[TextContent]:
    address = args["address"]
    length = args["length"]
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    mode = mode_string(pid, process_name)
    w = get_wrapper()
    data = await asyncio.to_thread(
        w.read_memory, address, length, pid=pid, process_name=process_name
    )

    return [
        TextContent(
            type="text",
            text=(
                f"Read {len(data)} bytes from {address} ({mode})\n\n"
                f"Hex: {data.hex()}\n\n"
                f"Bytes read: {len(data)}\n"
                f"Timestamp: {datetime.now().isoformat()}"
            ),
        )
    ]


async def handle_memory_write(args: dict) -> list[TextContent]:
    address = args["address"]
    data_hex = args["data"]
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    try:
        data = bytes.fromhex(data_hex)
    except ValueError as e:
        return [TextContent(type="text", text=f"Invalid hex data: {e}")]

    mode = mode_string(pid, process_name)
    w = get_wrapper()
    await asyncio.to_thread(w.write_memory, address, data, pid=pid, process_name=process_name)

    return [
        TextContent(
            type="text",
            text=(
                f"Wrote {len(data)} bytes to {address} ({mode})\n\n"
                f"Data: {data_hex}\n"
                f"Timestamp: {datetime.now().isoformat()}"
            ),
        )
    ]


async def handle_memory_format(args: dict) -> list[TextContent]:
    address = args["address"]
    length = args["length"]
    formats = args.get("formats", ["hexdump", "ascii", "bytes", "dwords", "raw"])
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    w = get_wrapper()
    data = await asyncio.to_thread(
        w.read_memory, address, length, pid=pid, process_name=process_name
    )
    addr_int = parse_hex_address(address)

    parts = [f"Memory at {address} ({length} bytes)", "=" * 80, ""]

    if "hexdump" in formats:
        parts += ["## Hex Dump:", format_hex_dump(data, addr_int), ""]
    if "ascii" in formats:
        parts += ["## ASCII:", format_ascii_view(data), ""]
    if "bytes" in formats:
        parts += ["## Byte Array:", format_byte_array(data), ""]
    if "dwords" in formats:
        parts += ["## DWORD Array (LE):", format_dword_array(data), ""]
    if "raw" in formats:
        parts += ["## Raw Hex:", data.hex(), ""]

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_system_info(args: dict) -> list[TextContent]:
    verbose = args.get("verbose", False)
    w = get_wrapper()
    info = await asyncio.to_thread(w.get_system_info, verbose)

    parts = ["## System Information", "=" * 50, ""]
    for k, v in info.items():
        if k == "memmap":
            parts.append(f"**Memory Regions:** {len(v)}")
        else:
            parts.append(f"**{k}:** {v}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_probe(args: dict) -> list[TextContent]:
    min_addr = args.get("min_address", "0x0")
    max_addr = args.get("max_address")

    w = get_wrapper()
    regions = await asyncio.to_thread(w.probe_memory, min_addr, max_addr)

    parts = ["## Memory Probe Results", "=" * 50, ""]
    if not regions:
        parts.append("No readable memory regions found.")
    else:
        parts.append(f"Found {len(regions)} region(s):\n")
        for i, r in enumerate(regions, 1):
            parts.append(f"{i}. **{r['start']}** - **{r['end']}** ({r['size_mb']:.2f} MB)")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_dump(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.dump_memory,
        args["min_address"],
        args["max_address"],
        args.get("output_file"),
        args.get("force", False),
    )

    parts = [
        "## Memory Dump Result",
        "=" * 50,
        "",
        f"**Range:** {result['min_address']} - {result['max_address']}",
        f"**Size:** {result['size']} bytes",
        f"**File:** {result.get('file', 'N/A')}",
        f"**Success:** {result['success']}",
    ]
    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_search(args: dict) -> list[TextContent]:
    w = get_wrapper()
    matches = await asyncio.to_thread(
        w.search_memory,
        args.get("pattern"),
        args.get("min_address"),
        args.get("max_address"),
        args.get("find_all", False),
    )

    parts = ["## Memory Search Results", "=" * 50, "", f"**Pattern:** {args.get('pattern')}", ""]
    if not matches:
        parts.append("No matches found.")
    else:
        parts.append(f"Found {len(matches)} match(es):\n")
        for i, m in enumerate(matches, 1):
            parts.append(f"{i}. **{m['address']}**  context: {m.get('line', '')}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_patch(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.patch_memory,
        args["signature"],
        args.get("min_address"),
        args.get("max_address"),
        args.get("patch_all", False),
    )
    return [TextContent(type="text", text=str(result))]


async def handle_process_list(args: dict) -> list[TextContent]:
    w = get_wrapper()
    processes = await asyncio.to_thread(w.list_processes)

    parts = ["## Process List", "=" * 50, "", f"Found {len(processes)} process(es):\n"]
    parts.append(f"{'PID':>8}  {'PPID':>8}  {'State':>5}  {'Name'}")
    parts.append("-" * 50)
    for p in processes:
        parts.append(f"{p['pid']:>8}  {p['ppid']:>8}  {p['state']:>5}  {p['name']}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_translate_virt2phys(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.translate_virt2phys,
        args["virtual_address"],
        args.get("cr3"),
    )

    parts = ["## Address Translation (Virt -> Phys)", "=" * 50, ""]
    for k, v in result.items():
        if v is not None:
            parts.append(f"**{k}:** {v}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_process_virt2phys(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.process_virt2phys,
        args["pid"],
        args["virtual_address"],
    )

    parts = ["## Process Address Translation", "=" * 50, ""]
    for k, v in result.items():
        if v is not None:
            parts.append(f"**{k}:** {v}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_module_list(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    modules = await asyncio.to_thread(w.list_modules, pid=pid, process_name=process_name)

    target = f"PID {pid}" if pid else process_name
    parts = [f"## Modules for {target}", "=" * 50, "", f"Found {len(modules)} module(s):\n"]
    parts.append(f"{'Base':>18}  {'Size':>12}  {'Name'}")
    parts.append("-" * 60)
    for m in modules:
        parts.append(f"{m['base']:>18}  {m['size']:>12}  {m['name']}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_aob_scan(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    matches = await asyncio.to_thread(
        w.aob_scan,
        args["pattern"],
        pid=pid,
        process_name=process_name,
        module=args.get("module"),
        find_all=args.get("find_all", False),
    )

    target = f"PID {pid}" if pid else process_name
    module_info = f" in {args['module']}" if args.get("module") else ""
    parts = [
        f"## AOB Scan Results ({target}{module_info})",
        "=" * 50,
        "",
        f"**Pattern:** `{args['pattern']}`",
        "",
    ]

    if not matches:
        parts.append("No matches found.")
    else:
        parts.append(f"Found {len(matches)} match(es):\n")
        for i, m in enumerate(matches, 1):
            parts.append(f"{i}. **{m['address']}**  `{m.get('context', '')}`")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_module_dump(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.module_dump,
        pid=pid,
        process_name=process_name,
        module_name=args["module_name"],
        output_file=args.get("output_file"),
    )

    parts = [
        "## Module Dump Result",
        "=" * 50,
        "",
        f"**Module:** {result['module']}",
        f"**Base:** {result['base']}",
        f"**Size:** {result['size']} bytes (0x{result['size']:x})",
        f"**File:** {result['file']}",
        f"**Success:** {result['success']}",
    ]
    return [TextContent(type="text", text="\n".join(parts))]


async def handle_module_exports(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    exports = await asyncio.to_thread(
        w.module_exports,
        pid=pid,
        process_name=process_name,
        module_name=args["module_name"],
    )

    parts = [
        f"## Exports: {args['module_name']}",
        "=" * 50,
        "",
        f"Found {len(exports)} export(s):\n",
    ]
    parts.append(f"{'Ordinal':>8}  {'Address':>18}  {'Name'}")
    parts.append("-" * 60)
    for e in exports:
        parts.append(f"{e['ordinal']:>8}  {e['address']:>18}  {e['name']}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_module_imports(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    imports = await asyncio.to_thread(
        w.module_imports,
        pid=pid,
        process_name=process_name,
        module_name=args["module_name"],
    )

    parts = [
        f"## Imports: {args['module_name']}",
        "=" * 50,
        "",
        f"Found {len(imports)} import(s):\n",
    ]
    parts.append(f"{'Address':>18}  {'Module':<30}  {'Name'}")
    parts.append("-" * 70)
    for imp in imports:
        parts.append(f"{imp['address']:>18}  {imp['module']:<30}  {imp['name']}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_pointer_read(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.pointer_read,
        args["base_address"],
        args["offsets"],
        read_size=args.get("read_size", 8),
        pid=pid,
        process_name=process_name,
    )

    parts = ["## Pointer Chain Result", "=" * 50, ""]

    # Show the chain
    chain = result.get("chain", [])
    offsets = args["offsets"]
    chain_str = chain[0] if chain else args["base_address"]
    for i, off in enumerate(offsets):
        sign = "+" if off >= 0 else "-"
        chain_str = f"[{chain_str}]{sign}0x{abs(off):x}"
    parts.append(f"**Chain:** {chain_str}")
    parts.append(f"**Resolved path:** {' -> '.join(chain)}")
    parts.append("")

    if result["success"]:
        parts.append(f"**Final address:** {result['final_address']}")
        parts.append(f"**Value:** {result['value']}")
        parts.append(f"**Raw:** {result['raw_hex']}")
    else:
        parts.append(f"**Failed:** {result['error']}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_process_regions(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    regions = await asyncio.to_thread(
        w.process_regions,
        pid=pid,
        process_name=process_name,
    )

    target = f"PID {pid}" if pid else process_name
    parts = [f"## Memory Regions: {target}", "=" * 50, "", f"Found {len(regions)} region(s):\n"]
    parts.append(f"{'Address':>18}  {'Size':>10}  {'Protection':<16}  {'Type':<12}  {'Info'}")
    parts.append("-" * 80)
    for r in regions:
        parts.append(
            f"{r['start']:>18}  {r['size_str']:>10}  {str(r['protection']):<16}  "
            f"{str(r['type']):<12}  {r.get('info', '')}"
        )

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_scatter_read(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    mode = mode_string(pid, process_name)
    w = get_wrapper()
    results = await asyncio.to_thread(
        w.scatter_read,
        args["reads"],
        pid=pid,
        process_name=process_name,
    )

    parts = [
        f"## Scatter Read Results ({mode})",
        "=" * 50,
        "",
        f"Read {len(results)} region(s) in one batch:\n",
    ]
    for i, r in enumerate(results, 1):
        parts.append(
            f"{i}. **{r['address']}** ({r['size']} bytes): `{r['data'][:64]}{'...' if len(r['data']) > 64 else ''}`"
        )

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_pe_sections(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    sections = await asyncio.to_thread(
        w.pe_sections,
        pid=pid,
        process_name=process_name,
        module_name=args["module_name"],
    )

    parts = [
        f"## PE Sections: {args['module_name']}",
        "=" * 50,
        "",
        f"Found {len(sections)} section(s):\n",
    ]
    parts.append(
        f"{'Name':<12}  {'Virtual Address':>18}  {'VSize':>10}  {'RawSize':>10}  {'Flags'}"
    )
    parts.append("-" * 80)
    for s in sections:
        flags = ", ".join(s["flags"])
        parts.append(
            f"{s['name']:<12}  {s['virtual_address']:>18}  "
            f"{s['virtual_size']:>10}  {s['raw_size']:>10}  {flags}"
        )

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_signature_resolve(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.signature_resolve,
        args["pattern"],
        pid=pid,
        process_name=process_name,
        module=args.get("module"),
        op_offset=args.get("op_offset", 3),
        op_length=args.get("op_length", 4),
        rip_relative=args.get("rip_relative", True),
        instruction_length=args.get("instruction_length"),
    )

    parts = ["## Signature Resolve Result", "=" * 50, "", f"**Pattern:** `{result['pattern']}`", ""]

    if result["success"]:
        parts.append(f"**Match address:** {result['match_address']}")
        parts.append(f"**Operand value:** {result['operand']}")
        parts.append(f"**Resolved address:** {result['resolved_address']}")
        if result.get("instruction_length"):
            parts.append(f"**Instruction length:** {result['instruction_length']}")
    else:
        parts.append(f"**Failed:** {result['error']}")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_rtti_scan(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    classes = await asyncio.to_thread(
        w.rtti_scan,
        pid=pid,
        process_name=process_name,
        module=args["module"],
        max_classes=args.get("max_classes", 500),
    )

    parts = [f"## RTTI Scan: {args['module']}", "=" * 50, "", f"Found {len(classes)} class(es):\n"]

    for i, c in enumerate(classes, 1):
        line = f"{i}. **{c['class_name']}**"
        if c.get("vtable"):
            line += f"  vtable: {c['vtable']}"
        if c.get("base_classes"):
            line += f"  extends: {', '.join(c['base_classes'])}"
        parts.append(line)
        parts.append(f"   TD: {c['type_descriptor']}  mangled: `{c['mangled_name']}`")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_struct_analyze(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.struct_analyze,
        args["address"],
        size=args.get("size", 256),
        pid=pid,
        process_name=process_name,
    )

    parts = [f"## Struct Analysis: {result['base_address']} ({result['size']} bytes)", "=" * 50, ""]

    for f in result["fields"]:
        line = f"  +{f['offset']:<8} [{f['type']:<12}] {f['value']}"
        if f.get("target_string"):
            line += f'  -> "{f["target_string"]}"'
        parts.append(line)

    if result.get("pointer_targets"):
        parts.append(f"\n**Pointer targets:** {len(result['pointer_targets'])} resolved")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_string_scan(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    results = await asyncio.to_thread(
        w.string_scan,
        pid=pid,
        process_name=process_name,
        module=args.get("module"),
        min_length=args.get("min_length", 4),
        encoding=args.get("encoding", "both"),
        pattern=args.get("pattern"),
        max_results=args.get("max_results", 500),
    )

    module_info = f" in {args['module']}" if args.get("module") else ""
    parts = [
        f"## String Scan Results{module_info}",
        "=" * 50,
        "",
        f"Found {len(results)} string(s):\n",
    ]

    for i, s in enumerate(results[:100], 1):  # Show first 100 in output
        parts.append(
            f"{i}. [{s['encoding']}] **{s['address']}** ({s['length']} chars): `{s['string'][:80]}`"
        )

    if len(results) > 100:
        parts.append(f"\n... and {len(results) - 100} more (truncated)")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_memory_diff(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.memory_diff,
        args["address"],
        args["size"],
        label=args.get("label", "default"),
        pid=pid,
        process_name=process_name,
    )

    parts = ["## Memory Diff Result", "=" * 50, ""]

    if result["action"] == "snapshot_taken":
        parts.append(f"**Snapshot taken:** {result['label']}")
        parts.append(f"**Address:** {result['address']} ({result['size']} bytes)")
        parts.append(f"\n{result['message']}")
    else:
        parts.append(f"**Label:** {result['label']}")
        parts.append(f"**Region:** {result['address']} ({result['size']} bytes)")
        parts.append(
            f"**Changes:** {result['total_changes']} region(s), {result['bytes_changed']} byte(s)\n"
        )

        if not result["changes"]:
            parts.append("No changes detected.")
        else:
            for i, c in enumerate(result["changes"][:50], 1):
                parts.append(
                    f"{i}. **{c['address']}** (+{c['offset']}, {c['size']}B): `{c['old']}` -> `{c['new']}`"
                )
                if c.get("as_int32"):
                    parts.append(f"   int32: {c['as_int32']}")
                if c.get("as_float"):
                    parts.append(f"   float: {c['as_float']}")
                if c.get("as_int64"):
                    parts.append(f"   int64: {c['as_int64']}")
                if c.get("as_byte"):
                    parts.append(f"   byte: {c['as_byte']}")

            if len(result["changes"]) > 50:
                parts.append(f"\n... and {len(result['changes']) - 50} more changes (truncated)")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_pointer_scan(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.pointer_scan,
        args["target_address"],
        pid=pid,
        process_name=process_name,
        max_depth=args.get("max_depth", 5),
        max_offset=args.get("max_offset", 4096),
        max_results=args.get("max_results", 100),
        module_filter=args.get("module_filter"),
    )

    stats = result.get("stats", {})
    parts = [
        f"## Pointer Scan Results",
        "=" * 50,
        "",
        f"**Target:** {stats.get('target', args['target_address'])}",
        f"**Depth:** {stats.get('levels_searched', 0)}/{stats.get('max_depth', 0)}",
        f"**Addresses scanned:** {stats.get('addresses_scanned', 0)}",
        f"**Chains found:** {stats.get('total_chains_found', 0)}\n",
    ]

    chains = result.get("chains", [])
    if not chains:
        parts.append("No pointer chains found.")
    else:
        for i, c in enumerate(chains[:50], 1):
            parts.append(f"{i}. `{c['expression']}` (depth {c['depth']})")
            parts.append(f"   module: {c['module']}, base_offset: 0x{c['base_offset']:x}")

        if len(chains) > 50:
            parts.append(f"\n... and {len(chains) - 50} more chains")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_xref_scan(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.xref_scan,
        args["target_address"],
        pid=pid,
        process_name=process_name,
        module=args["module"],
        scan_code=args.get("scan_code", True),
        scan_data=args.get("scan_data", True),
        max_results=args.get("max_results", 200),
    )

    code_refs = result.get("code_refs", [])
    data_refs = result.get("data_refs", [])
    stats = result.get("stats", {})

    parts = [
        f"## XRef Scan: {result.get('module', args['module'])}",
        "=" * 50,
        "",
        f"**Target:** {result.get('target', args['target_address'])}",
        f"**Code refs:** {len(code_refs)}",
        f"**Data refs:** {len(data_refs)}",
        f"**Bytes scanned:** {stats.get('total_bytes_scanned', 0)}\n",
    ]

    if code_refs:
        parts.append("### Code References")
        for i, r in enumerate(code_refs[:100], 1):
            parts.append(
                f"{i}. **{r['address']}** [{r['type']}] `{r.get('instruction_bytes', '')}`  ({r['section']})"
            )

    if data_refs:
        parts.append("\n### Data References")
        for i, r in enumerate(data_refs[:100], 1):
            parts.append(f"{i}. **{r['address']}**  ({r['section']})  `{r.get('context', '')}`")

    if not code_refs and not data_refs:
        parts.append("No references found.")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_ue_dump_names(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.ue_dump_names,
        args["gnames_address"],
        pid=pid,
        process_name=process_name,
        max_names=args.get("max_names", 200000),
        ue_version=args.get("ue_version", "ue5"),
    )

    parts = [
        f"## UE Name Dump",
        "=" * 50,
        "",
        f"**GNames address:** {result.get('gnames_address', args['gnames_address'])}",
        f"**Total names:** {result.get('total_names', 0)}",
        f"**Blocks read:** {result.get('blocks_read', 0)}\n",
    ]

    names = result.get("names", [])
    parts.append(f"### First {min(len(names), 50)} names:")
    for n in names[:50]:
        parts.append(f"  [{n['index']}] {n['name']}")

    if len(names) > 50:
        parts.append(f"\n... and {len(names) - 50} more names")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_ue_dump_objects(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.ue_dump_objects,
        args["gobjects_address"],
        pid=pid,
        process_name=process_name,
        gnames_address=args.get("gnames_address"),
        max_objects=args.get("max_objects", 200000),
        ue_version=args.get("ue_version", "ue5"),
    )

    parts = [
        f"## UE Object Dump",
        "=" * 50,
        "",
        f"**GObjects address:** {result.get('gobjects_address', args['gobjects_address'])}",
        f"**Total objects:** {result.get('total_objects', 0)}\n",
    ]

    objects = result.get("objects", [])
    parts.append(f"### First {min(len(objects), 50)} objects:")
    for o in objects[:50]:
        line = f"  [{o['index']}] {o.get('name', '?')} ({o.get('class_name', '?')})"
        if o.get("outer"):
            line += f" in {o['outer']}"
        parts.append(line)

    if len(objects) > 50:
        parts.append(f"\n... and {len(objects) - 50} more objects")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_ue_dump_sdk(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.ue_dump_sdk,
        args["gobjects_address"],
        args["gnames_address"],
        pid=pid,
        process_name=process_name,
        output_file=args.get("output_file"),
        max_classes=args.get("max_classes", 5000),
        ue_version=args.get("ue_version", "ue5"),
    )

    parts = [
        f"## UE SDK Dump",
        "=" * 50,
        "",
        f"**Total classes:** {result.get('total_classes', 0)}",
        f"**Total properties:** {result.get('total_properties', 0)}",
    ]

    if result.get("output_file"):
        parts.append(f"**Output file:** {result['output_file']}")

    classes = result.get("classes", [])
    if classes:
        parts.append(f"\n### Class summary ({min(len(classes), 50)} shown):")
        for c in classes[:50]:
            super_str = f" : {c['super']}" if c.get("super") else ""
            parts.append(f"  {c['name']}{super_str} (0x{c['size']:x}, {c['property_count']} props)")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_unity_il2cpp_dump(args: dict) -> list[TextContent]:
    pid = args.get("pid")
    process_name = args.get("process_name")

    error = validate_mutually_exclusive(args, "pid", "process_name")
    if error:
        return [TextContent(type="text", text=f"Parameter error: {error}")]
    if pid is None and process_name is None:
        return [TextContent(type="text", text="Error: pid or process_name is required")]

    w = get_wrapper()
    result = await asyncio.to_thread(
        w.unity_il2cpp_dump,
        pid=pid,
        process_name=process_name,
        output_file=args.get("output_file"),
        max_classes=args.get("max_classes", 5000),
    )

    parts = [
        f"## Unity IL2CPP Dump",
        "=" * 50,
        "",
        f"**GameAssembly:** {result.get('game_assembly', 'N/A')}",
        f"**Metadata address:** {result.get('metadata_address', 'N/A')}",
        f"**Metadata version:** {result.get('metadata_version', 'N/A')}",
        f"**Total types:** {result.get('total_types', 0)}",
        f"**Total fields:** {result.get('total_fields', 0)}",
        f"**Total methods:** {result.get('total_methods', 0)}",
    ]

    if result.get("output_file"):
        parts.append(f"**Output file:** {result['output_file']}")

    classes = result.get("classes", [])
    if classes:
        parts.append(f"\n### Classes ({min(len(classes), 50)} shown):")
        for c in classes[:50]:
            ns = f"{c['namespace']}." if c.get("namespace") else ""
            parts.append(
                f"  {ns}{c['name']} ({c.get('field_count', 0)} fields, {c.get('method_count', 0)} methods)"
            )

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_benchmark(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.benchmark,
        args.get("test_type", "read"),
        args.get("address", "0x1000"),
    )

    parts = ["## Benchmark Results", "=" * 50, ""]
    parts.append(
        f"**Read:** {result['read_mbps']} MB/s ({result['read_iterations']} iterations, {result['read_elapsed_s']}s)"
    )
    if "write_mbps" in result:
        parts.append(
            f"**Write:** {result['write_mbps']} MB/s ({result['write_iterations']} iterations, {result['write_elapsed_s']}s)"
        )

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_tlp_send(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.tlp_send,
        args.get("tlp_data"),
        args.get("wait_seconds", 0.5),
        args.get("verbose", True),
    )

    parts = ["## TLP Results", "=" * 50, ""]
    if result["sent"]:
        parts.append(f"**Sent:** {result['sent_bytes']} bytes")
        if "sent_info" in result:
            parts.append(f"```\n{result['sent_info']}\n```")

    parts.append(f"\n**Received TLPs:** {len(result['received_tlps'])}")
    for i, tlp in enumerate(result["received_tlps"], 1):
        parts.append(f"\n### TLP {i}")
        parts.append(f"Data: {tlp['data']}")
        if "info" in tlp:
            parts.append(f"```\n{tlp['info']}\n```")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_fpga_config(args: dict) -> list[TextContent]:
    w = get_wrapper()
    result = await asyncio.to_thread(
        w.fpga_config,
        args.get("action", "read"),
        args.get("address"),
        args.get("data"),
        args.get("output_file"),
    )

    parts = ["## FPGA Config Result", "=" * 50, ""]
    parts.append(f"**Action:** {result['action']}")
    parts.append(f"**Success:** {result['success']}")

    if result["action"] == "read":
        parts.append(f"**Size:** {result['size']} bytes")
        # Show first 256 bytes as hex dump
        raw = bytes.fromhex(result["data_hex"])
        preview = raw[:256]
        parts.append(f"\n### Config Space (first {len(preview)} bytes):")
        parts.append(f"```\n{format_hex_dump(preview, 0)}\n```")
        if result.get("file"):
            parts.append(f"**Saved to:** {result['file']}")
    else:
        parts.append(f"**Address:** {result.get('address')}")
        parts.append(f"**Bytes written:** {result.get('bytes_written')}")

    return [TextContent(type="text", text="\n".join(parts))]


# ==================== Device Lifecycle Handlers ====================


async def handle_device_disconnect(args: dict) -> list[TextContent]:
    global wrapper
    if wrapper is None:
        return [
            TextContent(type="text", text="Device is already disconnected (no active connection).")
        ]

    was_vmm = wrapper._vmm is not None
    was_lc = wrapper._lc is not None
    await asyncio.to_thread(wrapper.close)
    wrapper = None

    parts = ["## Device Disconnected", "=" * 50, ""]
    if was_vmm:
        parts.append("- MemProcFS (VMM) handle released")
    if was_lc:
        parts.append("- LeechCore (LC) handle released")
    if not was_vmm and not was_lc:
        parts.append("- No active handles were open (lazy init hadn't triggered)")
    parts.append("")
    parts.append("The FPGA device is now free for external use.")
    parts.append("Use **device_reconnect** when you want to resume MCP operations.")

    return [TextContent(type="text", text="\n".join(parts))]


async def handle_device_reconnect(args: dict) -> list[TextContent]:
    global wrapper
    # Close any stale state first
    if wrapper is not None:
        await asyncio.to_thread(wrapper.close)
        wrapper = None

    try:
        wrapper = VmmWrapper()
        # Force immediate connection to verify device is available
        await asyncio.to_thread(wrapper._get_vmm)
        vmm = wrapper._vmm
        info_parts = []
        try:
            mem_map = vmm.maps.memmap()
            if mem_map:
                max_addr = max(e["pa"] + e["cb"] for e in mem_map)
                info_parts.append(f"- Physical memory: {max_addr / (1024**3):.1f} GB")
        except Exception:
            pass

        parts = ["## Device Reconnected", "=" * 50, ""]
        parts.append("- MemProcFS (VMM) handle established")
        parts.extend(info_parts)
        parts.append("")
        parts.append("All MCP tools are operational again.")

        return [TextContent(type="text", text="\n".join(parts))]
    except Exception as e:
        wrapper = None
        return [
            TextContent(
                type="text",
                text=(
                    f"## Reconnection Failed\n\n"
                    f"Could not reconnect to device: {e}\n\n"
                    f"Make sure no other program is holding the FPGA device and try again."
                ),
            )
        ]


async def handle_device_status(args: dict) -> list[TextContent]:
    parts = ["## Device Status", "=" * 50, ""]

    if wrapper is None:
        parts.append("**Connection:** Disconnected")
        parts.append("")
        parts.append(
            "No wrapper instance exists. Use any MCP tool or **device_reconnect** to connect."
        )
        return [TextContent(type="text", text="\n".join(parts))]

    vmm_active = wrapper._vmm is not None
    lc_active = wrapper._lc is not None

    if not vmm_active and not lc_active:
        parts.append("**Connection:** Idle (lazy init — not yet connected)")
        parts.append("")
        parts.append(
            "Wrapper exists but no device handles are open yet. "
            "They will be created on first tool use."
        )
    else:
        parts.append("**Connection:** Active")
        parts.append(f"- VMM (MemProcFS): {'connected' if vmm_active else 'not initialized'}")
        parts.append(f"- LC (LeechCore): {'connected' if lc_active else 'not initialized'}")
        parts.append(f"- Device type: {wrapper._device_type}")
        if wrapper._remote:
            parts.append(f"- Remote: {wrapper._remote}")
        if vmm_active:
            try:
                proc_list = wrapper._vmm.process_list()
                parts.append(f"- Processes visible: {len(proc_list)}")
            except Exception:
                pass
        if wrapper._snapshots:
            parts.append(f"- Memory diff snapshots: {len(wrapper._snapshots)}")

    return [TextContent(type="text", text="\n".join(parts))]


# ==================== Entry Point ====================


async def main():
    from mcp.server.stdio import stdio_server

    async with stdio_server() as (read_stream, write_stream):
        logger.info("nevercheese-pcileech-memprocfs-mcp starting...")
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )


def run():
    """Synchronous entry point for the console script (used by ``uvx``/``pipx``)."""
    asyncio.run(main())


if __name__ == "__main__":
    run()

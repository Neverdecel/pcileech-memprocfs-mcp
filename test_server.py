#!/usr/bin/env python3
"""
Test suite for MCP Server for PCILeech (Linux native).

Tests are split into:
1. Unit tests - no hardware needed (helpers, MCP layer, mock wrapper)
2. Integration test hints - require DMA hardware or valid memory dump
"""

import json
import os
import sys
import struct
import asyncio
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(__file__))

PASS = 0
FAIL = 0


def check(name: str, condition: bool):
    global PASS, FAIL
    if condition:
        PASS += 1
        print(f"  [PASS] {name}")
    else:
        FAIL += 1
        print(f"  [FAIL] {name}")


# ==================== Unit Tests ====================


def test_helpers():
    print("\n--- Helper Functions ---")
    from vmm_wrapper import parse_hex_address, validate_process_name, format_hex_dump, PCILeechError

    check("parse 0x1000", parse_hex_address("0x1000") == 0x1000)
    check("parse 1000", parse_hex_address("1000") == 0x1000)
    check("parse 0xDEADBEEF", parse_hex_address("0xDEADBEEF") == 0xDEADBEEF)
    check("parse 0x0", parse_hex_address("0x0") == 0)
    check("parse uppercase", parse_hex_address("0xABCD") == 0xABCD)

    # Invalid addresses
    for bad in ["-1", "0xZZZZ", "", "not_hex"]:
        try:
            parse_hex_address(bad)
            check(f"reject '{bad}'", False)
        except PCILeechError:
            check(f"reject '{bad}'", True)

    # Process name validation
    check("valid process name", validate_process_name("explorer.exe") == "explorer.exe")
    check("valid hyphen name", validate_process_name("my-app") == "my-app")
    for bad in ["", "../../../etc/passwd", "a" * 300]:
        try:
            validate_process_name(bad)
            check(f"reject process name '{bad[:20]}'", False)
        except PCILeechError:
            check(f"reject process name '{bad[:20]}'", True)

    # Hex dump formatting
    data = bytes(range(32))
    dump = format_hex_dump(data, 0x1000)
    check("hex dump has address", "0x0000000000001000" in dump)
    check("hex dump has hex bytes", "00 01 02 03" in dump)
    check("hex dump has ASCII", "|" in dump)
    check("hex dump two lines", dump.count("\n") == 1)  # 32 bytes = 2 lines, 1 newline


def test_mcp_tools():
    print("\n--- MCP Tool Registration ---")
    from main import server, list_tools

    tools = asyncio.run(list_tools())
    check(f"tool count is 37", len(tools) == 37)

    expected_names = {
        "memory_read",
        "memory_write",
        "memory_format",
        "system_info",
        "memory_probe",
        "memory_dump",
        "memory_search",
        "memory_patch",
        "process_list",
        "translate_virt2phys",
        "process_virt2phys",
        "module_list",
        "aob_scan",
        "module_dump",
        "module_exports",
        "module_imports",
        "pointer_read",
        "process_regions",
        "benchmark",
        "tlp_send",
        "fpga_config",
        "scatter_read",
        "pe_sections",
        "signature_resolve",
        "rtti_scan",
        "struct_analyze",
        "string_scan",
        "memory_diff",
        "pointer_scan",
        "xref_scan",
        "ue_dump_names",
        "ue_dump_objects",
        "ue_dump_sdk",
        "unity_il2cpp_dump",
        "device_disconnect",
        "device_reconnect",
        "device_status",
    }
    actual_names = {t.name for t in tools}
    check("all expected tools present", actual_names == expected_names)

    for t in tools:
        check(f"  {t.name} has valid schema", t.inputSchema.get("type") == "object")


def test_format_helpers():
    print("\n--- Output Formatters ---")
    from main import format_byte_array, format_dword_array, format_ascii_view

    data = b"\x48\x65\x6c\x6c\x6f\x00\x01\x02"

    ba = format_byte_array(data)
    check("byte array contains values", "72" in ba and "101" in ba)

    da = format_dword_array(data)
    check("dword array format", "0x" in da)

    av = format_ascii_view(data)
    check("ascii view", av.startswith("Hello"))
    check("ascii non-printable", "." in av)


def test_mutual_exclusion():
    print("\n--- Mutual Exclusion Validation ---")
    from main import validate_mutually_exclusive

    check(
        "both set",
        validate_mutually_exclusive({"pid": 1, "process_name": "test"}, "pid", "process_name")
        is not None,
    )
    check("only pid", validate_mutually_exclusive({"pid": 1}, "pid", "process_name") is None)
    check(
        "only name",
        validate_mutually_exclusive({"process_name": "test"}, "pid", "process_name") is None,
    )
    check("neither set", validate_mutually_exclusive({}, "pid", "process_name") is None)


def test_mock_memory_read():
    print("\n--- Mock Memory Read Handler ---")
    from main import handle_memory_read

    mock_wrapper = MagicMock()
    mock_wrapper.read_memory.return_value = b"\x4d\x5a\x90\x00"

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_memory_read(
                {
                    "address": "0x1000",
                    "length": 4,
                }
            )
        )

    check("returns TextContent", len(result) == 1)
    check("contains hex data", "4d5a9000" in result[0].text)
    check("contains address", "0x1000" in result[0].text)
    check("mode is physical", "physical" in result[0].text)
    mock_wrapper.read_memory.assert_called_once_with("0x1000", 4, pid=None, process_name=None)


def test_mock_memory_read_virtual():
    print("\n--- Mock Virtual Memory Read ---")
    from main import handle_memory_read

    mock_wrapper = MagicMock()
    mock_wrapper.read_memory.return_value = b"\xcc" * 8

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_memory_read(
                {
                    "address": "0x7ff7f3a90000",
                    "length": 8,
                    "pid": 1234,
                }
            )
        )

    check("contains PID mode", "PID: 1234" in result[0].text)
    mock_wrapper.read_memory.assert_called_once_with(
        "0x7ff7f3a90000", 8, pid=1234, process_name=None
    )


def test_mock_memory_write():
    print("\n--- Mock Memory Write Handler ---")
    from main import handle_memory_write

    mock_wrapper = MagicMock()
    mock_wrapper.write_memory.return_value = True

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_memory_write(
                {
                    "address": "0x2000",
                    "data": "48656c6c6f",
                }
            )
        )

    check("write success", "Wrote 5 bytes" in result[0].text)
    mock_wrapper.write_memory.assert_called_once()
    call_args = mock_wrapper.write_memory.call_args
    check("correct data", call_args[0][1] == b"Hello")


def test_mock_memory_format():
    print("\n--- Mock Memory Format Handler ---")
    from main import handle_memory_format

    mock_wrapper = MagicMock()
    mock_wrapper.read_memory.return_value = bytes(range(32))

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_memory_format(
                {
                    "address": "0x3000",
                    "length": 32,
                    "formats": ["hexdump", "ascii", "raw"],
                }
            )
        )

    text = result[0].text
    check("has hexdump section", "## Hex Dump" in text)
    check("has ascii section", "## ASCII" in text)
    check("has raw section", "## Raw Hex" in text)
    check("no bytes section", "## Byte Array" not in text)


def test_mock_process_list():
    print("\n--- Mock Process List ---")
    from main import handle_process_list

    mock_wrapper = MagicMock()
    mock_wrapper.list_processes.return_value = [
        {
            "pid": 4,
            "ppid": 0,
            "name": "System",
            "state": 0,
            "dtb": "0x1aa000",
            "is_usermode": False,
        },
        {
            "pid": 1234,
            "ppid": 4,
            "name": "explorer.exe",
            "state": 0,
            "dtb": "0x3e1000",
            "is_usermode": True,
        },
    ]

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(handle_process_list({}))

    text = result[0].text
    check("shows count", "2 process" in text)
    check("shows System", "System" in text)
    check("shows explorer", "explorer.exe" in text)


def test_mock_system_info():
    print("\n--- Mock System Info ---")
    from main import handle_system_info

    mock_wrapper = MagicMock()
    mock_wrapper.get_system_info.return_value = {
        "device": "fpga",
        "kernel_build": 19041,
        "version_major": 10,
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(handle_system_info({"verbose": False}))

    text = result[0].text
    check("shows device", "fpga" in text)
    check("shows kernel build", "19041" in text)


def test_mock_benchmark():
    print("\n--- Mock Benchmark ---")
    from main import handle_benchmark

    mock_wrapper = MagicMock()
    mock_wrapper.benchmark.return_value = {
        "test_type": "read",
        "address": "0x1000",
        "read_iterations": 1000,
        "read_chunk_size": 4096,
        "read_elapsed_s": 0.5,
        "read_mbps": 7.81,
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(handle_benchmark({"test_type": "read"}))

    text = result[0].text
    check("shows MB/s", "7.81 MB/s" in text)


def test_mock_module_list():
    print("\n--- Mock Module List ---")
    from main import handle_module_list

    mock_wrapper = MagicMock()
    mock_wrapper.list_modules.return_value = [
        {
            "name": "kernel32.dll",
            "base": "0x7ff8a0000",
            "size": "0x1a0000",
            "image_size": 0x1A0000,
            "fullname": "kernel32.dll",
            "is_wow64": False,
        },
    ]

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(handle_module_list({"pid": 1234}))

    text = result[0].text
    check("shows module", "kernel32.dll" in text)
    check("shows PID in header", "PID 1234" in text)


def test_mock_aob_scan():
    print("\n--- Mock AOB Scan ---")
    from main import handle_aob_scan

    mock_wrapper = MagicMock()
    mock_wrapper.aob_scan.return_value = [
        {"address": "0x7ff6a001234", "context": "4d5a900003000000"},
    ]

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_aob_scan(
                {
                    "pattern": "4D 5A ?? ?? 03 00",
                    "pid": 1234,
                    "module": "game.exe",
                }
            )
        )

    text = result[0].text
    check("shows match address", "0x7ff6a001234" in text)
    check("shows pattern", "4D 5A ?? ?? 03 00" in text)
    check("shows module scope", "game.exe" in text)


def test_mock_module_dump():
    print("\n--- Mock Module Dump ---")
    from main import handle_module_dump

    mock_wrapper = MagicMock()
    mock_wrapper.module_dump.return_value = {
        "module": "client.dll",
        "base": "0x7ff6a000000",
        "size": 0x200000,
        "file": "/tmp/client.dll_0x7ff6a000000.bin",
        "success": True,
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_module_dump(
                {
                    "module_name": "client.dll",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows module name", "client.dll" in text)
    check("shows file path", "/tmp/client.dll" in text)
    check("shows size", "0x200000" in text)


def test_mock_module_exports():
    print("\n--- Mock Module Exports ---")
    from main import handle_module_exports

    mock_wrapper = MagicMock()
    mock_wrapper.module_exports.return_value = [
        {"name": "CreateInterface", "ordinal": 1, "address": "0x7ff6a012340"},
        {"name": "GetProcAddress", "ordinal": 2, "address": "0x7ff6a012380"},
    ]

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_module_exports(
                {
                    "module_name": "client.dll",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows export count", "2 export" in text)
    check("shows function name", "CreateInterface" in text)


def test_mock_pointer_read():
    print("\n--- Mock Pointer Read ---")
    from main import handle_pointer_read

    mock_wrapper = MagicMock()
    mock_wrapper.pointer_read.return_value = {
        "success": True,
        "error": None,
        "chain": ["0x7ff6a001000", "0x1a2b3c4d60", "0x1a2b3c4da8"],
        "final_address": "0x1a2b3c4da8",
        "value": "0x64 (100)",
        "raw_hex": "6400000000000000",
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_pointer_read(
                {
                    "base_address": "0x7ff6a001000",
                    "offsets": [0x50, 0x48],
                    "read_size": 8,
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows final address", "0x1a2b3c4da8" in text)
    check("shows value", "100" in text)
    check("shows chain", "->" in text)


def test_mock_process_regions():
    print("\n--- Mock Process Regions ---")
    from main import handle_process_regions

    mock_wrapper = MagicMock()
    mock_wrapper.process_regions.return_value = [
        {
            "start": "0x7ff6a000000",
            "size": 0x200000,
            "size_str": "2.0 MB",
            "protection": "PAGE_EXECUTE_READ",
            "type": "Image",
            "info": "game.exe",
        },
        {
            "start": "0x1a000000",
            "size": 0x1000,
            "size_str": "4.0 KB",
            "protection": "PAGE_READWRITE",
            "type": "Private",
            "info": "",
        },
    ]

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(handle_process_regions({"pid": 1234}))

    text = result[0].text
    check("shows region count", "2 region" in text)
    check("shows protection", "PAGE_EXECUTE_READ" in text)
    check("shows game.exe", "game.exe" in text)


def test_mock_pe_sections():
    print("\n--- Mock PE Sections ---")
    from main import handle_pe_sections

    mock_wrapper = MagicMock()
    mock_wrapper.pe_sections.return_value = [
        {
            "name": ".text",
            "virtual_address": "0x7ff6a001000",
            "virtual_size": 0x100000,
            "raw_size": 0x100000,
            "characteristics": "0x60000020",
            "flags": ["CODE", "EXECUTE", "READ"],
            "rva": "0x1000",
        },
        {
            "name": ".rdata",
            "virtual_address": "0x7ff6a101000",
            "virtual_size": 0x50000,
            "raw_size": 0x50000,
            "characteristics": "0x40000040",
            "flags": ["INITIALIZED_DATA", "READ"],
            "rva": "0x101000",
        },
        {
            "name": ".data",
            "virtual_address": "0x7ff6a151000",
            "virtual_size": 0x20000,
            "raw_size": 0x10000,
            "characteristics": "0xc0000040",
            "flags": ["INITIALIZED_DATA", "READ", "WRITE"],
            "rva": "0x151000",
        },
    ]

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_pe_sections(
                {
                    "module_name": "game.exe",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows section count", "3 section" in text)
    check("shows .text", ".text" in text)
    check("shows .rdata", ".rdata" in text)
    check("shows EXECUTE flag", "EXECUTE" in text)


def test_mock_signature_resolve():
    print("\n--- Mock Signature Resolve ---")
    from main import handle_signature_resolve

    mock_wrapper = MagicMock()
    mock_wrapper.signature_resolve.return_value = {
        "success": True,
        "error": None,
        "pattern": "48 8B 05 ?? ?? ?? ??",
        "match_address": "0x7ff6a012345",
        "operand": 0x1234,
        "resolved_address": "0x7ff6a013580",
        "instruction_length": 7,
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_signature_resolve(
                {
                    "pattern": "48 8B 05 ?? ?? ?? ??",
                    "pid": 1234,
                    "module": "game.exe",
                }
            )
        )

    text = result[0].text
    check("shows resolved address", "0x7ff6a013580" in text)
    check("shows match address", "0x7ff6a012345" in text)
    check("shows pattern", "48 8B 05" in text)


def test_mock_rtti_scan():
    print("\n--- Mock RTTI Scan ---")
    from main import handle_rtti_scan

    mock_wrapper = MagicMock()
    mock_wrapper.rtti_scan.return_value = [
        {
            "class_name": "CPlayer",
            "mangled_name": ".?AVCPlayer@@",
            "type_descriptor": "0x7ff6a200000",
            "vtable": "0x7ff6a100000",
            "base_classes": ["CEntity", "CBaseObject"],
        },
        {
            "class_name": "CEntity",
            "mangled_name": ".?AVCEntity@@",
            "type_descriptor": "0x7ff6a200100",
        },
    ]

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_rtti_scan(
                {
                    "module": "game.exe",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows class count", "2 class" in text)
    check("shows CPlayer", "CPlayer" in text)
    check("shows vtable", "vtable:" in text)
    check("shows inheritance", "CEntity" in text)


def test_mock_struct_analyze():
    print("\n--- Mock Struct Analyze ---")
    from main import handle_struct_analyze

    mock_wrapper = MagicMock()
    mock_wrapper.struct_analyze.return_value = {
        "base_address": "0x1a000000",
        "size": 64,
        "fields": [
            {"offset": "0x0", "size": 8, "type": "vtable_ptr", "value": "0x7ff6a100000"},
            {"offset": "0x8", "size": 8, "type": "null", "value": "0x0"},
            {
                "offset": "0x10",
                "size": 12,
                "type": "vec3",
                "value": "(100.5000, 200.3000, 50.1000)",
            },
            {"offset": "0x1c", "size": 4, "type": "int32", "value": "100"},
        ],
        "pointer_targets": {"0x7ff6a100000": "deadbeef" * 4},
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_struct_analyze(
                {
                    "address": "0x1a000000",
                    "size": 64,
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows vtable_ptr", "vtable_ptr" in text)
    check("shows vec3", "vec3" in text)
    check("shows int32", "int32" in text)
    check("shows position values", "100.5000" in text)


def test_mock_string_scan():
    print("\n--- Mock String Scan ---")
    from main import handle_string_scan

    mock_wrapper = MagicMock()
    mock_wrapper.string_scan.return_value = [
        {"address": "0x7ff6a200000", "encoding": "ascii", "length": 12, "string": "CPlayerClass"},
        {"address": "0x7ff6a200100", "encoding": "utf-16le", "length": 8, "string": "GameName"},
    ]

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_string_scan(
                {
                    "pid": 1234,
                    "module": "game.exe",
                    "pattern": "Player|Game",
                    "min_length": 4,
                }
            )
        )

    text = result[0].text
    check("shows string count", "2 string" in text)
    check("shows ascii string", "CPlayerClass" in text)
    check("shows utf-16le", "utf-16le" in text)


def test_mock_memory_diff():
    print("\n--- Mock Memory Diff ---")
    from main import handle_memory_diff

    # First call: snapshot
    mock_wrapper = MagicMock()
    mock_wrapper.memory_diff.return_value = {
        "action": "snapshot_taken",
        "label": "health",
        "address": "0x1a000000",
        "size": 256,
        "message": 'Initial snapshot "health" taken. Call again after a game action to see changes.',
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_memory_diff(
                {
                    "address": "0x1a000000",
                    "size": 256,
                    "label": "health",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("snapshot taken message", "snapshot taken" in text.lower() or "Snapshot taken" in text)

    # Second call: diff
    mock_wrapper.memory_diff.return_value = {
        "action": "diff",
        "label": "health",
        "address": "0x1a000000",
        "size": 256,
        "total_changes": 1,
        "bytes_changed": 4,
        "changes": [
            {
                "offset": "0x1c",
                "address": "0x1a00001c",
                "size": 4,
                "old": "64000000",
                "new": "55000000",
                "as_int32": "100 -> 85 (delta: -15)",
                "as_float": "0.0000 -> 0.0000",
            }
        ],
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_memory_diff(
                {
                    "address": "0x1a000000",
                    "size": 256,
                    "label": "health",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows change count", "1 region" in text)
    check("shows int32 interpretation", "100 -> 85" in text)
    check("shows delta", "delta: -15" in text)


def test_demangle_msvc():
    print("\n--- MSVC Name Demangling ---")
    from vmm_wrapper import VmmWrapper

    check("simple class", VmmWrapper._demangle_msvc(".?AVCPlayer@@") == "CPlayer")
    check("struct", VmmWrapper._demangle_msvc(".?AUVector3@@") == "Vector3")
    check("namespace", VmmWrapper._demangle_msvc(".?AVFoo@Bar@@") == "Bar::Foo")
    check("deep namespace", VmmWrapper._demangle_msvc(".?AVFoo@Bar@Baz@@") == "Baz::Bar::Foo")
    check("no suffix", VmmWrapper._demangle_msvc(".?AVSimple") == "Simple")


def test_mock_pointer_scan():
    print("\n--- Mock Pointer Scan ---")
    from main import handle_pointer_scan

    mock_wrapper = MagicMock()
    mock_wrapper.pointer_scan.return_value = {
        "chains": [
            {
                "module": "game.exe",
                "base_offset": 0x1234,
                "offsets": [0x10, 0x48],
                "depth": 2,
                "expression": "[[game.exe+0x1234]+0x10]+0x48",
            },
        ],
        "stats": {
            "target": "0x1a2b3c4d",
            "max_depth": 5,
            "max_offset": 4096,
            "levels_searched": 3,
            "total_chains_found": 1,
            "addresses_scanned": 5000,
        },
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_pointer_scan(
                {
                    "target_address": "0x1a2b3c4d",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows chain expression", "game.exe+0x1234" in text)
    check("shows chain count", "1" in text)
    check("shows target", "0x1a2b3c4d" in text)


def test_mock_xref_scan():
    print("\n--- Mock XRef Scan ---")
    from main import handle_xref_scan

    mock_wrapper = MagicMock()
    mock_wrapper.xref_scan.return_value = {
        "target": "0x7ff6a013580",
        "module": "game.exe",
        "code_refs": [
            {
                "address": "0x7ff6a012345",
                "type": "rip_rel_7",
                "instruction_bytes": "488b05351200",
                "section": ".text",
                "displacement": 0x1235,
            },
        ],
        "data_refs": [
            {
                "address": "0x7ff6a101000",
                "section": ".rdata",
                "context": "8035a0f67f000000",
            },
        ],
        "stats": {
            "code_sections_scanned": 1,
            "data_sections_scanned": 2,
            "total_bytes_scanned": 1048576,
        },
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_xref_scan(
                {
                    "target_address": "0x7ff6a013580",
                    "module": "game.exe",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows code ref", "0x7ff6a012345" in text)
    check("shows ref type", "rip_rel_7" in text)
    check("shows data ref", "0x7ff6a101000" in text)
    check("shows code refs count", "Code refs:" in text)


def test_mock_ue_dump_names():
    print("\n--- Mock UE Dump Names ---")
    from main import handle_ue_dump_names

    mock_wrapper = MagicMock()
    mock_wrapper.ue_dump_names.return_value = {
        "gnames_address": "0x7ff6a500000",
        "total_names": 85000,
        "blocks_read": 3,
        "names": [
            {"index": 0, "name": "None"},
            {"index": 1, "name": "ByteProperty"},
            {"index": 2, "name": "IntProperty"},
        ],
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_ue_dump_names(
                {
                    "gnames_address": "0x7ff6a500000",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows total names", "85000" in text)
    check("shows blocks", "3" in text)
    check("shows name entry", "ByteProperty" in text)


def test_mock_ue_dump_objects():
    print("\n--- Mock UE Dump Objects ---")
    from main import handle_ue_dump_objects

    mock_wrapper = MagicMock()
    mock_wrapper.ue_dump_objects.return_value = {
        "gobjects_address": "0x7ff6a600000",
        "total_objects": 45000,
        "objects": [
            {
                "index": 0,
                "address": "0x1a000000",
                "name": "PlayerController",
                "class_name": "Class",
                "outer": None,
                "flags": 0x41,
            },
        ],
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_ue_dump_objects(
                {
                    "gobjects_address": "0x7ff6a600000",
                    "pid": 1234,
                }
            )
        )

    text = result[0].text
    check("shows total objects", "45000" in text)
    check("shows object name", "PlayerController" in text)
    check("shows class name", "Class" in text)


def test_mock_ue_dump_sdk():
    print("\n--- Mock UE Dump SDK ---")
    from main import handle_ue_dump_sdk

    mock_wrapper = MagicMock()
    mock_wrapper.ue_dump_sdk.return_value = {
        "gobjects_address": "0x7ff6a600000",
        "gnames_address": "0x7ff6a500000",
        "total_classes": 120,
        "total_properties": 890,
        "output_file": "/tmp/sdk.h",
        "classes": [
            {
                "name": "APlayerController",
                "super": "AController",
                "size": 0x5A0,
                "property_count": 15,
            },
        ],
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_ue_dump_sdk(
                {
                    "gobjects_address": "0x7ff6a600000",
                    "gnames_address": "0x7ff6a500000",
                    "pid": 1234,
                    "output_file": "/tmp/sdk.h",
                }
            )
        )

    text = result[0].text
    check("shows total classes", "120" in text)
    check("shows total properties", "890" in text)
    check("shows output file", "/tmp/sdk.h" in text)
    check("shows class name", "APlayerController" in text)
    check("shows super class", "AController" in text)


def test_mock_unity_il2cpp_dump():
    print("\n--- Mock Unity IL2CPP Dump ---")
    from main import handle_unity_il2cpp_dump

    mock_wrapper = MagicMock()
    mock_wrapper.unity_il2cpp_dump.return_value = {
        "game_assembly": "0x7ff6a000000",
        "metadata_address": "0x1b000000",
        "metadata_version": 29,
        "total_types": 1234,
        "total_fields": 5678,
        "total_methods": 9012,
        "output_file": "/tmp/il2cpp_dump.cs",
        "classes": [
            {
                "name": "PlayerController",
                "namespace": "Game.Controllers",
                "field_count": 5,
                "method_count": 12,
            },
        ],
    }

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(
            handle_unity_il2cpp_dump(
                {
                    "pid": 1234,
                    "output_file": "/tmp/il2cpp_dump.cs",
                }
            )
        )

    text = result[0].text
    check("shows metadata version", "29" in text)
    check("shows total types", "1234" in text)
    check("shows total methods", "9012" in text)
    check("shows output file", "/tmp/il2cpp_dump.cs" in text)
    check("shows class name", "PlayerController" in text)
    check("shows namespace", "Game.Controllers" in text)


def test_pointer_scanner_unit():
    """Unit tests for PointerScanner with crafted data."""
    print("\n--- Pointer Scanner Unit Tests ---")
    from pointer_scanner import PointerScanner

    # Create a mock process with controlled memory
    mock_proc = MagicMock()

    # Module list: one module at base 0x7ff600000000
    mock_mod = MagicMock()
    mock_mod.name = "game.exe"
    mock_mod.base = 0x7FF600000000
    mock_mod.image_size = 0x100000
    mock_proc.module_list.return_value = [mock_mod]

    # VAD list: two regions
    mock_proc.maps.vad.return_value = [
        {"start": 0x7FF600000000, "size": 0x100000},  # module region
        {"start": 0x1A000000, "size": 0x10000},  # heap region
    ]

    target = 0x1A005000
    # At game.exe+0x1230 (module region, 8-byte aligned), pointer to target

    # Module region data: at offset 0x1230, an 8-byte pointer to target
    module_data = bytearray(0x100000)
    struct.pack_into("<Q", module_data, 0x1230, target)

    def mock_read(addr, size, flags=0):
        if 0x7FF600000000 <= addr < 0x7FF600100000:
            offset = addr - 0x7FF600000000
            return bytes(module_data[offset : offset + size])
        return b"\x00" * size

    mock_proc.memory.read = mock_read

    scanner = PointerScanner(mock_proc)
    result = scanner.scan(target, max_depth=1, max_offset=0, max_results=10)

    check("returns dict with chains", "chains" in result)
    check("returns dict with stats", "stats" in result)
    check("found at least one chain", len(result["chains"]) >= 1)

    if result["chains"]:
        chain = result["chains"][0]
        check("chain has module", chain["module"] == "game.exe")
        check("chain has base_offset 0x1230", chain["base_offset"] == 0x1230)
        check("chain has expression", "game.exe" in chain["expression"])


def test_xref_scanner_unit():
    """Unit tests for XRefScanner with crafted binary data."""
    print("\n--- XRef Scanner Unit Tests ---")
    from pointer_scanner import XRefScanner

    mock_proc = MagicMock()

    # Module at base 0x7ff600000000
    mock_mod = MagicMock()
    mock_mod.base = 0x7FF600000000
    mock_mod.image_size = 0x10000
    mock_proc.module.return_value = mock_mod

    # Build a fake PE with .text and .rdata sections
    # DOS header: e_lfanew at offset 0x3C = 0x80
    # PE header at 0x80: signature + COFF header + optional header
    # Sections at 0x80 + 24 + 240 (x64 optional header size)

    pe_data = bytearray(0x10000)

    # DOS header
    struct.pack_into("<H", pe_data, 0, 0x5A4D)  # MZ
    struct.pack_into("<I", pe_data, 0x3C, 0x80)  # e_lfanew

    # PE signature
    struct.pack_into("<I", pe_data, 0x80, 0x4550)  # PE\0\0

    # COFF header (20 bytes at 0x84)
    struct.pack_into("<H", pe_data, 0x84, 0x8664)  # Machine = AMD64
    struct.pack_into("<H", pe_data, 0x86, 2)  # NumberOfSections = 2
    struct.pack_into("<H", pe_data, 0x94, 240)  # SizeOfOptionalHeader

    # Section headers start at 0x80 + 4 + 20 + 240 = 0x188
    sec_offset = 0x188

    # .text section
    pe_data[sec_offset : sec_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", pe_data, sec_offset + 8, 0x1000)  # VirtualSize
    struct.pack_into("<I", pe_data, sec_offset + 12, 0x1000)  # VirtualAddress (RVA)
    struct.pack_into("<I", pe_data, sec_offset + 16, 0x1000)  # SizeOfRawData
    struct.pack_into("<I", pe_data, sec_offset + 36, 0x60000020)  # CODE|EXECUTE|READ

    # .rdata section
    sec_offset += 40
    pe_data[sec_offset : sec_offset + 8] = b".rdata\x00\x00"
    struct.pack_into("<I", pe_data, sec_offset + 8, 0x1000)  # VirtualSize
    struct.pack_into("<I", pe_data, sec_offset + 12, 0x2000)  # VirtualAddress (RVA)
    struct.pack_into("<I", pe_data, sec_offset + 16, 0x1000)  # SizeOfRawData
    struct.pack_into("<I", pe_data, sec_offset + 36, 0x40000040)  # INITIALIZED_DATA|READ

    # Target address for xrefs
    base = 0x7FF600000000
    target = base + 0x5000

    # Put a 7-byte RIP-relative instruction in .text at RVA 0x1100
    # mov rax, [rip + disp32] where disp resolves to target
    # instruction at base + 0x1100, length 7, target = base + 0x1100 + 7 + disp
    # disp = target - (base + 0x1100 + 7) = 0x5000 - 0x1107 = 0x3EF9
    disp = target - (base + 0x1100 + 7)
    pe_data[0x1100] = 0x48  # REX.W
    pe_data[0x1101] = 0x8B  # MOV
    pe_data[0x1102] = 0x05  # ModRM (rip-relative)
    struct.pack_into("<i", pe_data, 0x1103, disp)

    # Put a data pointer in .rdata at RVA 0x2100 pointing to target
    struct.pack_into("<Q", pe_data, 0x2100, target)

    def mock_read(addr, size, flags=0):
        offset = addr - base
        if 0 <= offset < len(pe_data):
            end = min(offset + size, len(pe_data))
            result = pe_data[offset:end]
            if len(result) < size:
                result += b"\x00" * (size - len(result))
            return bytes(result)
        return b"\x00" * size

    mock_proc.memory.read = mock_read

    scanner = XRefScanner(mock_proc)
    result = scanner.scan(target, module_name="game.exe")

    check("returns code_refs", "code_refs" in result)
    check("returns data_refs", "data_refs" in result)
    check("returns stats", "stats" in result)
    check("found code xref", len(result["code_refs"]) >= 1)
    check("found data xref", len(result["data_refs"]) >= 1)


def test_error_handling():
    print("\n--- Error Handling ---")
    from main import call_tool, handle_memory_write
    from vmm_wrapper import MemoryAccessError

    # Test PCILeechError propagation through call_tool
    mock_wrapper = MagicMock()
    mock_wrapper.read_memory.side_effect = MemoryAccessError("Access denied at 0x1000")

    with patch("main.get_wrapper", return_value=mock_wrapper):
        result = asyncio.run(call_tool("memory_read", {"address": "0x1000", "length": 16}))

    check("error in response", "Access denied" in result[0].text)

    # Invalid hex data (caught before wrapper call)
    mock_wrapper2 = MagicMock()
    with patch("main.get_wrapper", return_value=mock_wrapper2):
        result = asyncio.run(call_tool("memory_write", {"address": "0x1000", "data": "ZZZZ"}))
    check("invalid hex rejected", "Invalid hex" in result[0].text)

    # Mutual exclusion (caught before wrapper call)
    mock_wrapper3 = MagicMock()
    with patch("main.get_wrapper", return_value=mock_wrapper3):
        result = asyncio.run(
            call_tool(
                "memory_read", {"address": "0x1000", "length": 4, "pid": 1, "process_name": "test"}
            )
        )
    check("mutual exclusion error", "mutually exclusive" in result[0].text)

    # Unknown tool
    result = asyncio.run(call_tool("nonexistent_tool", {}))
    check("unknown tool error", "Unknown tool" in result[0].text)


# ==================== Run All ====================

if __name__ == "__main__":
    print("MCP Server for PCILeech (Linux) - Test Suite")
    print("=" * 60)

    test_helpers()
    test_mcp_tools()
    test_format_helpers()
    test_mutual_exclusion()
    test_mock_memory_read()
    test_mock_memory_read_virtual()
    test_mock_memory_write()
    test_mock_memory_format()
    test_mock_process_list()
    test_mock_system_info()
    test_mock_benchmark()
    test_mock_module_list()
    test_mock_aob_scan()
    test_mock_module_dump()
    test_mock_module_exports()
    test_mock_pointer_read()
    test_mock_process_regions()
    test_mock_pe_sections()
    test_mock_signature_resolve()
    test_mock_rtti_scan()
    test_mock_struct_analyze()
    test_mock_string_scan()
    test_mock_memory_diff()
    test_demangle_msvc()
    test_mock_pointer_scan()
    test_mock_xref_scan()
    test_mock_ue_dump_names()
    test_mock_ue_dump_objects()
    test_mock_ue_dump_sdk()
    test_mock_unity_il2cpp_dump()
    test_pointer_scanner_unit()
    test_xref_scanner_unit()
    test_error_handling()

    print("\n" + "=" * 60)
    print(f"RESULTS: {PASS} passed, {FAIL} failed")
    print("=" * 60)

    if FAIL > 0:
        print("\nNote: These are unit tests using mocks. For hardware integration")
        print("tests, connect your DMA device and update config.json.")
        sys.exit(1)
    else:
        print("\nAll unit tests passed! For hardware testing:")
        print("  1. Connect your DMA/FPGA device")
        print("  2. Update config.json with device type (e.g. 'fpga')")
        print("  3. Run: .venv/bin/python main.py")
        sys.exit(0)

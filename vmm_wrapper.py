"""
Native Linux wrapper for MemProcFS / LeechCore.

Uses the memprocfs and leechcorepyc Python packages directly
instead of shelling out to pcileech.exe.
"""

import json
import math
import os
import re
import time
import struct
from pathlib import Path
from typing import Optional

# ==================== Constants ====================
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_HEX_PATTERN = re.compile(r"^[0-9a-fA-F]+$")
_PROCESS_NAME_PATTERN = re.compile(r"^[\w.\-\s]+$")


# ==================== Exceptions ====================


class PCILeechError(Exception):
    """Base exception for PCILeech operations."""

    pass


class DeviceNotFoundError(PCILeechError):
    """Raised when PCILeech hardware device is not found."""

    pass


class MemoryAccessError(PCILeechError):
    """Raised when memory access fails."""

    pass


class SignatureNotFoundError(PCILeechError):
    """Raised when signature file is not found."""

    pass


class ProbeNotSupportedError(PCILeechError):
    """Raised when probe is not supported (non-FPGA device)."""

    pass


class KMDError(PCILeechError):
    """Raised when kernel module operation fails."""

    pass


# ==================== Helpers ====================


def parse_hex_address(value: str, name: str = "address") -> int:
    if not isinstance(value, str):
        raise PCILeechError(f"{name} must be a hex string, got {type(value).__name__}")
    s = value.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if s.startswith("-"):
        raise PCILeechError(f"{name} cannot be negative: {value}")
    if not s or not _HEX_PATTERN.fullmatch(s):
        raise PCILeechError(f"Invalid {name} format '{value}' (expected hex like 0x1000)")
    try:
        n = int(s, 16)
    except ValueError as e:
        raise PCILeechError(f"Invalid {name} format '{value}': {e}")
    if n > _U64_MAX:
        raise PCILeechError(f"{name} exceeds 64-bit range: {value}")
    return n


def validate_process_name(name: str) -> str:
    if not name or not name.strip():
        raise PCILeechError("process_name cannot be empty")
    name = name.strip()
    if len(name) > 260:
        raise PCILeechError(f"process_name too long: {len(name)} chars (max 260)")
    if not _PROCESS_NAME_PATTERN.fullmatch(name):
        raise PCILeechError(
            f"process_name contains invalid characters: '{name}'. "
            f"Only alphanumeric, dot, underscore, hyphen, and space allowed"
        )
    return name


def _format_size(size: int) -> str:
    if size >= 1024 * 1024:
        return f"{size / (1024 * 1024):.1f} MB"
    if size >= 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size} B"


def format_hex_dump(data: bytes, base_addr: int) -> str:
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        addr = f"0x{base_addr + i:016x}"
        hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(47)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{addr}: {hex_part}  |{ascii_part}|")
    return "\n".join(lines)


# ==================== Wrapper ====================


class VmmWrapper:
    """Native wrapper around memprocfs and leechcorepyc."""

    def __init__(self, config_path: str | None = None):
        if config_path is None:
            # Allow overriding the config location (useful for `uvx`/`pipx`
            # installs where the bundled config.json is read-only).
            config_path = os.environ.get("PCILEECH_MCP_CONFIG") or str(
                Path(__file__).parent / "config.json"
            )

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except FileNotFoundError:
            raise PCILeechError(f"Configuration file not found: {config_path}")
        except json.JSONDecodeError as e:
            raise PCILeechError(f"Invalid JSON in configuration file: {e}")

        self._device_type = config.get("device", {}).get("type", "fpga")
        self._remote = config.get("device", {}).get("remote", "")
        self._extra_args = config.get("device", {}).get("extra_args", [])

        self._vmm = None
        self._lc = None
        self._snapshots = {}

    def _get_vmm(self):
        """Lazily initialize the memprocfs Vmm instance."""
        if self._vmm is None:
            try:
                import memprocfs
            except ImportError:
                raise PCILeechError("memprocfs package not installed. Run: pip install memprocfs")
            args = ["-device", self._device_type]
            if self._remote:
                args.extend(["-remote", self._remote])
            args.extend(self._extra_args)
            try:
                self._vmm = memprocfs.Vmm(args)
            except Exception as e:
                raise DeviceNotFoundError(f"Failed to initialize MemProcFS: {e}")
        return self._vmm

    def _get_lc(self):
        """Lazily initialize the leechcorepyc LeechCore instance."""
        if self._lc is None:
            try:
                import leechcorepyc
            except ImportError:
                raise PCILeechError(
                    "leechcorepyc package not installed. Run: pip install leechcorepyc"
                )
            try:
                self._lc = leechcorepyc.LeechCore(self._device_type, self._remote)
            except Exception as e:
                raise DeviceNotFoundError(f"Failed to initialize LeechCore: {e}")
        return self._lc

    def _resolve_process(self, pid: int | None, process_name: str | None):
        """Resolve a process by PID or name. Returns VmmProcess."""
        if pid is not None and process_name is not None:
            raise PCILeechError("pid and process_name are mutually exclusive")
        vmm = self._get_vmm()
        if pid is not None:
            if pid <= 0:
                raise PCILeechError(f"pid must be positive, got {pid}")
            try:
                return vmm.process(pid)
            except Exception as e:
                raise PCILeechError(f"Process with PID {pid} not found: {e}")
        if process_name is not None:
            process_name = validate_process_name(process_name)
            try:
                return vmm.process(process_name)
            except Exception as e:
                raise PCILeechError(f"Process '{process_name}' not found: {e}")
        return None

    def close(self):
        if self._vmm is not None:
            try:
                self._vmm.close()
            except Exception:
                pass
            self._vmm = None
        if self._lc is not None:
            try:
                self._lc.close()
            except Exception:
                pass
            self._lc = None

    # ==================== Core Memory ====================

    def read_memory(
        self, address: str, length: int, pid: int | None = None, process_name: str | None = None
    ) -> bytes:
        addr_int = parse_hex_address(address)
        if length < 1:
            raise PCILeechError("length must be >= 1")
        if length > 1048576:
            raise PCILeechError("length must be <= 1MB (1048576)")

        proc = self._resolve_process(pid, process_name)
        try:
            if proc is not None:
                import memprocfs

                data = proc.memory.read(addr_int, length, memprocfs.FLAG_ZEROPAD_ON_FAIL)
            else:
                vmm = self._get_vmm()
                import memprocfs

                data = vmm.memory.read(addr_int, length, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        except Exception as e:
            raise MemoryAccessError(f"Memory read failed at 0x{addr_int:x}: {e}")

        return data

    def write_memory(
        self, address: str, data: bytes, pid: int | None = None, process_name: str | None = None
    ) -> bool:
        addr_int = parse_hex_address(address)
        if not data:
            raise PCILeechError("data cannot be empty")

        proc = self._resolve_process(pid, process_name)
        try:
            if proc is not None:
                proc.memory.write(addr_int, data)
            else:
                vmm = self._get_vmm()
                vmm.memory.write(addr_int, data)
        except Exception as e:
            raise MemoryAccessError(f"Memory write failed at 0x{addr_int:x}: {e}")

        return True

    def scatter_read(
        self, reads: list[dict], pid: int | None = None, process_name: str | None = None
    ) -> list[dict]:
        """Batch-read multiple disjoint memory regions in a single scatter operation (~10x faster)."""
        if not reads:
            raise PCILeechError("reads list cannot be empty")
        if len(reads) > 1024:
            raise PCILeechError("Maximum 1024 reads per scatter call")

        proc = self._resolve_process(pid, process_name)
        import memprocfs

        if proc is not None:
            scatter = proc.memory.scatter_initialize(memprocfs.FLAG_ZEROPAD_ON_FAIL)
        else:
            vmm = self._get_vmm()
            scatter = vmm.memory.scatter_initialize(memprocfs.FLAG_ZEROPAD_ON_FAIL)

        try:
            parsed = []
            for entry in reads:
                addr = parse_hex_address(entry["address"])
                size = entry["size"]
                if size < 1 or size > 1048576:
                    raise PCILeechError(f"Read size must be 1-1MB, got {size}")
                parsed.append((addr, size))

            scatter.prepare([[addr, size] for addr, size in parsed])
            scatter.execute()

            results = []
            for addr, size in parsed:
                data = scatter.read(addr, size)
                results.append(
                    {
                        "address": f"0x{addr:x}",
                        "size": len(data),
                        "data": data.hex(),
                    }
                )
            return results
        finally:
            scatter.close()

    # ==================== System ====================

    def get_system_info(self, verbose: bool = False) -> dict:
        vmm = self._get_vmm()
        info = {
            "device": self._device_type,
        }

        try:
            import memprocfs

            info["version_major"] = vmm.get_config(memprocfs.OPT_WIN_VERSION_MAJOR)
            info["version_minor"] = vmm.get_config(memprocfs.OPT_WIN_VERSION_MINOR)
            info["version_build"] = vmm.get_config(memprocfs.OPT_WIN_VERSION_BUILD)
        except Exception:
            pass

        try:
            info["kernel_build"] = vmm.kernel.build
        except Exception:
            pass

        try:
            info["memmap"] = vmm.maps.memmap()
        except Exception:
            pass

        if verbose:
            try:
                lc = self._get_lc()
                import leechcorepyc

                info["fpga_id"] = lc.get_option(leechcorepyc.LC_OPT_FPGA_FPGA_ID)
                info["fpga_version_major"] = lc.get_option(leechcorepyc.LC_OPT_FPGA_VERSION_MAJOR)
                info["fpga_version_minor"] = lc.get_option(leechcorepyc.LC_OPT_FPGA_VERSION_MINOR)
                info["fpga_device_id"] = lc.get_option(leechcorepyc.LC_OPT_FPGA_DEVICE_ID)
                info["is_fpga"] = True
            except Exception:
                info["is_fpga"] = False

        return info

    def probe_memory(self, min_addr: str = "0x0", max_addr: str | None = None) -> list[dict]:
        vmm = self._get_vmm()
        try:
            memmap = vmm.maps.memmap()
        except Exception as e:
            raise ProbeNotSupportedError(f"Memory probe failed: {e}")

        regions = []
        min_int = parse_hex_address(min_addr, "min_address")
        max_int = parse_hex_address(max_addr, "max_address") if max_addr else _U64_MAX

        for entry in memmap:
            start = entry.get("pa", entry.get("address", 0))
            size = entry.get("cb", entry.get("size", 0))
            end = start + size - 1

            if end < min_int or start > max_int:
                continue

            regions.append(
                {
                    "start": f"0x{start:x}",
                    "end": f"0x{end:x}",
                    "size_mb": size / (1024 * 1024),
                    "status": "readable",
                }
            )

        return regions

    def dump_memory(
        self, min_addr: str, max_addr: str, output_file: str | None = None, force: bool = False
    ) -> dict:
        min_int = parse_hex_address(min_addr, "min_address")
        max_int = parse_hex_address(max_addr, "max_address")

        if max_int <= min_int:
            raise PCILeechError("max_address must be greater than min_address")

        size = max_int - min_int
        if size > 256 * 1024 * 1024:
            raise PCILeechError("Dump size exceeds 256MB limit")

        if output_file is None:
            output_file = f"dump_0x{min_int:x}-0x{max_int:x}.raw"

        vmm = self._get_vmm()
        import memprocfs

        flags = memprocfs.FLAG_ZEROPAD_ON_FAIL if force else 0

        try:
            data = vmm.memory.read(min_int, size, flags)
        except Exception as e:
            raise MemoryAccessError(f"Memory dump failed: {e}")

        with open(output_file, "wb") as f:
            f.write(data)

        return {
            "min_address": f"0x{min_int:x}",
            "max_address": f"0x{max_int:x}",
            "size": len(data),
            "file": os.path.abspath(output_file),
            "success": True,
            "output": f"Dumped {len(data)} bytes to {output_file}",
        }

    def search_memory(
        self,
        pattern: str | None = None,
        min_addr: str | None = None,
        max_addr: str | None = None,
        find_all: bool = False,
    ) -> list[dict]:
        if not pattern:
            raise PCILeechError("pattern must be provided")

        # Validate hex pattern
        clean = pattern.replace(" ", "")
        if not _HEX_PATTERN.fullmatch(clean):
            raise PCILeechError(f"Invalid hex pattern: {pattern}")
        if len(clean) % 2 != 0:
            raise PCILeechError("Hex pattern must have even length")

        search_bytes = bytes.fromhex(clean)
        min_int = parse_hex_address(min_addr, "min_address") if min_addr else 0
        max_int = parse_hex_address(max_addr, "max_address") if max_addr else 0x100000000

        chunk_size = 0x100000  # 1MB chunks
        matches = []

        vmm = self._get_vmm()
        import memprocfs

        addr = min_int
        while addr < max_int:
            read_size = min(chunk_size, max_int - addr)
            try:
                data = vmm.memory.read(addr, read_size, memprocfs.FLAG_ZEROPAD_ON_FAIL)
            except Exception:
                addr += read_size
                continue

            offset = 0
            while True:
                idx = data.find(search_bytes, offset)
                if idx == -1:
                    break
                match_addr = addr + idx
                context = data[idx : idx + min(32, len(data) - idx)]
                matches.append({"address": f"0x{match_addr:x}", "line": context.hex()})
                if not find_all:
                    return matches
                offset = idx + 1

            addr += read_size

        return matches

    def patch_memory(
        self,
        signature: str,
        min_addr: str | None = None,
        max_addr: str | None = None,
        patch_all: bool = False,
    ) -> dict:
        raise PCILeechError(
            "Signature-based patching requires .sig files and is not yet "
            "supported in the native Linux version. Use memory_search + "
            "memory_write for manual patching."
        )

    def list_processes(self) -> list[dict]:
        vmm = self._get_vmm()
        processes = []
        try:
            for proc in vmm.process_list():
                processes.append(
                    {
                        "pid": proc.pid,
                        "ppid": proc.ppid,
                        "name": proc.name,
                        "state": proc.state,
                        "dtb": f"0x{proc.dtb:x}",
                        "is_usermode": proc.is_usermode,
                    }
                )
        except Exception as e:
            raise PCILeechError(f"Process list failed: {e}")

        return processes

    # ==================== Address Translation ====================

    def translate_virt2phys(
        self, virt_addr: str, cr3: str | None = None, pid: int | None = None
    ) -> dict:
        virt_int = parse_hex_address(virt_addr, "virtual_address")

        if pid is not None:
            proc = self._resolve_process(pid, None)
            try:
                phys = proc.memory.virt2phys(virt_int)
                return {
                    "virtual": f"0x{virt_int:x}",
                    "physical": f"0x{phys:x}",
                    "pid": pid,
                    "success": True,
                    "error": None,
                }
            except Exception as e:
                return {
                    "virtual": f"0x{virt_int:x}",
                    "physical": None,
                    "pid": pid,
                    "success": False,
                    "error": str(e),
                }

        if cr3 is None:
            raise PCILeechError("Either cr3 or pid must be provided")

        cr3_int = parse_hex_address(cr3, "cr3")
        # Use low-level LeechCore for CR3-based translation
        # Read page table entries manually
        return {
            "virtual": f"0x{virt_int:x}",
            "cr3": f"0x{cr3_int:x}",
            "physical": None,
            "success": False,
            "error": "CR3-based translation requires pid-based lookup via memprocfs. "
            "Use process_virt2phys with a PID instead.",
        }

    def process_virt2phys(self, pid: int, virt_addr: str) -> dict:
        virt_int = parse_hex_address(virt_addr, "virtual_address")

        if not isinstance(pid, int) or pid <= 0:
            raise PCILeechError(f"pid must be a positive integer, got {pid}")

        proc = self._resolve_process(pid, None)
        try:
            phys = proc.memory.virt2phys(virt_int)
            return {
                "pid": pid,
                "virtual": f"0x{virt_int:x}",
                "physical": f"0x{phys:x}",
                "dtb": f"0x{proc.dtb:x}",
                "success": True,
                "error": None,
            }
        except Exception as e:
            return {
                "pid": pid,
                "virtual": f"0x{virt_int:x}",
                "physical": None,
                "success": False,
                "error": str(e),
            }

    # ==================== Module Enumeration ====================

    def list_modules(self, pid: int | None = None, process_name: str | None = None) -> list[dict]:
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        modules = []
        try:
            for mod in proc.module_list():
                modules.append(
                    {
                        "name": mod.name,
                        "base": f"0x{mod.base:x}",
                        "size": f"0x{mod.image_size:x}",
                        "image_size": mod.image_size,
                        "fullname": mod.fullname,
                        "is_wow64": mod.is_wow64,
                    }
                )
        except Exception as e:
            raise PCILeechError(f"Module list failed: {e}")

        return modules

    def pe_sections(
        self, pid: int | None = None, process_name: str | None = None, module_name: str = ""
    ) -> list[dict]:
        """Enumerate PE sections (.text, .rdata, .data, etc.) with addresses and flags."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")
        if not module_name:
            raise PCILeechError("module_name is required")

        try:
            mod = proc.module(module_name)
        except Exception as e:
            raise PCILeechError(f"Module '{module_name}' not found: {e}")

        import memprocfs

        base = mod.base

        dos_header = proc.memory.read(base, 64, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        if dos_header[:2] != b"MZ":
            raise PCILeechError(f"Invalid PE: no MZ signature at 0x{base:x}")

        e_lfanew = struct.unpack_from("<I", dos_header, 0x3C)[0]
        pe_header = proc.memory.read(base + e_lfanew, 264, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        if pe_header[:4] != b"PE\x00\x00":
            raise PCILeechError("Invalid PE: no PE signature")

        num_sections = struct.unpack_from("<H", pe_header, 6)[0]
        size_of_optional = struct.unpack_from("<H", pe_header, 20)[0]

        section_offset = base + e_lfanew + 4 + 20 + size_of_optional
        section_data = proc.memory.read(
            section_offset, num_sections * 40, memprocfs.FLAG_ZEROPAD_ON_FAIL
        )

        _SCN_FLAGS = [
            (0x00000020, "CODE"),
            (0x00000040, "INITIALIZED_DATA"),
            (0x00000080, "UNINITIALIZED_DATA"),
            (0x20000000, "EXECUTE"),
            (0x40000000, "READ"),
            (0x80000000, "WRITE"),
            (0x02000000, "DISCARDABLE"),
        ]

        sections = []
        for i in range(num_sections):
            off = i * 40
            name = section_data[off : off + 8].split(b"\x00")[0].decode("ascii", errors="replace")
            virtual_size = struct.unpack_from("<I", section_data, off + 8)[0]
            rva = struct.unpack_from("<I", section_data, off + 12)[0]
            raw_size = struct.unpack_from("<I", section_data, off + 16)[0]
            characteristics = struct.unpack_from("<I", section_data, off + 36)[0]

            flags = [label for mask, label in _SCN_FLAGS if characteristics & mask]

            sections.append(
                {
                    "name": name,
                    "virtual_address": f"0x{base + rva:x}",
                    "virtual_size": virtual_size,
                    "raw_size": raw_size,
                    "characteristics": f"0x{characteristics:08x}",
                    "flags": flags,
                    "rva": f"0x{rva:x}",
                }
            )

        return sections

    # ==================== Game / RE Tools ====================

    def aob_scan(
        self,
        pattern: str,
        pid: int | None = None,
        process_name: str | None = None,
        module: str | None = None,
        find_all: bool = False,
    ) -> list[dict]:
        """Array-of-bytes scan with ?? wildcard support in process virtual memory."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required for AOB scan")

        # Parse pattern: "4D 5A ?? ?? 50 45" -> (bytes_pattern, mask)
        tokens = pattern.strip().replace(",", " ").split()
        pat_bytes = []
        mask = []
        for token in tokens:
            token = token.strip()
            if token in ("??", "?", "xx", "XX"):
                pat_bytes.append(0)
                mask.append(False)
            else:
                if len(token) != 2 or not _HEX_PATTERN.fullmatch(token):
                    raise PCILeechError(
                        f"Invalid AOB token: '{token}'. Use hex bytes or ?? wildcards."
                    )
                pat_bytes.append(int(token, 16))
                mask.append(True)

        if not pat_bytes:
            raise PCILeechError("Empty AOB pattern")

        pat_len = len(pat_bytes)
        import memprocfs

        # Determine scan ranges
        ranges = []
        if module:
            try:
                mod = proc.module(module)
                ranges.append((mod.base, mod.image_size))
            except Exception as e:
                raise PCILeechError(f"Module '{module}' not found: {e}")
        else:
            try:
                for vad in proc.maps.vad():
                    start = vad.get("start", vad.get("va", 0))
                    size = vad.get("size", vad.get("cb", 0))
                    # Only scan committed, readable regions
                    if size > 0 and size <= 64 * 1024 * 1024:
                        ranges.append((start, size))
            except Exception:
                raise PCILeechError("Failed to enumerate process memory regions")

        matches = []
        for base, size in ranges:
            try:
                data = proc.memory.read(base, size, memprocfs.FLAG_ZEROPAD_ON_FAIL)
            except Exception:
                continue

            offset = 0
            while offset <= len(data) - pat_len:
                found = True
                for i in range(pat_len):
                    if mask[i] and data[offset + i] != pat_bytes[i]:
                        found = False
                        break
                if found:
                    match_addr = base + offset
                    context = data[offset : offset + min(32, len(data) - offset)]
                    matches.append(
                        {
                            "address": f"0x{match_addr:x}",
                            "context": context.hex(),
                        }
                    )
                    if not find_all:
                        return matches
                    offset += pat_len  # skip past match
                else:
                    offset += 1

        return matches

    def module_dump(
        self,
        pid: int | None = None,
        process_name: str | None = None,
        module_name: str = "",
        output_file: str | None = None,
    ) -> dict:
        """Dump a full PE module from process memory to disk."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")
        if not module_name:
            raise PCILeechError("module_name is required")

        try:
            mod = proc.module(module_name)
        except Exception as e:
            raise PCILeechError(f"Module '{module_name}' not found: {e}")

        import memprocfs

        try:
            data = proc.memory.read(mod.base, mod.image_size, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        except Exception as e:
            raise MemoryAccessError(f"Failed to read module memory: {e}")

        if output_file is None:
            output_file = f"{module_name}_0x{mod.base:x}.bin"

        with open(output_file, "wb") as f:
            f.write(data)

        return {
            "module": module_name,
            "base": f"0x{mod.base:x}",
            "size": mod.image_size,
            "file": os.path.abspath(output_file),
            "success": True,
        }

    def module_exports(
        self, pid: int | None = None, process_name: str | None = None, module_name: str = ""
    ) -> list[dict]:
        """List exported functions from a module's Export Address Table."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")
        if not module_name:
            raise PCILeechError("module_name is required")

        try:
            mod = proc.module(module_name)
        except Exception as e:
            raise PCILeechError(f"Module '{module_name}' not found: {e}")

        exports = []
        try:
            eat = mod.maps.eat()
            entries = eat if isinstance(eat, list) else eat.get("e", eat.get("entries", []))
            for entry in entries:
                exports.append(
                    {
                        "name": entry.get("name", entry.get("fn", "")),
                        "ordinal": entry.get("ordinal", entry.get("ord", 0)),
                        "address": f'0x{entry.get("va", entry.get("offset", 0)):x}',
                    }
                )
        except Exception as e:
            raise PCILeechError(f"Failed to read exports: {e}")

        return exports

    def module_imports(
        self, pid: int | None = None, process_name: str | None = None, module_name: str = ""
    ) -> list[dict]:
        """List imported functions from a module's Import Address Table."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")
        if not module_name:
            raise PCILeechError("module_name is required")

        try:
            mod = proc.module(module_name)
        except Exception as e:
            raise PCILeechError(f"Module '{module_name}' not found: {e}")

        imports = []
        try:
            iat = mod.maps.iat()
            entries = iat if isinstance(iat, list) else iat.get("e", iat.get("entries", []))
            for entry in entries:
                imports.append(
                    {
                        "module": entry.get("module", entry.get("dll", "")),
                        "name": entry.get("name", entry.get("fn", "")),
                        "address": f'0x{entry.get("va", entry.get("offset", 0)):x}',
                    }
                )
        except Exception as e:
            raise PCILeechError(f"Failed to read imports: {e}")

        return imports

    def pointer_read(
        self,
        base_address: str,
        offsets: list[int],
        read_size: int = 8,
        pid: int | None = None,
        process_name: str | None = None,
    ) -> dict:
        """Follow a multi-level pointer chain and read the final value."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        import memprocfs

        addr = parse_hex_address(base_address, "base_address")
        chain = [f"0x{addr:x}"]

        try:
            for i, offset in enumerate(offsets):
                # Read pointer at current address
                ptr_data = proc.memory.read(addr, 8, memprocfs.FLAG_ZEROPAD_ON_FAIL)
                addr = struct.unpack_from("<Q", ptr_data, 0)[0]
                if addr == 0:
                    return {
                        "success": False,
                        "error": f'Null pointer at level {i} (after reading 0x{int.from_bytes(ptr_data, "little"):x})',
                        "chain": chain,
                        "final_address": None,
                        "value": None,
                    }
                addr += offset
                chain.append(f"0x{addr:x}")
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed at pointer level {i}: {e}",
                "chain": chain,
                "final_address": None,
                "value": None,
            }

        # Read the final value
        try:
            final_data = proc.memory.read(addr, read_size, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to read final value at 0x{addr:x}: {e}",
                "chain": chain,
                "final_address": f"0x{addr:x}",
                "value": None,
            }

        # Format value based on size
        if read_size <= 8:
            int_val = int.from_bytes(final_data[:read_size], "little")
            value_str = f"0x{int_val:x} ({int_val})"
        else:
            value_str = final_data.hex()

        return {
            "success": True,
            "error": None,
            "chain": chain,
            "final_address": f"0x{addr:x}",
            "value": value_str,
            "raw_hex": final_data.hex(),
        }

    def process_regions(
        self, pid: int | None = None, process_name: str | None = None
    ) -> list[dict]:
        """List virtual memory regions (VADs) for a process with protection flags."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        regions = []
        try:
            for vad in proc.maps.vad():
                regions.append(
                    {
                        "start": f'0x{vad.get("start", vad.get("va", 0)):x}',
                        "size": vad.get("size", vad.get("cb", 0)),
                        "size_str": _format_size(vad.get("size", vad.get("cb", 0))),
                        "protection": vad.get("protection", vad.get("flags", "")),
                        "type": vad.get("type", vad.get("tag", "")),
                        "info": vad.get("info", vad.get("text", "")),
                    }
                )
        except Exception as e:
            raise PCILeechError(f"Failed to enumerate regions: {e}")

        return regions

    # ==================== Advanced RE Tools ====================

    @staticmethod
    def _demangle_msvc(mangled: str) -> str:
        """Demangle MSVC RTTI name: '.?AVFoo@Bar@@' -> 'Bar::Foo'."""
        clean = mangled
        if clean.startswith(".?AV") or clean.startswith(".?AU"):
            clean = clean[4:]
        if clean.endswith("@@"):
            clean = clean[:-2]
        parts = [p for p in clean.split("@") if p]
        return "::".join(reversed(parts)) if len(parts) > 1 else (parts[0] if parts else mangled)

    def signature_resolve(
        self,
        pattern: str,
        pid: int | None = None,
        process_name: str | None = None,
        module: str | None = None,
        op_offset: int = 3,
        op_length: int = 4,
        rip_relative: bool = True,
        instruction_length: int | None = None,
    ) -> dict:
        """
        AOB scan + operand extraction + address resolution in one step.

        Finds pattern, extracts the operand at op_offset, and resolves:
        - RIP-relative: match_addr + instruction_length + signed_operand
        - Absolute: raw operand value

        Example: '48 8B 05 ?? ?? ?? ??' with op_offset=3, op_length=4,
        instruction_length=7 resolves a mov rax,[rip+disp32] target.
        """
        matches = self.aob_scan(
            pattern, pid=pid, process_name=process_name, module=module, find_all=False
        )
        if not matches:
            return {
                "success": False,
                "error": "Pattern not found",
                "pattern": pattern,
                "resolved_address": None,
            }

        match = matches[0]
        match_addr = parse_hex_address(match["address"])
        context = bytes.fromhex(match["context"])

        # Read more data if context is too short
        if op_offset + op_length > len(context):
            proc = self._resolve_process(pid, process_name)
            import memprocfs

            context = proc.memory.read(
                match_addr, op_offset + op_length, memprocfs.FLAG_ZEROPAD_ON_FAIL
            )

        fmt = {1: "<b", 2: "<h", 4: "<i", 8: "<q"}.get(op_length)
        if fmt is None:
            raise PCILeechError(f"Unsupported op_length: {op_length}. Use 1, 2, 4, or 8.")
        operand = struct.unpack_from(fmt, context, op_offset)[0]

        if rip_relative:
            inst_len = (
                instruction_length if instruction_length is not None else (op_offset + op_length)
            )
            resolved = (match_addr + inst_len + operand) & _U64_MAX
        else:
            resolved = operand & _U64_MAX

        return {
            "success": True,
            "error": None,
            "pattern": pattern,
            "match_address": f"0x{match_addr:x}",
            "operand": operand,
            "resolved_address": f"0x{resolved:x}",
            "instruction_length": inst_len if rip_relative else None,
        }

    def rtti_scan(
        self,
        pid: int | None = None,
        process_name: str | None = None,
        module: str | None = None,
        max_classes: int = 500,
    ) -> list[dict]:
        """
        Scan for MSVC x64 RTTI structures in a module.

        Finds TypeDescriptors (.?AV/.?AU markers), resolves CompleteObjectLocators,
        ClassHierarchyDescriptors, and vtable addresses. Returns class names,
        inheritance hierarchies, and vtable locations.
        """
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")
        if not module:
            raise PCILeechError("module name is required for RTTI scan")

        try:
            mod = proc.module(module)
        except Exception as e:
            raise PCILeechError(f"Module '{module}' not found: {e}")

        import memprocfs

        base = mod.base

        # Read entire module image
        module_data = proc.memory.read(base, mod.image_size, memprocfs.FLAG_ZEROPAD_ON_FAIL)

        # Get code ranges for vtable validation
        sections = self.pe_sections(pid=pid, process_name=process_name, module_name=module)
        code_ranges = []
        for sec in sections:
            if "EXECUTE" in sec["flags"]:
                rva = int(sec["rva"], 16)
                code_ranges.append((base + rva, base + rva + sec["virtual_size"]))

        def is_code_addr(addr):
            return any(s <= addr < e for s, e in code_ranges)

        def read_at_rva(rva, size):
            if 0 <= rva < len(module_data) - size:
                return module_data[rva : rva + size]
            return None

        classes = []
        for marker in (b".?AV", b".?AU"):
            offset = 0
            while offset < len(module_data) and len(classes) < max_classes:
                idx = module_data.find(marker, offset)
                if idx == -1:
                    break

                name_end = module_data.find(b"\x00", idx)
                if name_end == -1 or name_end - idx > 512:
                    offset = idx + 1
                    continue

                mangled = module_data[idx:name_end].decode("ascii", errors="replace")

                # TypeDescriptor (x64): [pVFTable:8][spare:8][name:var]
                # name starts at offset 16
                td_rva = idx - 16
                if td_rva < 0:
                    offset = idx + 1
                    continue

                # Validate pVFTable is non-zero
                pvft = struct.unpack_from("<Q", module_data, td_rva)[0]
                if pvft == 0:
                    offset = idx + 1
                    continue

                clean_name = self._demangle_msvc(mangled)
                entry = {
                    "class_name": clean_name,
                    "mangled_name": mangled,
                    "type_descriptor": f"0x{base + td_rva:x}",
                }

                # Find COL referencing this TypeDescriptor
                # COL+12 = pTypeDescriptor (4-byte RVA from module base)
                td_rva_bytes = struct.pack("<I", td_rva & 0xFFFFFFFF)

                col_search = 0
                while col_search < len(module_data):
                    col_ref = module_data.find(td_rva_bytes, col_search)
                    if col_ref == -1:
                        break

                    col_start = col_ref - 12
                    if col_start < 0 or col_start + 24 > len(module_data):
                        col_search = col_ref + 1
                        continue

                    # COL signature must be 1 (x64)
                    sig = struct.unpack_from("<I", module_data, col_start)[0]
                    if sig != 1:
                        col_search = col_ref + 1
                        continue

                    # Validate pSelf (COL+20) matches this COL's RVA
                    p_self = struct.unpack_from("<I", module_data, col_start + 20)[0]
                    if p_self != col_start & 0xFFFFFFFF:
                        col_search = col_ref + 1
                        continue

                    entry["col"] = f"0x{base + col_start:x}"

                    # Read ClassHierarchyDescriptor for inheritance
                    chd_rva = struct.unpack_from("<I", module_data, col_start + 16)[0]
                    chd_data = read_at_rva(chd_rva, 16)
                    if chd_data:
                        num_bases = struct.unpack_from("<I", chd_data, 8)[0]
                        bca_rva = struct.unpack_from("<I", chd_data, 12)[0]

                        base_classes = []
                        if num_bases <= 64:
                            for bi in range(min(num_bases, 32)):
                                bcd_rva_data = read_at_rva(bca_rva + bi * 4, 4)
                                if not bcd_rva_data:
                                    break
                                bcd_rva = struct.unpack_from("<I", bcd_rva_data, 0)[0]
                                bcd = read_at_rva(bcd_rva, 28)
                                if not bcd:
                                    continue
                                bc_td_rva = struct.unpack_from("<I", bcd, 0)[0]
                                bc_name_data = read_at_rva(bc_td_rva + 16, 256)
                                if not bc_name_data:
                                    continue
                                bc_end = bc_name_data.find(b"\x00")
                                if bc_end == -1:
                                    continue
                                bc_mangled = bc_name_data[:bc_end].decode("ascii", errors="replace")
                                bc_clean = self._demangle_msvc(bc_mangled)
                                if bc_clean != clean_name:
                                    base_classes.append(bc_clean)

                        if base_classes:
                            entry["base_classes"] = base_classes

                    # Find vtable: scan for pointer to COL (vtable[-1])
                    col_va = base + col_start
                    col_va_bytes = struct.pack("<Q", col_va)
                    vt_search = 0
                    while vt_search < len(module_data) - 8:
                        vt_ref = module_data.find(col_va_bytes, vt_search)
                        if vt_ref == -1:
                            break
                        # vtable starts at vt_ref + 8
                        if vt_ref + 16 <= len(module_data):
                            first_func = struct.unpack_from("<Q", module_data, vt_ref + 8)[0]
                            if is_code_addr(first_func):
                                entry["vtable"] = f"0x{base + vt_ref + 8:x}"
                                break
                        vt_search = vt_ref + 1

                    break
                    col_search = col_ref + 1

                classes.append(entry)
                offset = idx + 1

        return classes

    def struct_analyze(
        self, address: str, size: int = 256, pid: int | None = None, process_name: str | None = None
    ) -> dict:
        """
        Heuristic analysis of a memory region to identify likely data types.

        Identifies pointers, vtable pointers, floats, vectors, integers,
        strings, and null/padding at each offset. Follows pointers to
        detect string targets and vtables.
        """
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        addr = parse_hex_address(address)
        if size < 8 or size > 4096:
            raise PCILeechError("size must be 8-4096 bytes")

        import memprocfs

        data = proc.memory.read(addr, size, memprocfs.FLAG_ZEROPAD_ON_FAIL)

        # Build valid address ranges for pointer detection
        try:
            valid_ranges = []
            for vad in proc.maps.vad():
                start = vad.get("start", vad.get("va", 0))
                end = start + vad.get("size", vad.get("cb", 0))
                valid_ranges.append((start, end))
        except Exception:
            valid_ranges = []

        def is_valid_ptr(val):
            if val == 0 or val > 0x7FFFFFFFFFFF:
                return False
            if valid_ranges:
                return any(s <= val < e for s, e in valid_ranges)
            return 0x10000 <= val <= 0x7FFFFFFFFFFF

        def is_reasonable_float(val):
            if val == 0.0 or math.isnan(val) or math.isinf(val):
                return False
            return -1e6 <= val <= 1e6 and abs(val) > 1e-10

        fields = []
        pointer_targets = {}
        offset = 0

        while offset < len(data):
            remaining = len(data) - offset

            if remaining < 4:
                fields.append(
                    {
                        "offset": f"0x{offset:x}",
                        "size": remaining,
                        "type": "bytes",
                        "value": data[offset:].hex(),
                    }
                )
                break

            if remaining >= 8:
                val_u64 = struct.unpack_from("<Q", data, offset)[0]

                # NULL / padding
                if val_u64 == 0:
                    fields.append(
                        {
                            "offset": f"0x{offset:x}",
                            "size": 8,
                            "type": "null",
                            "value": "0x0",
                        }
                    )
                    offset += 8
                    continue

                # Pointer detection
                if is_valid_ptr(val_u64):
                    field = {
                        "offset": f"0x{offset:x}",
                        "size": 8,
                        "type": "pointer",
                        "value": f"0x{val_u64:x}",
                    }
                    try:
                        target = proc.memory.read(val_u64, 32, memprocfs.FLAG_ZEROPAD_ON_FAIL)
                        # Vtable check (first field, pointer to code pointers)
                        first_ptr = struct.unpack_from("<Q", target, 0)[0]
                        if offset == 0 and is_valid_ptr(first_ptr):
                            field["type"] = "vtable_ptr"
                        # String check
                        try:
                            s = target.split(b"\x00")[0].decode("ascii")
                            if len(s) >= 4 and all(32 <= ord(c) < 127 for c in s):
                                field["target_string"] = s
                        except (UnicodeDecodeError, ValueError):
                            pass
                        pointer_targets[f"0x{val_u64:x}"] = target.hex()[:64]
                    except Exception:
                        pass
                    fields.append(field)
                    offset += 8
                    continue

            # Float / vector detection (4-byte aligned)
            val_f32 = struct.unpack_from("<f", data, offset)[0]
            if is_reasonable_float(val_f32):
                # Check for vec3
                if remaining >= 12:
                    f2 = struct.unpack_from("<f", data, offset + 4)[0]
                    f3 = struct.unpack_from("<f", data, offset + 8)[0]
                    if is_reasonable_float(f2) and is_reasonable_float(f3):
                        fields.append(
                            {
                                "offset": f"0x{offset:x}",
                                "size": 12,
                                "type": "vec3",
                                "value": f"({val_f32:.4f}, {f2:.4f}, {f3:.4f})",
                            }
                        )
                        offset += 12
                        continue
                # Check for vec2
                if remaining >= 8:
                    f2 = struct.unpack_from("<f", data, offset + 4)[0]
                    if is_reasonable_float(f2):
                        fields.append(
                            {
                                "offset": f"0x{offset:x}",
                                "size": 8,
                                "type": "vec2",
                                "value": f"({val_f32:.4f}, {f2:.4f})",
                            }
                        )
                        offset += 8
                        continue
                fields.append(
                    {
                        "offset": f"0x{offset:x}",
                        "size": 4,
                        "type": "float",
                        "value": f"{val_f32:.6f}",
                    }
                )
                offset += 4
                continue

            # Small integer detection
            val_u32 = struct.unpack_from("<I", data, offset)[0]
            if remaining >= 8:
                high = struct.unpack_from("<I", data, offset + 4)[0]
            else:
                high = 1  # force 4-byte path
            if 0 < val_u32 <= 10000 and high == 0 and remaining >= 8:
                fields.append(
                    {
                        "offset": f"0x{offset:x}",
                        "size": 4,
                        "type": "int32",
                        "value": str(val_u32),
                    }
                )
                offset += 4
                continue

            # Unknown
            step = 8 if remaining >= 8 else 4
            raw = struct.unpack_from("<Q" if step == 8 else "<I", data, offset)[0]
            fields.append(
                {
                    "offset": f"0x{offset:x}",
                    "size": step,
                    "type": "unknown",
                    "value": f"0x{raw:0{step * 2}x}",
                }
            )
            offset += step

        return {
            "base_address": f"0x{addr:x}",
            "size": size,
            "fields": fields,
            "pointer_targets": pointer_targets,
        }

    def string_scan(
        self,
        pid: int | None = None,
        process_name: str | None = None,
        module: str | None = None,
        min_length: int = 4,
        encoding: str = "both",
        pattern: str | None = None,
        max_results: int = 500,
    ) -> list[dict]:
        """Scan process memory for ASCII and/or UTF-16LE strings."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")
        if min_length < 3:
            raise PCILeechError("min_length must be >= 3")
        if encoding not in ("ascii", "unicode", "both"):
            raise PCILeechError("encoding must be 'ascii', 'unicode', or 'both'")

        import memprocfs

        ranges = []
        if module:
            try:
                mod = proc.module(module)
                ranges.append((mod.base, mod.image_size))
            except Exception as e:
                raise PCILeechError(f"Module '{module}' not found: {e}")
        else:
            try:
                for vad in proc.maps.vad():
                    start = vad.get("start", vad.get("va", 0))
                    size = vad.get("size", vad.get("cb", 0))
                    if 0 < size <= 64 * 1024 * 1024:
                        ranges.append((start, size))
            except Exception:
                raise PCILeechError("Failed to enumerate process memory regions")

        compiled = re.compile(pattern, re.IGNORECASE) if pattern else None
        results = []

        for base_addr, region_size in ranges:
            if len(results) >= max_results:
                break
            try:
                data = proc.memory.read(base_addr, region_size, memprocfs.FLAG_ZEROPAD_ON_FAIL)
            except Exception:
                continue

            if encoding in ("ascii", "both"):
                i = 0
                while i < len(data) and len(results) < max_results:
                    if 32 <= data[i] < 127:
                        start = i
                        while i < len(data) and 32 <= data[i] < 127:
                            i += 1
                        if i - start >= min_length:
                            s = data[start:i].decode("ascii")
                            if compiled is None or compiled.search(s):
                                results.append(
                                    {
                                        "address": f"0x{base_addr + start:x}",
                                        "encoding": "ascii",
                                        "length": i - start,
                                        "string": s[:256],
                                    }
                                )
                    else:
                        i += 1

            if encoding in ("unicode", "both"):
                i = 0
                while i < len(data) - 1 and len(results) < max_results:
                    char = struct.unpack_from("<H", data, i)[0]
                    if 32 <= char < 127:
                        start = i
                        chars = []
                        while i < len(data) - 1:
                            char = struct.unpack_from("<H", data, i)[0]
                            if 32 <= char < 127:
                                chars.append(chr(char))
                                i += 2
                            else:
                                break
                        if len(chars) >= min_length:
                            s = "".join(chars)
                            if compiled is None or compiled.search(s):
                                results.append(
                                    {
                                        "address": f"0x{base_addr + start:x}",
                                        "encoding": "utf-16le",
                                        "length": len(chars),
                                        "string": s[:256],
                                    }
                                )
                    else:
                        i += 2

        return results

    def memory_snapshot(
        self,
        label: str,
        address: str,
        size: int,
        pid: int | None = None,
        process_name: str | None = None,
    ) -> dict:
        """Take a named snapshot of a memory region for later diffing."""
        data = self.read_memory(address, size, pid=pid, process_name=process_name)
        addr_int = parse_hex_address(address)

        self._snapshots[label] = {
            "address": addr_int,
            "size": size,
            "data": data,
            "pid": pid,
            "process_name": process_name,
            "timestamp": time.time(),
        }
        return {
            "label": label,
            "address": f"0x{addr_int:x}",
            "size": size,
            "timestamp": self._snapshots[label]["timestamp"],
        }

    def memory_diff(
        self,
        address: str,
        size: int,
        label: str = "default",
        pid: int | None = None,
        process_name: str | None = None,
    ) -> dict:
        """
        Compare current memory against a stored snapshot.

        First call takes a snapshot; subsequent calls diff against it and
        report changed bytes with type interpretations (int, float, etc.).
        """
        addr_int = parse_hex_address(address)

        if label not in self._snapshots:
            self.memory_snapshot(label, address, size, pid=pid, process_name=process_name)
            return {
                "action": "snapshot_taken",
                "label": label,
                "address": f"0x{addr_int:x}",
                "size": size,
                "message": f'Initial snapshot "{label}" taken. Call again after a game action to see changes.',
            }

        old_data = self._snapshots[label]["data"]
        current_data = self.read_memory(address, size, pid=pid, process_name=process_name)

        changes = []
        i = 0
        limit = min(len(old_data), len(current_data))
        while i < limit:
            if old_data[i] != current_data[i]:
                start = i
                while i < limit and old_data[i] != current_data[i]:
                    i += 1
                old_bytes = old_data[start:i]
                new_bytes = current_data[start:i]
                change = {
                    "offset": f"0x{start:x}",
                    "address": f"0x{addr_int + start:x}",
                    "size": i - start,
                    "old": old_bytes.hex(),
                    "new": new_bytes.hex(),
                }
                n = i - start
                if n == 4:
                    oi = struct.unpack_from("<i", old_bytes, 0)[0]
                    ni = struct.unpack_from("<i", new_bytes, 0)[0]
                    change["as_int32"] = f"{oi} -> {ni} (delta: {ni - oi})"
                    of = struct.unpack_from("<f", old_bytes, 0)[0]
                    nf = struct.unpack_from("<f", new_bytes, 0)[0]
                    if not (math.isnan(of) or math.isinf(of) or math.isnan(nf) or math.isinf(nf)):
                        change["as_float"] = f"{of:.4f} -> {nf:.4f}"
                elif n == 8:
                    oi = struct.unpack_from("<q", old_bytes, 0)[0]
                    ni = struct.unpack_from("<q", new_bytes, 0)[0]
                    change["as_int64"] = f"{oi} -> {ni}"
                elif n == 1:
                    change["as_byte"] = f"{old_bytes[0]} -> {new_bytes[0]}"
                changes.append(change)
            else:
                i += 1

        # Update snapshot for next diff
        self._snapshots[label] = {
            "address": addr_int,
            "size": size,
            "data": current_data,
            "pid": pid,
            "process_name": process_name,
            "timestamp": time.time(),
        }

        return {
            "action": "diff",
            "label": label,
            "address": f"0x{addr_int:x}",
            "size": size,
            "total_changes": len(changes),
            "bytes_changed": sum(c["size"] for c in changes),
            "changes": changes,
        }

    # ==================== Pointer / XRef Scanning ====================

    def pointer_scan(
        self,
        target_address: str,
        pid: int | None = None,
        process_name: str | None = None,
        max_depth: int = 5,
        max_offset: int = 4096,
        max_results: int = 100,
        module_filter: str | None = None,
    ) -> dict:
        """Discover pointer chains from static module bases to a target address."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")
        target = parse_hex_address(target_address)

        from pointer_scanner import PointerScanner

        scanner = PointerScanner(proc)
        return scanner.scan(
            target,
            max_depth=max_depth,
            max_offset=max_offset,
            max_results=max_results,
            module_filter=module_filter,
        )

    def xref_scan(
        self,
        target_address: str,
        pid: int | None = None,
        process_name: str | None = None,
        module: str | None = None,
        scan_code: bool = True,
        scan_data: bool = True,
        max_results: int = 200,
    ) -> dict:
        """Find all code/data references to a target address within a module."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")
        if not module:
            raise PCILeechError("module name is required for xref scan")
        target = parse_hex_address(target_address)

        from pointer_scanner import XRefScanner

        scanner = XRefScanner(proc)
        return scanner.scan(
            target,
            module_name=module,
            scan_code=scan_code,
            scan_data=scan_data,
            max_results=max_results,
        )

    # ==================== Engine Tools ====================

    def ue_dump_names(
        self,
        gnames_address: str,
        pid: int | None = None,
        process_name: str | None = None,
        max_names: int = 200000,
        ue_version: str = "ue5",
    ) -> dict:
        """Read UE FNamePool and dump all name entries."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        from engine_tools import UnrealEngine

        ue = UnrealEngine(proc, ue_version=ue_version)
        gnames = parse_hex_address(gnames_address)
        return ue.dump_names(gnames, max_names=max_names)

    def ue_dump_objects(
        self,
        gobjects_address: str,
        pid: int | None = None,
        process_name: str | None = None,
        gnames_address: str | None = None,
        max_objects: int = 200000,
        ue_version: str = "ue5",
    ) -> dict:
        """Read FUObjectArray and dump all UObject entries."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        from engine_tools import UnrealEngine

        ue = UnrealEngine(proc, ue_version=ue_version)
        gobjects = parse_hex_address(gobjects_address)
        gnames = parse_hex_address(gnames_address) if gnames_address else None
        if gnames is not None:
            ue.dump_names(gnames)
        return ue.dump_objects(gobjects, max_objects=max_objects)

    def ue_dump_sdk(
        self,
        gobjects_address: str,
        gnames_address: str,
        pid: int | None = None,
        process_name: str | None = None,
        output_file: str | None = None,
        max_classes: int = 5000,
        ue_version: str = "ue5",
    ) -> dict:
        """Generate C++ SDK headers from UE reflection system."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        from engine_tools import UnrealEngine

        ue = UnrealEngine(proc, ue_version=ue_version)
        gnames = parse_hex_address(gnames_address)
        gobjects = parse_hex_address(gobjects_address)
        ue.dump_names(gnames)
        ue.dump_objects(gobjects)
        return ue.dump_sdk(gobjects, gnames, output_file=output_file, max_classes=max_classes)

    def unity_il2cpp_dump(
        self,
        pid: int | None = None,
        process_name: str | None = None,
        output_file: str | None = None,
        max_classes: int = 5000,
    ) -> dict:
        """Find and parse IL2CPP metadata from a running Unity process."""
        proc = self._resolve_process(pid, process_name)
        if proc is None:
            raise PCILeechError("pid or process_name is required")

        from engine_tools import IL2CPP

        il2cpp = IL2CPP(proc)
        return il2cpp.dump(output_file=output_file, max_classes=max_classes)

    # ==================== FPGA / Advanced ====================

    def benchmark(self, test_type: str = "read", address: str = "0x1000") -> dict:
        addr_int = parse_hex_address(address)
        lc = self._get_lc()

        iterations = 1000
        chunk_size = 4096

        # Read benchmark
        start = time.perf_counter()
        for _ in range(iterations):
            try:
                lc.read(addr_int, chunk_size)
            except Exception:
                pass
        read_elapsed = time.perf_counter() - start
        read_mbps = (iterations * chunk_size / (1024 * 1024)) / read_elapsed

        result = {
            "test_type": test_type,
            "address": f"0x{addr_int:x}",
            "read_iterations": iterations,
            "read_chunk_size": chunk_size,
            "read_elapsed_s": round(read_elapsed, 3),
            "read_mbps": round(read_mbps, 2),
        }

        if test_type in ("readwrite", "full"):
            test_data = b"\x00" * chunk_size
            start = time.perf_counter()
            for _ in range(iterations):
                try:
                    lc.write(addr_int, test_data)
                except Exception:
                    pass
            write_elapsed = time.perf_counter() - start
            write_mbps = (iterations * chunk_size / (1024 * 1024)) / write_elapsed
            result["write_iterations"] = iterations
            result["write_elapsed_s"] = round(write_elapsed, 3)
            result["write_mbps"] = round(write_mbps, 2)

        return result

    def tlp_send(
        self, tlp_data: str | None = None, wait_seconds: float = 0.5, verbose: bool = True
    ) -> dict:
        lc = self._get_lc()
        import leechcorepyc

        result = {
            "sent": False,
            "received_tlps": [],
        }

        # Send TLP if data provided
        if tlp_data:
            clean = tlp_data.replace(" ", "")
            if not _HEX_PATTERN.fullmatch(clean) or len(clean) % 2 != 0:
                raise PCILeechError(f"Invalid TLP hex data: {tlp_data}")
            raw_tlp = bytes.fromhex(clean)
            try:
                lc.tlp_write([raw_tlp])
                result["sent"] = True
                result["sent_bytes"] = len(raw_tlp)
                if verbose:
                    try:
                        result["sent_info"] = lc.tlp_tostring(raw_tlp)
                    except Exception:
                        pass
            except Exception as e:
                raise PCILeechError(f"TLP send failed: {e}")

        # Listen for TLP responses
        received = []

        def tlp_callback(tlp_bytes, tlp_str_info):
            entry = {"data": tlp_bytes.hex()}
            if verbose:
                entry["info"] = tlp_str_info
            received.append(entry)

        try:
            lc.tlp_read(tlp_callback, False, True)
            time.sleep(wait_seconds)
        except Exception as e:
            raise PCILeechError(f"TLP receive failed: {e}")

        result["received_tlps"] = received
        return result

    def fpga_config(
        self,
        action: str = "read",
        address: str | None = None,
        data: str | None = None,
        output_file: str | None = None,
    ) -> dict:
        lc = self._get_lc()
        import leechcorepyc

        if action == "read":
            try:
                cfg = lc.command_data(leechcorepyc.LC_CMD_FPGA_PCIECFGSPACE)
            except Exception as e:
                raise PCILeechError(f"FPGA config read failed: {e}")

            result = {
                "action": "read",
                "size": len(cfg),
                "data_hex": cfg.hex(),
                "success": True,
            }

            if output_file:
                with open(output_file, "wb") as f:
                    f.write(cfg)
                result["file"] = os.path.abspath(output_file)

            return result

        elif action == "write":
            if not data:
                raise PCILeechError("data is required for write action")
            if address is None:
                raise PCILeechError("address is required for write action")

            addr_int = parse_hex_address(address, "address")
            clean = data.replace(" ", "")
            if not _HEX_PATTERN.fullmatch(clean) or len(clean) % 2 != 0:
                raise PCILeechError(f"Invalid hex data: {data}")
            write_bytes = bytes.fromhex(clean)

            try:
                lc.command_data(leechcorepyc.LC_CMD_FPGA_CFGREGPCIE | addr_int, write_bytes)
            except Exception as e:
                raise PCILeechError(f"FPGA config write failed: {e}")

            return {
                "action": "write",
                "address": f"0x{addr_int:x}",
                "bytes_written": len(write_bytes),
                "success": True,
            }

        else:
            raise PCILeechError(f"Unknown action: {action}. Use 'read' or 'write'.")

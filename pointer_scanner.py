"""
Pointer chain scanner and cross-reference scanner for DMA memory analysis.

Provides two classes:
- PointerScanner: Discovers pointer chains from static module bases to a target address.
- XRefScanner: Finds all code/data references to a target address within a module.
"""

import struct


class PointerScanner:
    """Discovers pointer chains from static module bases to a target address.

    Performs a breadth-first reverse pointer scan: starting from the target address,
    it searches process memory for pointers that reference the target (within a
    configurable offset range), then recurses upward until a pointer is found
    within a known module's static address range, forming a complete chain.

    Args:
        proc: memprocfs process object (has .memory.read(), .module_list(), .maps.vad())
        modules: Optional pre-fetched module list. If None, will be fetched via proc.module_list().
    """

    def __init__(self, proc, modules=None):
        self._proc = proc
        self._modules = modules

    def _get_modules(self, module_filter=None):
        """Build module base map. Returns list of (name, base, size) tuples."""
        modules = self._modules if self._modules is not None else self._proc.module_list()
        result = []
        for mod in modules:
            name = mod.name
            if module_filter and module_filter.lower() not in name.lower():
                continue
            result.append((name, mod.base, mod.image_size))
        return result

    def _find_module_for_address(self, addr, module_map):
        """Check if an address falls within any module range.

        Returns (module_name, offset_from_base) or None.
        """
        for name, base, size in module_map:
            if base <= addr < base + size:
                return (name, addr - base)
        return None

    def scan(
        self, target_address, max_depth=5, max_offset=4096, max_results=100, module_filter=None
    ):
        """Scan for pointer chains from static module bases to a target address.

        Algorithm:
            1. Build static base map from proc.module_list() -- these are chain roots.
            2. Level 0: Scan all VADs for 8-byte aligned pointers within
               [target - max_offset, target + max_offset]. If a hit falls in a
               module range, it is a complete chain. Otherwise, add to pending for
               the next level.
            3. Levels 1..N: Repeat for each pending address, up to max_depth.

        Args:
            target_address: The address to find pointer chains to.
            max_depth: Maximum pointer chain depth (default 5).
            max_offset: Maximum offset from target to consider a hit (default 4096).
            max_results: Maximum number of chains to return (default 100).
            module_filter: If set, only include modules whose name matches
                (case-insensitive substring).

        Returns:
            Dict with 'chains' list and 'stats' dict. Each chain has module name,
            base_offset, offsets list, depth, and a human-readable expression.
        """
        import memprocfs

        module_map = self._get_modules(module_filter)
        if not module_map:
            return {
                "chains": [],
                "stats": {
                    "target": f"0x{target_address:x}",
                    "max_depth": max_depth,
                    "max_offset": max_offset,
                    "levels_searched": 0,
                    "total_chains_found": 0,
                    "addresses_scanned": 0,
                },
            }

        # Collect VAD ranges once
        vad_ranges = []
        try:
            for vad in self._proc.maps.vad():
                start = vad.get("start", vad.get("va", 0))
                size = vad.get("size", vad.get("cb", 0))
                # Only scan regions up to 128 MB
                if size > 0 and size <= 128 * 1024 * 1024:
                    vad_ranges.append((start, size))
        except Exception:
            return {
                "chains": [],
                "stats": {
                    "target": f"0x{target_address:x}",
                    "max_depth": max_depth,
                    "max_offset": max_offset,
                    "levels_searched": 0,
                    "total_chains_found": 0,
                    "addresses_scanned": 0,
                },
            }

        chains = []
        total_scanned = 0
        levels_searched = 0

        # pending_items: list of (address_to_find_pointers_to, offsets_so_far)
        # offsets_so_far is built in reverse order (from target back to root)
        pending = [(target_address, [])]

        for depth in range(max_depth):
            if not pending or len(chains) >= max_results:
                break

            levels_searched = depth + 1
            next_pending = []

            for search_addr, offsets_so_far in pending:
                if len(chains) >= max_results:
                    break

                lo = search_addr - max_offset
                hi = search_addr + max_offset

                for vad_start, vad_size in vad_ranges:
                    if len(chains) >= max_results:
                        break

                    try:
                        data = self._proc.memory.read(
                            vad_start, vad_size, memprocfs.FLAG_ZEROPAD_ON_FAIL
                        )
                    except Exception:
                        continue

                    # Scan for 8-byte aligned pointers in [lo, hi]
                    for pos in range(0, len(data) - 7, 8):
                        ptr_val = struct.unpack_from("<Q", data, pos)[0]
                        if lo <= ptr_val <= hi:
                            total_scanned += 1
                            hit_addr = vad_start + pos
                            offset_from_target = search_addr - ptr_val
                            # Note: offset_from_target can be negative if ptr > search_addr
                            # but the semantics are: [ptr_val] + offset = search_addr
                            # i.e., offset = search_addr - ptr_val
                            current_offset = search_addr - ptr_val
                            new_offsets = [current_offset] + offsets_so_far

                            mod_info = self._find_module_for_address(hit_addr, module_map)
                            if mod_info is not None:
                                mod_name, base_offset = mod_info
                                # Build expression
                                expr = f"[{mod_name}+0x{base_offset:x}]"
                                for off in new_offsets[:-1]:
                                    if off >= 0:
                                        expr = f"[{expr}+0x{off:x}]"
                                    else:
                                        expr = f"[{expr}-0x{-off:x}]"
                                # Last offset (closest to target)
                                if new_offsets:
                                    last_off = new_offsets[-1]
                                    if last_off >= 0:
                                        expr = f"{expr}+0x{last_off:x}"
                                    elif last_off < 0:
                                        expr = f"{expr}-0x{-last_off:x}"

                                chains.append(
                                    {
                                        "module": mod_name,
                                        "base_offset": base_offset,
                                        "offsets": new_offsets,
                                        "depth": len(new_offsets),
                                        "expression": expr,
                                    }
                                )
                                if len(chains) >= max_results:
                                    break
                            else:
                                # Not in a module yet -- add to next level
                                if len(next_pending) < 10000:
                                    next_pending.append((hit_addr, new_offsets))

            pending = next_pending

        return {
            "chains": chains,
            "stats": {
                "target": f"0x{target_address:x}",
                "max_depth": max_depth,
                "max_offset": max_offset,
                "levels_searched": levels_searched,
                "total_chains_found": len(chains),
                "addresses_scanned": total_scanned,
            },
        }


class XRefScanner:
    """Finds all code and data cross-references to a target address within a module.

    Scans PE sections for:
    - Code xrefs: RIP-relative instructions (7-byte and 6-byte forms) and
      relative call/jmp instructions (E8/E9).
    - Data xrefs: 8-byte aligned absolute address references.

    Args:
        proc: memprocfs process object (has .memory.read(), .module()).
    """

    def __init__(self, proc):
        self._proc = proc

    def _parse_pe_sections(self, module_base):
        """Parse PE section headers from memory.

        Returns list of dicts with keys: name, rva, virtual_size, characteristics.
        """
        import memprocfs

        dos_header = self._proc.memory.read(module_base, 64, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        if dos_header[:2] != b"MZ":
            raise RuntimeError(f"Invalid PE: no MZ signature at 0x{module_base:x}")

        e_lfanew = struct.unpack_from("<I", dos_header, 0x3C)[0]
        pe_header = self._proc.memory.read(
            module_base + e_lfanew, 264, memprocfs.FLAG_ZEROPAD_ON_FAIL
        )
        if pe_header[:4] != b"PE\x00\x00":
            raise RuntimeError("Invalid PE: no PE signature")

        num_sections = struct.unpack_from("<H", pe_header, 6)[0]
        size_of_optional = struct.unpack_from("<H", pe_header, 20)[0]

        section_table_offset = module_base + e_lfanew + 4 + 20 + size_of_optional
        section_data = self._proc.memory.read(
            section_table_offset, num_sections * 40, memprocfs.FLAG_ZEROPAD_ON_FAIL
        )

        sections = []
        for i in range(num_sections):
            off = i * 40
            name = section_data[off : off + 8].split(b"\x00")[0].decode("ascii", errors="replace")
            virtual_size = struct.unpack_from("<I", section_data, off + 8)[0]
            rva = struct.unpack_from("<I", section_data, off + 12)[0]
            characteristics = struct.unpack_from("<I", section_data, off + 36)[0]

            sections.append(
                {
                    "name": name,
                    "rva": rva,
                    "virtual_size": virtual_size,
                    "characteristics": characteristics,
                }
            )

        return sections

    def scan(self, target_address, module_name, scan_code=True, scan_data=True, max_results=200):
        """Find all code and data cross-references to target_address within a module.

        Algorithm:
            1. Resolve the module and parse its PE section headers.
            2. For code sections (characteristics & 0x20): scan for RIP-relative
               instructions (7-byte and 6-byte forms) and E8/E9 relative
               call/jmp instructions.
            3. For data sections (characteristics & 0x40): scan for 8-byte
               aligned absolute address matches.

        Args:
            target_address: The address to find references to.
            module_name: Name of the module to scan (e.g. 'game.exe').
            scan_code: Whether to scan code sections (default True).
            scan_data: Whether to scan data sections (default True).
            max_results: Maximum total results to return (default 200).

        Returns:
            Dict with 'target', 'module', 'code_refs', 'data_refs', and 'stats'.
        """
        import memprocfs

        try:
            mod = self._proc.module(module_name)
        except Exception as e:
            raise RuntimeError(f"Module '{module_name}' not found: {e}")

        base = mod.base
        sections = self._parse_pe_sections(base)

        code_refs = []
        data_refs = []
        code_sections_scanned = 0
        data_sections_scanned = 0
        total_bytes_scanned = 0
        total_found = 0

        for section in sections:
            if total_found >= max_results:
                break

            sec_chars = section["characteristics"]
            sec_rva = section["rva"]
            sec_size = section["virtual_size"]
            sec_name = section["name"]
            sec_base = base + sec_rva

            is_code = bool(sec_chars & 0x20)
            is_data = bool(sec_chars & 0x40)

            if scan_code and is_code:
                code_sections_scanned += 1
                try:
                    data = self._proc.memory.read(
                        sec_base, sec_size, memprocfs.FLAG_ZEROPAD_ON_FAIL
                    )
                except Exception:
                    continue
                total_bytes_scanned += len(data)

                refs = self._scan_code_section(
                    data, sec_base, sec_name, target_address, max_results - total_found
                )
                code_refs.extend(refs)
                total_found += len(refs)

            if scan_data and is_data and total_found < max_results:
                data_sections_scanned += 1
                try:
                    data = self._proc.memory.read(
                        sec_base, sec_size, memprocfs.FLAG_ZEROPAD_ON_FAIL
                    )
                except Exception:
                    continue
                total_bytes_scanned += len(data)

                refs = self._scan_data_section(
                    data, sec_base, sec_name, target_address, max_results - total_found
                )
                data_refs.extend(refs)
                total_found += len(refs)

        return {
            "target": f"0x{target_address:x}",
            "module": module_name,
            "code_refs": code_refs,
            "data_refs": data_refs,
            "stats": {
                "code_sections_scanned": code_sections_scanned,
                "data_sections_scanned": data_sections_scanned,
                "total_bytes_scanned": total_bytes_scanned,
            },
        }

    @staticmethod
    def _scan_code_section(data, section_base, section_name, target_address, remaining):
        """Scan a code section for RIP-relative and E8/E9 references.

        Uses a constant-sum technique for a single-pass scan. For all
        instruction forms (7/6/5-byte), the relationship between the
        displacement field offset dp in data and the signed disp32 is:

            dp + disp32 == K,  where K = target - section_base - 4

        This allows checking all three instruction types at each position.

        Patterns detected:
        - 7-byte RIP-relative (mov/lea/cmp with rip+disp32): disp at byte 3
        - 6-byte RIP-relative (jmp/call indirect): disp at byte 2
        - 5-byte relative call (E8) and jmp (E9): disp at byte 1

        Args:
            data: Raw bytes of the section.
            section_base: Virtual address of the section start.
            section_name: Name of the section (e.g. '.text').
            target_address: Address to find references to.
            remaining: Maximum number of results to collect.

        Returns:
            List of code_ref dicts.
        """
        results = []
        data_len = len(data)
        unpack_i32 = struct.unpack_from

        # Constant: dp + disp == K for all instruction types
        # 7-byte at dp-3: target = section_base + (dp-3) + 7 + disp → dp+disp = target-section_base-4
        # 6-byte at dp-2: target = section_base + (dp-2) + 6 + disp → dp+disp = target-section_base-4
        # 5-byte at dp-1: target = section_base + (dp-1) + 5 + disp → dp+disp = target-section_base-4
        k = target_address - section_base - 4

        for dp in range(0, data_len - 3):
            if len(results) >= remaining:
                break
            disp = unpack_i32("<i", data, dp)[0]
            if dp + disp != k:
                continue

            # 7-byte RIP-relative: disp at byte 3, instruction at dp-3
            if dp >= 3:
                instr_pos = dp - 3
                if data[instr_pos] not in (0xE8, 0xE9):
                    instr_addr = section_base + instr_pos
                    ctx_end = min(data_len, instr_pos + 7)
                    results.append(
                        {
                            "address": f"0x{instr_addr:x}",
                            "type": "rip_rel_7",
                            "instruction_bytes": data[instr_pos:ctx_end].hex(),
                            "section": section_name,
                            "displacement": disp,
                        }
                    )

            # 6-byte RIP-relative: disp at byte 2, instruction at dp-2
            if dp >= 2:
                instr_pos = dp - 2
                if data[instr_pos] not in (0xE8, 0xE9):
                    instr_addr = section_base + instr_pos
                    ctx_end = min(data_len, instr_pos + 6)
                    results.append(
                        {
                            "address": f"0x{instr_addr:x}",
                            "type": "rip_rel_6",
                            "instruction_bytes": data[instr_pos:ctx_end].hex(),
                            "section": section_name,
                            "displacement": disp,
                        }
                    )

            # 5-byte E8/E9: disp at byte 1, instruction at dp-1
            if dp >= 1:
                instr_pos = dp - 1
                opcode = data[instr_pos]
                if opcode in (0xE8, 0xE9):
                    instr_addr = section_base + instr_pos
                    ref_type = "call_e8" if opcode == 0xE8 else "jmp_e9"
                    results.append(
                        {
                            "address": f"0x{instr_addr:x}",
                            "type": ref_type,
                            "instruction_bytes": data[instr_pos : instr_pos + 5].hex(),
                            "section": section_name,
                            "displacement": disp,
                        }
                    )

        return results

    @staticmethod
    def _scan_data_section(data, section_base, section_name, target_address, remaining):
        """Scan a data section for absolute 8-byte pointer references.

        Searches for the target address packed as a little-endian 64-bit value
        at 8-byte aligned positions.

        Args:
            data: Raw bytes of the section.
            section_base: Virtual address of the section start.
            section_name: Name of the section (e.g. '.rdata').
            target_address: Address to find references to.
            remaining: Maximum number of results to collect.

        Returns:
            List of data_ref dicts.
        """
        results = []
        target_bytes = struct.pack("<Q", target_address)
        search_start = 0

        while len(results) < remaining:
            idx = data.find(target_bytes, search_start)
            if idx == -1:
                break
            # Only report 8-byte aligned matches
            if idx % 8 == 0:
                ref_addr = section_base + idx
                # Context: 16 bytes surrounding the match (8 before, 8 after if available)
                ctx_start = max(0, idx - 8)
                ctx_end = min(len(data), idx + 16)
                results.append(
                    {
                        "address": f"0x{ref_addr:x}",
                        "section": section_name,
                        "context": data[ctx_start:ctx_end].hex(),
                    }
                )
            search_start = idx + 8  # Move past this position (aligned step)

        return results

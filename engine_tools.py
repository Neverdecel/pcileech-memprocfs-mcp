"""
Engine-specific reverse engineering tools for Unreal Engine and IL2CPP (Unity).

Provides high-level dump utilities that read game engine metadata structures
via DMA memory reads and produce SDK-style output (C++ headers, C# classes).
"""

import struct


class UnrealEngine:
    """Unreal Engine FNamePool / FUObjectArray / SDK dumper using DMA reads."""

    # Version-keyed offset constants
    UE_OFFSETS = {
        "ue5": {
            # FNamePool layout
            "fnamepool_lock": 0,  # 8 bytes
            "fnamepool_current_block": 8,  # 4 bytes
            "fnamepool_current_byte_cursor": 12,  # 4 bytes
            "fnamepool_blocks": 16,  # array of 8192 pointers
            # FNameEntry header
            "fnameentry_header_size": 2,  # [bIsWide:1 | Len:15] (big-endian bitfield)
            # FUObjectArray
            "fuobjectarray_objects": 0,  # pointer to chunk array
            "fuobjectarray_max_elements": 8,
            "fuobjectarray_num_elements": 12,
            "fuobjectarray_chunk_size": 65536,
            # FUObjectItem
            "fuobjectitem_size": 24,  # [Object*:8][Flags:4][ClusterRoot:4][Serial:4] + padding
            "fuobjectitem_object": 0,
            "fuobjectitem_flags": 8,
            # UObject layout
            "uobject_vtable": 0,
            "uobject_flags": 8,
            "uobject_index": 12,
            "uobject_class": 16,
            "uobject_name": 24,  # FName (index + number)
            "uobject_outer": 32,
            "uobject_size": 40,
            # UStruct / UClass layout (offsets from UObject base)
            "ustruct_super": 0x40,  # SuperStruct pointer
            "ustruct_children": 0x48,  # Children (UField link)
            "ustruct_childproperties": 0x50,  # ChildProperties (FField link)
            "ustruct_size": 0x58,  # PropertiesSize (int32)
            # FField layout
            "ffield_class": 0,  # FFieldClass*
            "ffield_owner": 8,  # FFieldVariant
            "ffield_next": 0x20,  # FField* Next
            "ffield_name": 0x28,  # FName
            "ffield_flags": 0x30,  # EObjectFlags
            # FProperty layout (extends FField)
            "fproperty_offset": 0x44,  # int32 Offset_Internal
            "fproperty_size": 0x4C,  # int32 ElementSize
        },
        "ue4": {
            "fnamepool_lock": 0,
            "fnamepool_current_block": 8,
            "fnamepool_current_byte_cursor": 12,
            "fnamepool_blocks": 16,
            "fnameentry_header_size": 2,
            "fuobjectarray_objects": 0,
            "fuobjectarray_max_elements": 8,
            "fuobjectarray_num_elements": 12,
            "fuobjectarray_chunk_size": 65536,
            "fuobjectitem_size": 24,
            "fuobjectitem_object": 0,
            "fuobjectitem_flags": 8,
            "uobject_vtable": 0,
            "uobject_flags": 8,
            "uobject_index": 12,
            "uobject_class": 16,
            "uobject_name": 24,
            "uobject_outer": 32,
            "uobject_size": 40,
            "ustruct_super": 0x30,
            "ustruct_children": 0x38,
            "ustruct_childproperties": 0x38,  # UE4 uses UProperty (UField children)
            "ustruct_size": 0x40,
            "ffield_class": 0,
            "ffield_owner": 8,
            "ffield_next": 0x20,
            "ffield_name": 0x28,
            "ffield_flags": 0x30,
            "fproperty_offset": 0x44,
            "fproperty_size": 0x4C,
        },
    }

    def __init__(self, proc, ue_version="ue5"):
        self.proc = proc
        self.version = ue_version
        self.offsets = self.UE_OFFSETS[ue_version]
        self._name_cache = {}  # FName index -> string
        self._objects_cache = []  # cached UObject dicts from dump_objects

    def _resolve_name(self, fname_index):
        """Look up name from _name_cache. Return fallback if not found."""
        if fname_index in self._name_cache:
            return self._name_cache[fname_index]
        return f"FName_{fname_index}"

    def _read_fname(self, addr):
        """Read FName struct at addr (8 bytes: ComparisonIndex:i32, Number:i32), return resolved name string."""
        import memprocfs

        data = self.proc.memory.read(addr, 8, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        comparison_index = struct.unpack_from("<i", data, 0)[0]
        number = struct.unpack_from("<i", data, 4)[0]
        name = self._resolve_name(comparison_index)
        if number > 0:
            name = f"{name}_{number}"
        return name

    def dump_names(self, gnames_address, max_names=200000):
        """Read UE FNamePool and return all name entries.

        Args:
            gnames_address: Address of GNames / FNamePool.
            max_names: Maximum number of name entries to read.

        Returns:
            Dict with gnames_address, total_names, blocks_read, and names list.
        """
        import memprocfs

        # Read FNamePool header: current_block (uint32), current_byte_cursor (uint32)
        header_data = self.proc.memory.read(gnames_address, 16, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        current_block = struct.unpack_from(
            "<I", header_data, self.offsets["fnamepool_current_block"]
        )[0]
        current_byte_cursor = struct.unpack_from(
            "<I", header_data, self.offsets["fnamepool_current_byte_cursor"]
        )[0]

        num_blocks = current_block + 1

        # Read block pointers using scatter reads
        blocks_base = gnames_address + self.offsets["fnamepool_blocks"]
        scatter = self.proc.memory.scatter_initialize(memprocfs.FLAG_ZEROPAD_ON_FAIL)
        try:
            scatter.prepare([[blocks_base + i * 8, 8] for i in range(num_blocks)])
            scatter.execute()
            block_ptrs = []
            for i in range(num_blocks):
                ptr_data = scatter.read(blocks_base + i * 8, 8)
                block_ptrs.append(struct.unpack_from("<Q", ptr_data, 0)[0])
        finally:
            scatter.close()

        # Read each block's data and walk FNameEntry structures
        names = []
        total_count = 0
        block_stride = 65536  # bytes per block (except possibly the last)

        for block_idx in range(num_blocks):
            ptr = block_ptrs[block_idx]
            if ptr == 0:
                continue

            # Determine how many bytes to read from this block
            if block_idx == current_block:
                block_size = current_byte_cursor
            else:
                block_size = block_stride

            if block_size == 0:
                continue

            block_data = self.proc.memory.read(ptr, block_size, memprocfs.FLAG_ZEROPAD_ON_FAIL)

            # Block 0 starts at byte 2 (skip stride header), others start at 0
            cursor = 2 if block_idx == 0 else 0

            while cursor < len(block_data) - 2:
                if total_count >= max_names:
                    break

                # Read 2-byte FNameEntry header
                header = struct.unpack_from("<H", block_data, cursor)[0]
                name_len = header >> 1  # low 15 bits after shift
                is_wide = header & 1

                if name_len == 0:
                    # End of valid entries in this block
                    break

                header_bytes = self.offsets["fnameentry_header_size"]
                char_start = cursor + header_bytes

                if is_wide:
                    char_bytes = name_len * 2
                else:
                    char_bytes = name_len

                if char_start + char_bytes > len(block_data):
                    break

                if is_wide:
                    name_str = block_data[char_start : char_start + char_bytes].decode(
                        "utf-16-le", errors="replace"
                    )
                else:
                    name_str = block_data[char_start : char_start + char_bytes].decode(
                        "utf-8", errors="replace"
                    )

                # Index = (block_index << 16) | byte_offset_in_block
                fname_index = (block_idx << 16) | cursor
                self._name_cache[fname_index] = name_str

                names.append(
                    {
                        "index": fname_index,
                        "name": name_str,
                    }
                )
                total_count += 1

                # Advance cursor: header + char data, aligned to 2-byte boundary
                entry_size = header_bytes + char_bytes
                entry_size = (entry_size + 1) & ~1  # align up to 2
                cursor += entry_size

            if total_count >= max_names:
                break

        return {
            "gnames_address": f"0x{gnames_address:x}",
            "total_names": total_count,
            "blocks_read": num_blocks,
            "names": names[:1000],  # first 1000 for display
        }

    def dump_objects(self, gobjects_address, gnames_address=None, max_objects=200000):
        """Read FUObjectArray and dump all UObject entries.

        Args:
            gobjects_address: Address of GUObjectArray.
            gnames_address: Optional GNames address; if provided and name cache
                            is empty, dump_names is called first.
            max_objects: Maximum number of objects to read.

        Returns:
            Dict with gobjects_address, total_objects, and objects list.
        """
        import memprocfs

        # Populate name cache if needed
        if gnames_address is not None and not self._name_cache:
            self.dump_names(gnames_address)

        # Read FUObjectArray header
        header_data = self.proc.memory.read(gobjects_address, 16, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        objects_ptr = struct.unpack_from("<Q", header_data, self.offsets["fuobjectarray_objects"])[
            0
        ]
        num_elements = struct.unpack_from(
            "<i", header_data, self.offsets["fuobjectarray_num_elements"]
        )[0]

        if num_elements <= 0:
            return {
                "gobjects_address": f"0x{gobjects_address:x}",
                "total_objects": 0,
                "objects": [],
            }

        chunk_size = self.offsets["fuobjectarray_chunk_size"]
        num_chunks = (num_elements + chunk_size - 1) // chunk_size
        item_size = self.offsets["fuobjectitem_size"]

        # Read chunk pointers using scatter
        scatter = self.proc.memory.scatter_initialize(memprocfs.FLAG_ZEROPAD_ON_FAIL)
        try:
            scatter.prepare([[objects_ptr + i * 8, 8] for i in range(num_chunks)])
            scatter.execute()
            chunk_ptrs = []
            for i in range(num_chunks):
                ptr_data = scatter.read(objects_ptr + i * 8, 8)
                chunk_ptrs.append(struct.unpack_from("<Q", ptr_data, 0)[0])
        finally:
            scatter.close()

        objects = []
        total_count = 0

        for chunk_idx in range(num_chunks):
            chunk_ptr = chunk_ptrs[chunk_idx]
            if chunk_ptr == 0:
                continue

            # How many items in this chunk
            items_in_chunk = min(chunk_size, num_elements - chunk_idx * chunk_size)
            chunk_data_size = items_in_chunk * item_size

            chunk_data = self.proc.memory.read(
                chunk_ptr, chunk_data_size, memprocfs.FLAG_ZEROPAD_ON_FAIL
            )

            # Collect non-null object pointers for batch reading
            obj_addrs = []
            for i in range(items_in_chunk):
                if total_count + i >= max_objects:
                    break
                off = i * item_size
                obj_ptr = struct.unpack_from(
                    "<Q", chunk_data, off + self.offsets["fuobjectitem_object"]
                )[0]
                flags = struct.unpack_from(
                    "<I", chunk_data, off + self.offsets["fuobjectitem_flags"]
                )[0]
                if obj_ptr != 0:
                    obj_addrs.append((chunk_idx * chunk_size + i, obj_ptr, flags))

            if not obj_addrs:
                total_count += items_in_chunk
                if total_count >= max_objects:
                    break
                continue

            # Scatter read UObject headers for all non-null objects
            uobj_size = self.offsets["uobject_size"]
            scatter = self.proc.memory.scatter_initialize(memprocfs.FLAG_ZEROPAD_ON_FAIL)
            try:
                scatter.prepare([[addr, uobj_size] for _, addr, _ in obj_addrs])
                scatter.execute()

                class_ptrs_to_resolve = {}  # class_ptr -> list of obj indices
                obj_entries = []

                for idx, obj_ptr, flags in obj_addrs:
                    uobj_data = scatter.read(obj_ptr, uobj_size)

                    class_ptr = struct.unpack_from("<Q", uobj_data, self.offsets["uobject_class"])[
                        0
                    ]
                    fname_index = struct.unpack_from("<i", uobj_data, self.offsets["uobject_name"])[
                        0
                    ]
                    fname_number = struct.unpack_from(
                        "<i", uobj_data, self.offsets["uobject_name"] + 4
                    )[0]
                    outer_ptr = struct.unpack_from("<Q", uobj_data, self.offsets["uobject_outer"])[
                        0
                    ]

                    name = self._resolve_name(fname_index)
                    if fname_number > 0:
                        name = f"{name}_{fname_number}"

                    entry = {
                        "index": idx,
                        "address": f"0x{obj_ptr:x}",
                        "name": name,
                        "class_name": None,  # resolved below
                        "outer": f"0x{outer_ptr:x}" if outer_ptr != 0 else None,
                        "flags": flags,
                        "_class_ptr": class_ptr,
                    }
                    obj_entries.append(entry)

                    if class_ptr != 0:
                        if class_ptr not in class_ptrs_to_resolve:
                            class_ptrs_to_resolve[class_ptr] = []
                        class_ptrs_to_resolve[class_ptr].append(len(obj_entries) - 1)
            finally:
                scatter.close()

            # Batch-resolve class names by reading FName from each ClassPrivate UObject
            if class_ptrs_to_resolve:
                name_off = self.offsets["uobject_name"]
                scatter = self.proc.memory.scatter_initialize(memprocfs.FLAG_ZEROPAD_ON_FAIL)
                try:
                    unique_class_ptrs = list(class_ptrs_to_resolve.keys())
                    scatter.prepare([[cptr + name_off, 8] for cptr in unique_class_ptrs])
                    scatter.execute()

                    for cptr in unique_class_ptrs:
                        fname_data = scatter.read(cptr + name_off, 8)
                        ci = struct.unpack_from("<i", fname_data, 0)[0]
                        cn = struct.unpack_from("<i", fname_data, 4)[0]
                        class_name = self._resolve_name(ci)
                        if cn > 0:
                            class_name = f"{class_name}_{cn}"
                        for obj_idx in class_ptrs_to_resolve[cptr]:
                            obj_entries[obj_idx]["class_name"] = class_name
                finally:
                    scatter.close()

            # Strip internal field and add to results
            for entry in obj_entries:
                del entry["_class_ptr"]
                objects.append(entry)

            total_count += items_in_chunk
            if total_count >= max_objects:
                break

        self._objects_cache = objects

        return {
            "gobjects_address": f"0x{gobjects_address:x}",
            "total_objects": len(objects),
            "objects": objects[:1000],  # first 1000 for display
        }

    def dump_sdk(self, gobjects_address, gnames_address, output_file=None, max_classes=5000):
        """Generate C++ SDK headers from UE reflection system.

        Args:
            gobjects_address: Address of GUObjectArray.
            gnames_address: Address of GNames / FNamePool.
            output_file: Optional path to write SDK header file.
            max_classes: Maximum number of classes to process.

        Returns:
            Dict with summary of generated SDK classes and properties.
        """
        import memprocfs

        # Ensure name cache is populated
        if not self._name_cache:
            self.dump_names(gnames_address)

        # Ensure objects cache is populated
        if not self._objects_cache:
            self.dump_objects(gobjects_address, gnames_address)

        # Find all UClass objects (class_name == 'Class')
        class_objects = []
        for obj in self._objects_cache:
            if obj.get("class_name") == "Class" and len(class_objects) < max_classes:
                class_objects.append(obj)

        sdk_classes = []
        total_properties = 0
        sdk_lines = [
            "// Auto-generated Unreal Engine SDK",
            f"// Engine version: {self.version}",
            f"// Total classes: {len(class_objects)}",
            "",
        ]

        for cls_obj in class_objects:
            cls_addr = int(cls_obj["address"], 16)

            # Read UStruct fields: SuperStruct, ChildProperties, PropertiesSize
            struct_data = self.proc.memory.read(
                cls_addr, self.offsets["ustruct_size"] + 4, memprocfs.FLAG_ZEROPAD_ON_FAIL
            )

            super_ptr = struct.unpack_from("<Q", struct_data, self.offsets["ustruct_super"])[0]
            child_props_ptr = struct.unpack_from(
                "<Q", struct_data, self.offsets["ustruct_childproperties"]
            )[0]
            props_size = struct.unpack_from("<i", struct_data, self.offsets["ustruct_size"])[0]

            # Resolve super class name
            super_name = None
            if super_ptr != 0:
                super_name = self._read_fname(super_ptr + self.offsets["uobject_name"])

            # Walk ChildProperties (FField chain)
            properties = []
            field_ptr = child_props_ptr
            walk_limit = 500  # prevent infinite loops
            while field_ptr != 0 and walk_limit > 0:
                walk_limit -= 1

                # Read FField data: class ptr, next ptr, name, and FProperty offsets
                read_size = max(self.offsets["fproperty_size"] + 4, self.offsets["ffield_next"] + 8)
                field_data = self.proc.memory.read(
                    field_ptr, read_size, memprocfs.FLAG_ZEROPAD_ON_FAIL
                )

                # FFieldClass pointer (for property type name)
                field_class_ptr = struct.unpack_from(
                    "<Q", field_data, self.offsets["ffield_class"]
                )[0]

                # FName of the field
                fname_index = struct.unpack_from("<i", field_data, self.offsets["ffield_name"])[0]
                fname_number = struct.unpack_from(
                    "<i", field_data, self.offsets["ffield_name"] + 4
                )[0]
                field_name = self._resolve_name(fname_index)
                if fname_number > 0:
                    field_name = f"{field_name}_{fname_number}"

                # FProperty: Offset_Internal and ElementSize
                prop_offset = struct.unpack_from(
                    "<i", field_data, self.offsets["fproperty_offset"]
                )[0]
                prop_elem_size = struct.unpack_from(
                    "<i", field_data, self.offsets["fproperty_size"]
                )[0]

                # Resolve FFieldClass name (FFieldClass has FName at offset 0)
                prop_type_name = "Unknown"
                if field_class_ptr != 0:
                    try:
                        type_fname_data = self.proc.memory.read(
                            field_class_ptr, 8, memprocfs.FLAG_ZEROPAD_ON_FAIL
                        )
                        type_fi = struct.unpack_from("<i", type_fname_data, 0)[0]
                        prop_type_name = self._resolve_name(type_fi)
                    except Exception:
                        pass

                properties.append(
                    {
                        "name": field_name,
                        "type": prop_type_name,
                        "offset": prop_offset,
                        "size": prop_elem_size,
                    }
                )
                total_properties += 1

                # Follow Next pointer
                next_ptr = struct.unpack_from("<Q", field_data, self.offsets["ffield_next"])[0]
                field_ptr = next_ptr

            cls_name = cls_obj["name"]
            cls_info = {
                "name": cls_name,
                "super": super_name,
                "size": props_size,
                "property_count": len(properties),
            }
            sdk_classes.append(cls_info)

            # Generate C++ header lines
            if super_name:
                sdk_lines.append(f"// Size: 0x{props_size:X}")
                sdk_lines.append(f"class {cls_name} : public {super_name} {{")
            else:
                sdk_lines.append(f"// Size: 0x{props_size:X}")
                sdk_lines.append(f"class {cls_name} {{")
            sdk_lines.append("public:")

            for prop in sorted(properties, key=lambda p: p["offset"]):
                sdk_lines.append(
                    f'    {prop["type"]} {prop["name"]}; '
                    f'// 0x{prop["offset"]:X} (Size: 0x{prop["size"]:X})'
                )

            sdk_lines.append("};")
            sdk_lines.append("")

        # Write to file if requested
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(sdk_lines))

        return {
            "gobjects_address": f"0x{gobjects_address:x}",
            "gnames_address": f"0x{gnames_address:x}",
            "total_classes": len(sdk_classes),
            "total_properties": total_properties,
            "output_file": output_file,
            "classes": sdk_classes[:100],  # summary of first 100 classes
        }


class IL2CPP:
    """IL2CPP (Unity) metadata dumper using DMA reads."""

    # Metadata magic
    METADATA_MAGIC = 0xFAB11BAF

    # Version-keyed header offsets (for Il2CppGlobalMetadataHeader)
    HEADER_OFFSETS = {
        29: {
            "string_offset": 8,
            "string_size": 12,
            "events_offset": 16,
            "events_size": 20,
            "properties_offset": 24,
            "properties_size": 28,
            "methods_offset": 32,
            "methods_size": 36,
            "field_offset": 56,
            "field_size": 60,
            "type_definitions_offset": 168,
            "type_definitions_size": 172,
            "images_offset": 96,
            "images_size": 100,
            "assemblies_offset": 104,
            "assemblies_size": 108,
        },
        27: {
            "string_offset": 8,
            "string_size": 12,
            "events_offset": 16,
            "events_size": 20,
            "properties_offset": 24,
            "properties_size": 28,
            "methods_offset": 32,
            "methods_size": 36,
            "field_offset": 56,
            "field_size": 60,
            "type_definitions_offset": 168,
            "type_definitions_size": 172,
            "images_offset": 96,
            "images_size": 100,
            "assemblies_offset": 104,
            "assemblies_size": 108,
        },
        31: {
            "string_offset": 8,
            "string_size": 12,
            "events_offset": 16,
            "events_size": 20,
            "properties_offset": 24,
            "properties_size": 28,
            "methods_offset": 32,
            "methods_size": 36,
            "field_offset": 56,
            "field_size": 60,
            "type_definitions_offset": 168,
            "type_definitions_size": 172,
            "images_offset": 96,
            "images_size": 100,
            "assemblies_offset": 104,
            "assemblies_size": 108,
        },
    }

    # TypeDefinition struct sizes by version
    TYPEDEF_SIZE = {27: 92, 29: 100, 31: 108}
    # Field struct size
    FIELD_SIZE = 12  # [nameIndex:4][typeIndex:4][token:4]
    # Method struct size
    METHOD_SIZE = {27: 28, 29: 32, 31: 36}

    def __init__(self, proc):
        self.proc = proc

    def _read_metadata_string(self, metadata_data, string_table_offset, index):
        """Read null-terminated string from metadata_data at string_table_offset + index."""
        pos = string_table_offset + index
        if pos < 0 or pos >= len(metadata_data):
            return f"String_{index}"
        end = metadata_data.find(b"\x00", pos)
        if end == -1:
            end = min(pos + 256, len(metadata_data))
        return metadata_data[pos:end].decode("utf-8", errors="replace")

    def dump(self, pid_or_process=None, output_file=None, max_classes=5000):
        """Dump IL2CPP metadata: type definitions, fields, and methods.

        Locates GameAssembly.dll, finds the global-metadata.dat blob in memory
        by scanning for the IL2CPP magic, then parses type definitions, fields,
        and methods from the metadata structures.

        Args:
            pid_or_process: Unused (proc is already bound via __init__).
            output_file: Optional path to write C#-style class definitions.
            max_classes: Maximum number of type definitions to process.

        Returns:
            Dict with metadata address, version, type/field/method counts,
            and a list of class summaries.
        """
        import memprocfs

        # Find GameAssembly.dll in module list
        game_assembly = None
        for mod in self.proc.module_list():
            if mod.name.lower() == "gameassembly.dll":
                game_assembly = mod
                break

        if game_assembly is None:
            raise Exception("GameAssembly.dll not found in process module list")

        ga_base = game_assembly.base

        # Read .data section of GameAssembly.dll to find pointer to metadata
        # Parse PE headers to find .data section
        dos_header = self.proc.memory.read(ga_base, 64, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        if dos_header[:2] != b"MZ":
            raise Exception(f"Invalid PE: no MZ signature at GameAssembly.dll base 0x{ga_base:x}")

        e_lfanew = struct.unpack_from("<I", dos_header, 0x3C)[0]
        pe_header = self.proc.memory.read(ga_base + e_lfanew, 264, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        if pe_header[:4] != b"PE\x00\x00":
            raise Exception("Invalid PE: no PE signature in GameAssembly.dll")

        num_sections = struct.unpack_from("<H", pe_header, 6)[0]
        size_of_optional = struct.unpack_from("<H", pe_header, 20)[0]
        section_table_offset = ga_base + e_lfanew + 4 + 20 + size_of_optional
        section_data = self.proc.memory.read(
            section_table_offset, num_sections * 40, memprocfs.FLAG_ZEROPAD_ON_FAIL
        )

        # Collect .data and .rdata sections
        data_sections = []
        for i in range(num_sections):
            off = i * 40
            sec_name = (
                section_data[off : off + 8].split(b"\x00")[0].decode("ascii", errors="replace")
            )
            sec_rva = struct.unpack_from("<I", section_data, off + 12)[0]
            sec_vsize = struct.unpack_from("<I", section_data, off + 8)[0]
            if sec_name in (".data", ".rdata"):
                data_sections.append((ga_base + sec_rva, sec_vsize))

        # Scan data sections for pointers to metadata (look for magic at pointed-to address)
        metadata_addr = None
        magic_bytes = struct.pack("<I", self.METADATA_MAGIC)

        for sec_base, sec_size in data_sections:
            # Read section data and scan for pointer-aligned values
            sec_data = self.proc.memory.read(sec_base, sec_size, memprocfs.FLAG_ZEROPAD_ON_FAIL)

            # Check every 8-byte aligned value as a potential pointer
            candidate_ptrs = []
            for off in range(0, len(sec_data) - 7, 8):
                ptr_val = struct.unpack_from("<Q", sec_data, off)[0]
                # Filter: valid usermode pointer range
                if 0x10000 < ptr_val < 0x7FFFFFFFFFFF:
                    candidate_ptrs.append(ptr_val)

            # Batch-check candidates using scatter reads
            batch_size = 512
            for batch_start in range(0, len(candidate_ptrs), batch_size):
                batch = candidate_ptrs[batch_start : batch_start + batch_size]
                scatter = self.proc.memory.scatter_initialize(memprocfs.FLAG_ZEROPAD_ON_FAIL)
                try:
                    scatter.prepare([[ptr, 4] for ptr in batch])
                    scatter.execute()
                    for ptr in batch:
                        check = scatter.read(ptr, 4)
                        if check == magic_bytes:
                            metadata_addr = ptr
                            break
                finally:
                    scatter.close()

                if metadata_addr is not None:
                    break

            if metadata_addr is not None:
                break

        # Fallback: AOB scan process memory for the magic directly
        if metadata_addr is None:
            try:
                for vad in self.proc.maps.vad():
                    start = vad.get("start", vad.get("va", 0))
                    size = vad.get("size", vad.get("cb", 0))
                    if size <= 0 or size > 64 * 1024 * 1024:
                        continue
                    region = self.proc.memory.read(start, size, memprocfs.FLAG_ZEROPAD_ON_FAIL)
                    idx = region.find(magic_bytes)
                    if idx != -1:
                        # Verify it looks like a metadata header (version in sane range)
                        if idx + 8 <= len(region):
                            ver = struct.unpack_from("<I", region, idx + 4)[0]
                            if 20 <= ver <= 40:
                                metadata_addr = start + idx
                                break
            except Exception:
                pass

        if metadata_addr is None:
            raise Exception(
                "IL2CPP metadata not found: could not locate FAB11BAF magic in process memory"
            )

        # Read metadata header (first 256 bytes)
        meta_header = self.proc.memory.read(metadata_addr, 256, memprocfs.FLAG_ZEROPAD_ON_FAIL)
        magic_check = struct.unpack_from("<I", meta_header, 0)[0]
        if magic_check != self.METADATA_MAGIC:
            raise Exception(
                f"Metadata magic mismatch at 0x{metadata_addr:x}: got 0x{magic_check:x}"
            )

        version = struct.unpack_from("<I", meta_header, 4)[0]

        # Select offsets for this version (fall back to v29)
        if version in self.HEADER_OFFSETS:
            hdr_off = self.HEADER_OFFSETS[version]
        else:
            hdr_off = self.HEADER_OFFSETS[29]

        typedef_size = self.TYPEDEF_SIZE.get(version, self.TYPEDEF_SIZE[29])
        method_size = self.METHOD_SIZE.get(version, self.METHOD_SIZE[29])

        # Read header fields
        string_offset = struct.unpack_from("<I", meta_header, hdr_off["string_offset"])[0]
        string_size = struct.unpack_from("<I", meta_header, hdr_off["string_size"])[0]
        typedef_offset = struct.unpack_from("<I", meta_header, hdr_off["type_definitions_offset"])[
            0
        ]
        typedef_total_size = struct.unpack_from(
            "<I", meta_header, hdr_off["type_definitions_size"]
        )[0]
        field_offset = struct.unpack_from("<I", meta_header, hdr_off["field_offset"])[0]
        field_total_size = struct.unpack_from("<I", meta_header, hdr_off["field_size"])[0]
        methods_offset = struct.unpack_from("<I", meta_header, hdr_off["methods_offset"])[0]
        methods_total_size = struct.unpack_from("<I", meta_header, hdr_off["methods_size"])[0]

        # Calculate total metadata size needed and read it all at once
        max_needed = max(
            string_offset + string_size,
            typedef_offset + typedef_total_size,
            field_offset + field_total_size,
            methods_offset + methods_total_size,
        )
        # Cap at 128 MB to avoid absurd reads
        max_needed = min(max_needed, 128 * 1024 * 1024)

        metadata_data = self.proc.memory.read(
            metadata_addr, max_needed, memprocfs.FLAG_ZEROPAD_ON_FAIL
        )

        # Parse type definitions
        num_typedefs = typedef_total_size // typedef_size
        num_fields = field_total_size // self.FIELD_SIZE
        num_methods = methods_total_size // method_size

        classes = []
        cs_lines = [
            "// Auto-generated IL2CPP dump",
            f"// Metadata version: {version}",
            f"// Total types: {num_typedefs}",
            "",
        ]

        for i in range(min(num_typedefs, max_classes)):
            td_pos = typedef_offset + i * typedef_size
            if td_pos + typedef_size > len(metadata_data):
                break

            td_data = metadata_data[td_pos : td_pos + typedef_size]

            name_index = struct.unpack_from("<i", td_data, 0)[0]
            namespace_index = struct.unpack_from("<i", td_data, 4)[0]

            # fieldStart and fieldCount location varies by version but typically at:
            # fieldStart: offset 64 (v29), fieldCount: offset 84 (v29) as int16
            # methodStart: offset 68 (v29), methodCount: offset 86 (v29) as int16
            # These are approximate — actual offsets depend on the TypeDefinition struct layout
            if version >= 29:
                field_start = struct.unpack_from("<i", td_data, 64)[0]
                method_start = struct.unpack_from("<i", td_data, 68)[0]
                field_count = struct.unpack_from("<h", td_data, 84)[0]
                method_count = struct.unpack_from("<h", td_data, 86)[0]
            else:
                field_start = struct.unpack_from("<i", td_data, 56)[0]
                method_start = struct.unpack_from("<i", td_data, 60)[0]
                field_count = struct.unpack_from("<h", td_data, 76)[0]
                method_count = struct.unpack_from("<h", td_data, 78)[0]

            type_name = self._read_metadata_string(metadata_data, string_offset, name_index)
            namespace = self._read_metadata_string(metadata_data, string_offset, namespace_index)

            # Parse fields for this type
            fields = []
            for fi in range(max(0, field_count)):
                f_idx = field_start + fi
                if f_idx < 0 or f_idx >= num_fields:
                    break
                f_pos = field_offset + f_idx * self.FIELD_SIZE
                if f_pos + self.FIELD_SIZE > len(metadata_data):
                    break

                f_name_idx = struct.unpack_from("<i", metadata_data, f_pos)[0]
                f_type_idx = struct.unpack_from("<i", metadata_data, f_pos + 4)[0]
                f_name = self._read_metadata_string(metadata_data, string_offset, f_name_idx)

                fields.append(
                    {
                        "name": f_name,
                        "type_index": f_type_idx,
                    }
                )

            # Parse methods for this type
            methods = []
            for mi in range(max(0, method_count)):
                m_idx = method_start + mi
                if m_idx < 0 or m_idx >= num_methods:
                    break
                m_pos = methods_offset + m_idx * method_size
                if m_pos + method_size > len(metadata_data):
                    break

                m_name_idx = struct.unpack_from("<i", metadata_data, m_pos)[0]
                m_name = self._read_metadata_string(metadata_data, string_offset, m_name_idx)

                methods.append(
                    {
                        "name": m_name,
                    }
                )

            cls_info = {
                "name": type_name,
                "namespace": namespace,
                "field_count": len(fields),
                "method_count": len(methods),
                "fields": fields,
            }
            classes.append(cls_info)

            # Generate C# class lines
            cs_lines.append(f"// Namespace: {namespace}")
            cs_lines.append(f"public class {type_name} {{")
            for fld in fields:
                cs_lines.append(
                    f'    /* TypeIndex: {fld["type_index"]} */ public var {fld["name"]};'
                )
            for mtd in methods:
                cs_lines.append(f'    public void {mtd["name"]}() {{ }}')
            cs_lines.append("}")
            cs_lines.append("")

        # Write to file if requested
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write("\n".join(cs_lines))

        return {
            "game_assembly": f"0x{ga_base:x}",
            "metadata_address": f"0x{metadata_addr:x}",
            "metadata_version": version,
            "total_types": num_typedefs,
            "total_fields": num_fields,
            "total_methods": num_methods,
            "output_file": output_file,
            "classes": classes[:100],  # first 100 for display
        }

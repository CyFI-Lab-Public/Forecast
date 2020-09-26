import logging
from typing import Dict, Optional, Tuple

from angr import Project

from .resolver_base import FunctionResolver

log = logging.getLogger(__name__)


class PeFormat:
    EXPORT_DIR_OFF = None
    EXPORT_DIR_SZ_OFF = None
    IMPORT_DIR_OFF = None
    IMPORT_DIR_SZ_OFF = None
    IAT_OFF = None
    IAT_SZ_OFF = None
    ILT_SZ = None  # bytes


class Pe32Format(PeFormat):
    EXPORT_DIR_OFF = 0x78
    EXPORT_DIR_SZ_OFF = 0x7C
    IMPORT_DIR_OFF = 0x80
    IMPORT_DIR_SZ_OFF = 0x84
    IAT_OFF = 0xD8
    IAT_SZ_OFF = 0xDC
    ILT_SZ = 4  # bytes


class Pe32PlusFormat(PeFormat):
    EXPORT_DIR_OFF = 0x88
    EXPORT_DIR_SZ_OFF = 0x8C
    IMPORT_DIR_OFF = 0x90
    IMPORT_DIR_SZ_OFF = 0x94
    IAT_OFF = 0xE8
    IAT_SZ_OFF = 0xEC
    ILT_SZ = 8  # bytes


class PeResolver(FunctionResolver):
    def __init__(self, proj: Project):
        super().__init__(proj)
        self.ordinal_warning_logged = False

    def _get_common_info(
        self, start_addr: int
    ) -> Tuple[bool, Optional[int], Optional[PeFormat]]:
        pe_header_addr = start_addr + self.load(start_addr + 0x3C, 4)
        size_of_optional_headers = self.load(pe_header_addr + 0x14, 2)
        if size_of_optional_headers == 0:
            log.warning("PE file has no optional headers")
            return (False, None, None)

        # Get correct offsets based on PE type
        magic = self.load(pe_header_addr + 0x18, 2)
        if magic == 0x10B:
            pe_format = Pe32Format
        else:
            pe_format = Pe32PlusFormat

        return (True, pe_header_addr, pe_format)

    def get_imports(self, start_addr: int) -> Dict[int, str]:
        log.debug(f"Analyzing import table of main object at 0x{start_addr:X}")
        opt_headers, pe_header_addr, pe_format = self._get_common_info(start_addr)
        if not opt_headers:
            return {}

        # Locate import directory info
        import_directory_offset = self.load(
            pe_header_addr + pe_format.IMPORT_DIR_OFF, 4
        )
        import_directory_size = self.load(
            pe_header_addr + pe_format.IMPORT_DIR_SZ_OFF, 4
        )
        iat_offset = self.load(pe_header_addr + pe_format.IAT_OFF, 4)
        iat_size = self.load(pe_header_addr + pe_format.IAT_SZ_OFF, 4)
        log.log(
            5,
            f"Import dir offset: {hex(import_directory_offset)}, size: {import_directory_size}",
        )
        log.log(5, f"IAT offset: {hex(iat_offset)}, size: {iat_size}")
        if import_directory_size == 0 or iat_size == 0:
            return {}

        # Parse import directory table
        import_dlls = []
        idx = 0
        while 1:
            dir_entry_addr = start_addr + import_directory_offset + (idx * 20)
            if self.load(dir_entry_addr, 20) == 0:
                break
            dll_name_addr = start_addr + self.load(dir_entry_addr + 12, 4)
            dll_name = self.load_string(dll_name_addr)
            import_lookup_table_rva = self.load(dir_entry_addr, 4)
            iat_rva = self.load(dir_entry_addr + 16, 4)
            import_dlls.append(
                {
                    "name": dll_name,
                    "lookup_table": import_lookup_table_rva,
                    "iat": iat_rva,
                }
            )
            idx += 1

        # Get data for each imported function
        function_pointers = {}

        for dll in import_dlls:
            log.debug(f"Found imported DLL: {dll['name']}")
            # Iterate through Import Directory Table
            import_lookup_table_addr = start_addr + dll["lookup_table"]
            iat_addr = start_addr + dll["iat"]
            idx = 0
            while 1:
                lookup_entry_addr = import_lookup_table_addr + (idx * pe_format.ILT_SZ)
                iat_entry_addr = iat_addr + (idx * pe_format.ILT_SZ)
                ilt_entry = self.load(lookup_entry_addr, pe_format.ILT_SZ)
                if ilt_entry == 0:
                    break

                ord_name_flag = ilt_entry >> ((pe_format.ILT_SZ * 8) - 1)
                if ord_name_flag == 1:
                    ordinal = ilt_entry & 0xFFFF
                    log.log(5, f"   IAT {hex(iat_entry_addr)}: Ord {ordinal}")
                    # TODO: Handle import by ordinal
                    if not self.ordinal_warning_logged:
                        log.warning("Cannot handle import by ordinal")
                        self.ordinal_warning_logged = True
                else:
                    hint_name_entry_addr = (ilt_entry & 0x7FFFFFFF) + start_addr
                    hint_name = self.load_string(hint_name_entry_addr + 2)
                    log.log(5, f"   IAT {hex(iat_entry_addr)}: {hint_name}")
                    function_pointers[iat_entry_addr] = hint_name
                idx += 1

        return function_pointers

    def get_exports(self, start_addr: int) -> Dict[int, str]:
        opt_headers, pe_header_addr, pe_format = self._get_common_info(start_addr)
        if not opt_headers:
            return {}

        # Get export directory address and size
        export_dir_offset = self.load(pe_header_addr + pe_format.EXPORT_DIR_OFF, 4)
        export_dir_size = self.load(pe_header_addr + pe_format.EXPORT_DIR_SZ_OFF, 4)
        if export_dir_size == 0:
            return {}
        export_dir_addr = start_addr + export_dir_offset

        # Parse the Export Directory Table
        dll_name_addr = start_addr + self.load(export_dir_addr + 12, 4)
        dll_name = self.load_string(dll_name_addr)
        log.debug(f"Analyzing export table of {dll_name} at 0x{start_addr:X}")
        log.log(
            5, f"Export dir address: {hex(export_dir_addr)}, size: {export_dir_size}"
        )

        num_name_pointers = self.load(export_dir_addr + 24, 4)
        export_addr_table_addr = start_addr + self.load(export_dir_addr + 28, 4)
        name_ptr_table_addr = start_addr + self.load(export_dir_addr + 32, 4)
        ordinal_table_addr = start_addr + self.load(export_dir_addr + 36, 4)

        # Get details for each exported function
        function_pointers = {}
        for i in range(num_name_pointers):
            # Parse name pointer table and export ordinal table
            name_ptr_entry_addr = name_ptr_table_addr + (i * 4)
            ordinal_entry_addr = ordinal_table_addr + (i * 2)
            name_ptr_entry = self.load(name_ptr_entry_addr, 4)
            name_ptr_addr = start_addr + name_ptr_entry
            ordinal_entry = self.load(ordinal_entry_addr, 2)
            export_name = self.load_string(name_ptr_addr, max_size=200)
            log.log(5, f"   {ordinal_entry}: {export_name}")

            # Parse export address table
            export_addr_table_entry_addr = export_addr_table_addr + (ordinal_entry * 4)
            export_addr = start_addr + self.load(export_addr_table_entry_addr, 4)
            if export_dir_addr <= export_addr < export_dir_addr + export_dir_size:
                # Forwarder RVA
                forwarder_name = self.load_string(export_addr)
                log.log(5, f"      Forwarder: {forwarder_name}")
            else:
                # Export RVA
                log.log(5, f"      Export RVA: {hex(export_addr)}")
                function_pointers[export_addr] = export_name

        return function_pointers

    @classmethod
    def is_compatible(cls, start_addr: int, proj: Project) -> bool:
        loader = proj.loader
        magic = loader.memory.load(start_addr, 2)
        if magic != b"MZ":
            return False
        pe_signature_addr = start_addr + int.from_bytes(
            loader.memory.load(start_addr + 0x3C, 4), "little"
        )
        pe_signature = loader.memory.load(pe_signature_addr, 4)
        optional_header_magic = int.from_bytes(
            loader.memory.load(pe_signature_addr + 0x18, 2), "little"
        )
        return pe_signature == b"PE\0\0" and optional_header_magic in (0x10B, 0x20B)

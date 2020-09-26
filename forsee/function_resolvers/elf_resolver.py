import logging
from enum import Enum
from typing import Dict, Iterable

from angr import Project

from .resolver_base import FunctionResolver

log = logging.getLogger(__name__)


class DynamicTags(Enum):
    PLTRELSZ = 2
    STRTAB = 5
    SYMTAB = 6
    RELA = 7
    RELAENT = 9
    STRSZ = 10
    SYMENT = 11
    REL = 17
    RELENT = 19
    PLTREL = 20
    JMPREL = 23


class Elf32Resolver(FunctionResolver):
    # TODO: What changes need to be made for Elf 64?
    def _validate_dynamic_entries(
        self, tags: Iterable[DynamicTags], dynamic_entries: Dict[int, int]
    ) -> bool:
        """
        Validates that all tags are in the dynamic entries dictionary.
        """
        validated = True
        for tag in tags:
            if tag.value not in dynamic_entries:
                log.warning(f"Could not find {tag.name}")
                validated = False
        return validated

    def get_imports(self, start_addr: int) -> Dict[int, str]:
        # Find program header
        e_phoff = self.load(start_addr + 28, 4)
        e_phentsize = self.load(start_addr + 42, 2)
        e_phnum = self.load(start_addr + 44, 2)

        if e_phnum == 0:
            log.warning("Program header has no entries")
            return {}

        # Find dynamic section table
        p_vaddr = None
        for i in range(e_phnum):
            entry_addr = i * e_phentsize + start_addr + e_phoff
            p_type = self.load(entry_addr, 4)
            if p_type == 2:
                p_vaddr = self.load(entry_addr + 8, 4)
                p_filesz = self.load(entry_addr + 16, 4)
                break

        if p_vaddr is None:
            log.warning("Could not find dynamic section")
            return {}
        if p_filesz == 0:
            log.warning("Dynamic section is empty")
            return {}

        # Process dynamic section entries
        dynamic_entries = {}
        for i in range(int(p_filesz / 8)):
            entry_addr = i * 8 + p_vaddr
            d_tag = self.load(entry_addr, 4)
            d_un = self.load(entry_addr + 4, 4)
            dynamic_entries[d_tag] = d_un

        non_rel_entries = [
            DynamicTags.STRTAB,
            DynamicTags.SYMTAB,
            DynamicTags.STRSZ,
            DynamicTags.SYMENT,
            DynamicTags.PLTREL,
            DynamicTags.PLTRELSZ,
        ]
        if not self._validate_dynamic_entries(non_rel_entries, dynamic_entries):
            return {}
        plt_rel = dynamic_entries[DynamicTags.PLTREL.value]
        if plt_rel == DynamicTags.REL.value:
            rel_entries = [DynamicTags.RELENT]
            if not self._validate_dynamic_entries(rel_entries, dynamic_entries):
                return {}
            rel_ent_size = dynamic_entries[DynamicTags.RELENT.value]
        elif plt_rel == DynamicTags.RELA.value:
            rela_entries = [DynamicTags.RELAENT]
            if not self._validate_dynamic_entries(rela_entries, dynamic_entries):
                return {}
            rel_ent_size = dynamic_entries[DynamicTags.RELAENT.value]
        else:
            log.warning("Invalid PLTREL value")
            return {}

        # Process Jump Relocation Table
        relocs = {}
        jump_rel_ptr = dynamic_entries[DynamicTags.JMPREL.value]
        plt_rel_size = dynamic_entries[DynamicTags.PLTRELSZ.value]
        jump_rel_size = int(plt_rel_size / rel_ent_size)
        for i in range(jump_rel_size):
            entry_addr = i * rel_ent_size + jump_rel_ptr
            r_offset = self.load(entry_addr, 4)
            r_info = self.load(entry_addr + 4, 4)
            r_sym = r_info >> 8
            relocs[r_sym] = r_offset

        # Process Symbol Table and String Table
        function_pointers = {}
        sym_table_addr = dynamic_entries[DynamicTags.SYMTAB.value]
        sym_ent_size = dynamic_entries[DynamicTags.SYMENT.value]
        str_table_addr = dynamic_entries[DynamicTags.STRTAB.value]
        for index, sym_addr in relocs.items():
            entry_addr = index * sym_ent_size + sym_table_addr
            str_table_index = self.load(entry_addr, 4)
            sym_name = self.load_string(str_table_addr + str_table_index)
            function_pointers[sym_addr] = sym_name

        return function_pointers

    def get_exports(self, start_addr: int) -> Dict[int, str]:
        log.warning("Exports not implemented for ELF files")
        # TODO: Implement
        return {}

    @classmethod
    def is_compatible(cls, start_addr: int, proj: Project) -> bool:
        if proj.arch.bits != 32:
            return False
        loader = proj.loader
        magic = loader.memory.load(start_addr, 4)
        return magic == b"\x7fELF"

import logging
from typing import Dict, List, Tuple

from angr import Project

log = logging.getLogger(__name__)


class FunctionResolver:
    def __init__(self, proj: Project):
        self.proj = proj
        self.loader = proj.loader

    def load(self, addr: int, size: int) -> int:
        """
        Load the contents of memory at the specified address
        """
        value = self.loader.memory.load(addr, size)
        return int.from_bytes(value, "little")

    def load_string(self, addr: int, max_size: int = 100) -> str:
        """
        Load the string at the specified address
        """
        index = 0
        string = ""
        while index < max_size:
            last_char = self.load(addr + index, 1)
            if last_char == 0:
                break
            string += chr(last_char)
            index += 1
        else:
            log.warning(f'String "{string}..." exceeded max size {max_size}')
        return string

    def get_imports(self, start_addr: int) -> Dict[int, str]:
        raise NotImplementedError()

    def get_exports(self, start_addr: int) -> Dict[int, str]:
        raise NotImplementedError()

    def find_functions(
        self, main_object: int, loaded_libraries: List[int]
    ) -> Tuple[Dict[int, str], Dict[int, str]]:
        imports = self.get_imports(main_object)
        all_exports = {}
        for lib in loaded_libraries:
            lib_exports = self.get_exports(lib)
            all_exports.update(lib_exports)
        return imports, all_exports

    @classmethod
    def is_compatible(cls, start_addr: int, proj: Project) -> bool:
        """
        Determines whether this backend can parse the file format of the project binary
        """
        raise NotImplementedError()

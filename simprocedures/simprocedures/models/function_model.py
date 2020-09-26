import logging
from typing import List, Optional

from angr import SimCC
from angr.calling_conventions import SimCCStdcall
from archinfo import Arch, ArchX86

from simprocedures.models.data_types import MASTER_TYPES

log = logging.getLogger(__name__)


class Parameter:
    def __init__(
        self, name: str, type: Optional[str] = None, meta: Optional[str] = None
    ):
        self.name = name
        if not type:
            self.type = None
        elif type in MASTER_TYPES:
            self.type = MASTER_TYPES[type]
        else:
            if meta and "out" in meta.lower():
                log.warning(
                    f"No definition for type {type} which is an output. Add defintion for"
                    f" proper functionality"
                )
            else:
                log.debug(f"No definition for type {type} which is an input")
            self.type = MASTER_TYPES["void"]
        self.meta = meta


class FunctionModel:
    def __init__(self, name: str, params: List[Parameter], cc: Optional[str] = None):
        self.name = name
        self.params = params
        self.cc_str = cc

    @property
    def num_params(self) -> int:
        return len(self.params)

    @property
    def has_complete_metadata(self) -> bool:
        return all([p.meta for p in self.params])

    @property
    def has_complete_typing(self) -> bool:
        return all([p.type for p in self.params])

    def create_cc(self, arch: Arch) -> Optional[SimCC]:
        if not isinstance(arch, ArchX86):
            # Use default calling convention unless arch is x86
            return None
        if self.cc_str in {
            "__stdcall",
            "__fastcall",
            "__thiscall",
            "__vectorcall",
            "X86StdCall",
        }:
            # Callee cleanup
            return SimCCStdcall(arch)
        return None

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Optional

import angr
import claripy
from angr import SimCC
from angr.procedures.stubs.ReturnUnconstrained import ReturnUnconstrained

if TYPE_CHECKING:
    from forsee.techniques.procedure_handler.procedure_handler import ExportManager

log = logging.getLogger(__name__)


class ReturnUnconstrainedLog(ReturnUnconstrained):
    def run(self, *args, **kwargs):
        log.warning(f"No SimProcedure for {self.display_name}. Returning unconstrained")
        ret_val = super().run(*args, **kwargs)
        return ret_val


class LoadLibraryA(angr.SimProcedure):
    def run(self, lib_ptr):
        lib = self.state.mem[lib_ptr].string.concrete.decode("utf-8")
        log.debug(f'LoadLibraryA called with pointer to "{lib}"')
        return self.state.solver.Unconstrained("load_library", self.state.arch.bits)


class LoadLibraryW(angr.SimProcedure):
    def run(self, lib_ptr):
        lib = self.state.mem[lib_ptr].wstring.concrete
        log.debug(f'LoadLibraryW called with pointer to "{lib}"')
        return self.state.solver.Unconstrained("load_library", self.state.arch.bits)


class LoadLibraryExA(angr.SimProcedure):
    def run(self, lib_ptr, hFile, dwFlags):
        lib = self.state.mem[lib_ptr].string.concrete.decode("utf-8")
        log.debug(f'LoadLibraryExA called with pointer to "{lib}"')
        return self.state.solver.Unconstrained("load_library", self.state.arch.bits)


class LoadLibraryExW(angr.SimProcedure):
    def run(self, lib_ptr, hFile, dwFlags):
        lib = self.state.mem[lib_ptr].wstring.concrete
        log.debug(f'LoadLibraryExW called with pointer to "{lib}"')
        return self.state.solver.Unconstrained("load_library", self.state.arch.bits)


class GetProcAddress(angr.SimProcedure):
    def __init__(
        self, project: angr.Project, exports: ExportManager, cc: Optional[SimCC] = None
    ):
        super().__init__(project, cc=cc)
        self.exports = exports

    def run(self, lib_handle, name_addr):
        if claripy.is_true(name_addr < 0x10000):
            # this matches the bogus name specified in the loader...
            ordinal = self.state.solver.eval(name_addr)
            log.warning(
                f"GetProcAddress called for ordinal {ordinal}. Ordinals are not supported."
            )
            return 0  # TODO: Handle ordinals

        name = self.state.mem[name_addr].string.concrete.decode("utf-8")
        log.debug(f'GetProcAddress called with pointer to "{name}"')
        addr = self.exports.name_to_addr(name, create_addr=True)
        return addr


custom_dynamic_procedures = {
    "LoadLibraryA": LoadLibraryA,
    "LoadLibraryW": LoadLibraryW,
    "LoadLibraryExA": LoadLibraryExA,
    "LoadLibraryExW": LoadLibraryExW,
    "GetProcAddress": GetProcAddress,
}

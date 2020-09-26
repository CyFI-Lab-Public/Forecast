import logging
from collections import defaultdict

import angr
import archinfo
from angr.errors import SimUnsatError

from .extract_string import get_string_a, get_string_w
from .plugin_base import PluginBase

log = logging.getLogger(__name__)


class Dropper(PluginBase):
    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def _analyze(self, state: angr.SimState, lpApplicationName, proc_name):
        for created_file in state.globals["dropper"]["CreateFile"]:
            lpFileName = created_file["lpFileName"]
            ret_val = created_file["return"]

            # Check CreateProcess
            if not state.solver.is_true(lpFileName == lpApplicationName):
                continue

            # Check WriteFile
            for written_file in state.globals["dropper"]["WriteFile"]:
                if state.solver.is_true(written_file["hFile"] == ret_val):
                    break
            else:
                continue

            # Check SetFileAttributes
            for set_file_attr in state.globals["dropper"]["SetFileAttributes"]:
                if state.solver.is_true(set_file_attr["lpFileName"] == lpFileName):
                    break
            else:
                continue

            log.info(
                f'Detected Dropper (created process from file "{proc_name}") with DoC {state.doc.concreteness:.2f}'
            )

    def simprocedure(self, state: angr.SimState):
        # Init globals
        if "dropper" not in state.globals:
            state.globals["dropper"] = defaultdict(list)

        # Handle procedure
        proc = state.inspect.simprocedure
        if proc is None:
            # Handle syscall SimProcedures
            log.debug("Reached a syscall SimProcedure")
            return
        proc_name = proc.display_name

        if proc_name == "CreateFileA" or proc_name == "CreateFileW":
            data = {
                "lpFileName": proc.arg(0),
                "return": state.inspect.simprocedure_result,
            }
            state.globals["dropper"]["CreateFile"].append(data)

        elif proc_name == "WriteFile":
            data = {
                "hFile": proc.arg(0),
            }
            state.globals["dropper"]["WriteFile"].append(data)

        elif proc_name == "SetFileAttributesA" or proc_name == "SetFileAttributesW":
            data = {
                "lpFileName": proc.arg(0),
            }
            state.globals["dropper"]["SetFileAttributes"].append(data)

        elif proc_name == "CreateProcessA" or proc_name == "CreateProcessW":
            # Final function in sequence
            created_proc_pointer = proc.arg(0)
            if proc_name == "CreateProcessA":
                try:
                    created_proc = get_string_a(state, created_proc_pointer)
                except SimUnsatError:
                    created_proc = None
            else:
                try:
                    created_proc = get_string_w(state, created_proc_pointer)
                except SimUnsatError:
                    created_proc = None
            self._analyze(state, proc.arg(0), created_proc)

    def __repr__(self):
        return "<DropperDetectionPlugin>"

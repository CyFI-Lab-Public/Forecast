import logging
from collections import defaultdict

import angr
import archinfo

from .plugin_base import PluginBase

log = logging.getLogger(__name__)


class Persistence(PluginBase):
    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def _analyze(self, state: angr.SimState, hKey):
        # Check RegCreateKeyEx
        for created_key in state.globals["persistence"]["RegCreateKeyEx"]:
            if state.solver.is_true(created_key["phkResult"] == hKey.args[0]):
                log.info(f"Detected Persistence with DoC {state.doc.concreteness:.2f}")
                return

        # Check SetFileAttributesA
        for opened_key in state.globals["persistence"]["RegOpenKeyEx"]:
            if state.solver.is_true(opened_key["phkResult"] == hKey.args[0]):
                log.info(f"Detected Persistence with DoC {state.doc.concreteness:.2f}")
                return

    def simprocedure(self, state: angr.SimState):
        # Init globals
        if "persistence" not in state.globals:
            state.globals["persistence"] = defaultdict(list)

        # Handle procedure
        proc = state.inspect.simprocedure
        if proc is None:
            # Handle syscall SimProcedures
            log.debug("Reached a syscall SimProcedure")
            return
        proc_name = proc.display_name

        if proc_name == "RegCreateKeyExA" or proc_name == "RegCreateKeyExW":
            data = {
                "phkResult": state.memory.load(
                    proc.arg(7), disable_actions=True, inspect=False
                ),
            }
            state.globals["persistence"]["RegCreateKeyEx"].append(data)

        elif proc_name == "RegOpenKeyExA" or proc_name == "RegOpenKeyExW":
            data = {
                "phkResult": state.memory.load(
                    proc.arg(4), disable_actions=True, inspect=False
                ),
            }
            state.globals["persistence"]["RegOpenKeyEx"].append(data)

        elif proc_name == "RegSetValueExA" or proc_name == "RegSetValueExW":
            # Final function in sequence
            self._analyze(state, proc.arg(0))

    def __repr__(self):
        return "<PersistenceDetectionPlugin>"

import logging
from collections import defaultdict

import angr
import archinfo

from .plugin_base import PluginBase

log = logging.getLogger(__name__)
from forsee.techniques.procedure_handler.function_detected import FunctionList

class KeySpying(PluginBase):
    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def _analyze(self, state: angr.SimState, hWindow):
        # Check RegisterHotKey
        registered_hot_key = False
        for hWnd in state.globals["key_spying"]["RegisterHotKey"]:
            if state.solver.is_true(hWnd == hWindow):
                registered_hot_key = True

        if not registered_hot_key:
            return
        # Check SetWindowHookEx
        for id_hook in state.globals["key_spying"]["SetWindowsHookEx"]:
            if state.solver.satisfiable(extra_constraints=(id_hook == 2,)):
                log.info(f"Detected Key Spying with DoC {state.doc.concreteness:.2f}")
                return

    def saySomething(self, proc_name: str, state: angr.SimState):
        proc = state.inspect.simprocedure
        if proc_name == "RegisterHotKey":
            state.globals["key_spying"]["RegisterHotKey"].append(proc.arg(0))

        elif proc_name == "SetWindowsHookExA" or proc_name == "SetWindowsHookExW":
            state.globals["key_spying"]["SetWindowsHookEx"].append(proc.arg(0))

        elif proc_name == "GetMessageA" or proc_name == "GetMessageW":
            # Final function in sequence
            self._analyze(state, proc.arg(1))

    def simprocedure(self, state: angr.SimState):
        # Init globals
        if "key_spying" not in state.globals:
            state.globals["key_spying"] = defaultdict(list)

        # Handle procedure
        proc = state.inspect.simprocedure
        if proc is None:
            # Handle syscall SimProcedures
            log.debug("Reached a syscall SimProcedure")
            return
        proc_name = proc.display_name
        self.saySomething(proc_name, state)
        for function, typ in FunctionList.dic.items():
            self.saySomething(typ, state)

    def __repr__(self):
        return "<KeySpyingPlugin>"

import logging
from collections import defaultdict

import angr
import archinfo
from angr.errors import SimUnsatError

from .extract_string import get_string_a, get_string_w
from .plugin_base import PluginBase

log = logging.getLogger(__name__)
from forsee.techniques.procedure_handler.function_detected import FunctionList

class CodeInjectionDetection(PluginBase):
    """
    This analysis monitors for calls to functions that are commonly used to hollow processes and inject code
    """

    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("Code Injection plugin initialized")
        self.functions_monitored = [
            "OpenProcess",
            "CreateProcessW",
            "CreateProcessA",
            "CreateRemoteThread",
            "WriteProcessMemory",
        ]

    def _analyze(self, state: angr.SimState):
        for process in state.globals["code_injection"]["WriteProcessMemory"]:
            hProcess = process["hProcess"]

            for OpenedProcess in state.globals["code_injection"]["OpenProcess"]:
                if state.solver.is_true(hProcess == OpenedProcess["oHandle"]):
                    log.info(
                        f"Detected Code Injection with DoC {state.doc.concreteness:2f}"
                    )
                    continue
            for CreatedProcess in state.globals["code_injection"]["CreateProcess"]:
                if state.solver.is_true(
                    hProcess.args[0].args[2]
                    == CreatedProcess["lpProcessInformation"].args[2]
                ):
                    log.info(
                        f"Detected Code Injection (in created process {CreatedProcess['process']}) "
                        f"with DoC {state.doc.concreteness:2f}"
                    )
                    continue

            for RemoteThread in state.globals["code_injection"]["CreateRemoteThread"]:
                if state.solver.is_true(hProcess == RemoteThread["hProcess"]):
                    log.info(
                        f"Detected Code Injection with DoC {state.doc.concreteness:2f}"
                    )
                    continue

    def simprocedure(self, state: angr.SimState):
        """
        Tracks all SimProcedure calls and checks if it is calling a monitored function
        """

        proc = state.inspect.simprocedure
        if proc is None:
            # Handle syscall SimProcedures
            log.debug("Reached a syscall SimProcedure")
            return
        proc_name = proc.display_name
        self.saySomething(proc_name, state)
        for function, typ in FunctionList.dic.items():
            self.saySomething(typ,state)

    def saySomething(self, proc_name: str, state:angr.SimState):
        proc = state.inspect.simprocedure
        if proc_name not in self.functions_monitored:
            return

        if "code_injection" not in state.globals:
            state.globals["code_injection"] = defaultdict(list)

        if proc_name == "OpenProcess":
            data = {"oHandle": state.inspect.simprocedure_result}
            state.globals["code_injection"]["OpenProcess"].append(data)
        elif proc_name == "CreateProcessA" or proc_name == "CreateProcessW":
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
            data = {
                "process": created_proc,
                "lpProcessInformation": state.memory.load(
                    proc.arg(9), 4, disable_actions=True, inspect=False
                ),
            }
            state.globals["code_injection"]["CreateProcess"].append(data)
        elif proc_name == "CreateRemoteThread":
            data = {"hProcess": proc.arg(0)}
            state.globals["code_injection"]["CreateRemoteThread"].append(data)
        elif proc_name == "WriteProcessMemory":
            data = {"hProcess": proc.arg(0)}
            state.globals["code_injection"]["WriteProcessMemory"].append(data)
            self._analyze(state)

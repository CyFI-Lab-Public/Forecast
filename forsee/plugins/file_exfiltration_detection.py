import logging
from collections import defaultdict

import angr
import archinfo

from .plugin_base import PluginBase

log = logging.getLogger(__name__)
from forsee.techniques.procedure_handler.function_detected import FunctionList

class FileExfiltrationDetection(PluginBase):
    """
    This analysis monitors for calls to functions that are commonly used to exfiltrate files
    """

    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("FileExfiltration plugin initialized")
        self.functions_monitored = [
            "OpenFile",
            "ReadFile",
            "Send",
        ]

    def _analyze(self, state: angr.SimState):
        for read_file in state.globals["file_exfiltration"]["ReadFile"]:
            lpBytesRead = read_file["lpBytesRead"]

            for send in state.globals["file_exfiltration"]["Send"]:
                if state.solver.is_true(send["buf"] == lpBytesRead):
                    break
            else:
                continue

            log.info(
                f"Detected File Exfiltration with DoC {state.doc.concreteness:.2f}"
            )

    def saySomething(self, proc_name: str, state: angr.SimState):
        proc = state.inspect.simprocedure
        if proc_name not in self.functions_monitored:
            return

        if "file_exfiltration" not in state.globals:
            state.globals["file_exfiltration"] = defaultdict(list)

        if proc_name == "OpenFile":
            data = {"return": state.inspect.simprocedure_result}
            state.globals["file_exfiltration"]["OpenFile"].append(data)
        elif proc_name == "ReadFile":
            data = {
                "lpBytesRead": state.memory.load(
                    proc.arg(3), disable_actions=True, inspect=False
                )
            }
            state.globals["file_exfiltration"]["ReadFile"].append(data)
        elif proc_name == "Send":
            data = {
                "buf": state.memory.load(
                    proc.arg(1), disable_actions=True, inspect=False
                )
            }
            state.globals["file_exfiltration"]["Send"].append(data)
            self._analyze(state)

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
            self.saySomething(typ, state)

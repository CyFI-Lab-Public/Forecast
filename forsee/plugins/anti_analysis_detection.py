import logging

import angr
import archinfo
from angr import SimEngineError

from .plugin_base import PluginBase

log = logging.getLogger(__name__)
from forsee.techniques.procedure_handler.function_detected import FunctionList

class AntiAnalysisDetection(PluginBase):
    """
    This analysis monitors for calls to functions that are commonly used to detect debuggers or virtual machines.
    """

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("AntiAnalysis plugin initialized")
        self.functions_monitored = [
            "OutputDebugStringA",
            "OutputDebugStringW",
            "IsDebuggerPresent",
            "CheckRemoteDebuggerPresent",
            "CreateToolhelp32Snapshot",
            "EnumProcesses",
        ]

    def stepped(self, simgr: angr.SimulationManager):
        """
        Track execution of cpuid instructions on x86 and x86-64
        """
        if type(self.proj.arch) not in frozenset(
            [archinfo.ArchAMD64, archinfo.ArchX86]
        ):
            return
        for state in simgr.active:
            try:
                cs = self.proj.factory.block(state.addr).capstone
                cpuid_count = len(
                    [ins for ins in cs.insns if ins.insn_name() == "cpuid"]
                )
                if cpuid_count > 0:
                    log.info(f"CPUID instruction called in block {state.addr}")
            except SimEngineError:
                pass

    def saySomething(self, proc_name: str, state: angr.SimState):
        if proc_name in self.functions_monitored:
            log.info(
                f"Detected possible debugger detection."
                f" Called function: {state.inspect.simprocedure.display_name}"
            )

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

    def __repr__(self):
        return "<AntiAnalysisPlugin>"

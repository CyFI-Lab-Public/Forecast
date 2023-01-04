import logging

import angr
import archinfo

from .plugin_base import PluginBase

log = logging.getLogger(__name__)


class CCDomainDetection(PluginBase):
    """
    This analysis monitors for calls to functions that are commonly used to communicate with Command and Control Severs
    """

    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("C&C Domain plugin initialized")
        self.functions_monitored = [
            "socket",
            "InternetUrlOpenA",
            "Open",
        ]

    def saySomething(self, proc_name: str, state: angr.SimState):
        proc = state.inspect.simprocedure
        if proc_name not in self.functions_monitored:
            return

        if proc_name == "socket":
            log.info(
                f"Detected possible C&C Domain: {proc.arg(0)} with DoC {state.doc.concreteness:.2f}"
            )

        if proc_name == "InternetOpenUrlA":
            log.info(
                f"Detected possible C&C Domain: {proc.arg(1)} with DoC {state.doc.concreteness:.2f}"
            )

        if proc_name == "Open":
            if proc.library_name == "IWinHttpRequest":
                log.info(
                    f"Detected possible C&C Domain: {proc.arg(1)} with DoC {state.doc.concreteness:.2f}"
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

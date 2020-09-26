import logging

import angr
import archinfo
from angr import SimValueError

from .plugin_base import PluginBase

log = logging.getLogger(__name__)


class CallAnalysis(PluginBase):
    """
    This analysis monitors all function calls
    """

    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("CallAnalysis plugin initialized")

    def call(self, state: angr.SimState):
        """
        Track all calls and get the description of the call address provided by cle
        """
        call_addr_bv = state.inspect.function_address
        try:
            call_addr_int = state.solver.eval_one(call_addr_bv)
            call_name = self.proj.loader.describe_addr(call_addr_int)
        except SimValueError:
            call_name = f"unsat address {call_addr_bv}"
        log.info(f"Called {call_name}")
        state.globals["next_return"] = state.callstack.current_return_target

    def _return(self, state: angr.SimState):
        log.info(f"Returning to {self.proj.loader.describe_addr(state.addr)}")
        if "next_return" in state.globals:
            if (
                state.globals["next_return"]
                and state.globals["next_return"] != state.addr
            ):
                log.error(f"Stack backtrace violation")
        state.globals["next_return"] = state.callstack.current_return_target

    def __repr__(self):
        return "<CallAnalysisPlugin>"

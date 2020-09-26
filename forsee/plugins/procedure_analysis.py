import inspect
import logging

import angr
import archinfo

from .plugin_base import PluginBase

log = logging.getLogger(__name__)


class ProcedureAnalysis(PluginBase):
    """
    This analysis monitors all SimProcedure calls
    """

    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("ProcedureAnalysis plugin initialized")

    def simprocedure(self, state: angr.SimState):
        """
        Tracks all SimProcedure calls and gets the variable type and value
        """

        proc = state.inspect.simprocedure
        if proc is None:
            # Handle syscall SimProcedures
            log.info("Reached a syscall SimProcedure")
            return
        log.info(f"Reached SimProcedure {proc}")
        arg_spec = inspect.getfullargspec(proc.run)
        for num in range(proc.num_args):
            arg = proc.arg(num)
            try:
                arg_name = arg_spec[0][1 + num]
            except IndexError:
                arg_name = str(num)
            log.info(f"   {arg_name}: {arg}")
        log.info(f"   Returned: {state.inspect.simprocedure_result}")

    def __repr__(self):
        return "<ProcedureAnalysisPlugin>"

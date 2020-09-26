import logging

import angr
import archinfo

from .plugin_base import PluginBase

log = logging.getLogger(__name__)


class FlagFinder(PluginBase):
    """
    This analysis monitors all calls to find the "You win!\n" argument
    """

    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("FlagFinder plugin initialized")

    def call(self, state: angr.SimState):
        cc = state.project.factory.cc()
        arg = cc.arg(state, 0)
        if not arg.concrete:
            return
        if arg not in state.memory:
            return
        mem = state.memory.load(arg, 10, disable_actions=True, inspect=False)
        if not mem.concrete:
            return
        mem_val = state.solver.eval(mem)
        if mem_val == 0x596F752077696E210A00:
            state.globals["flag"] = state.doc.concreteness
            log.critical(f"Found flag with doc: {state.doc.concreteness}")

    def __repr__(self):
        return "<FlagFinderPlugin>"

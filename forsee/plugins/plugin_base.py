from typing import List

import angr
import archinfo
from archinfo import Arch

ALL_ARCH = [arch_info[3] for arch_info in archinfo.arch_id_map]
CAPSTONE_ARCH = [
    arch_info[3]
    for arch_info in archinfo.arch_id_map
    if arch_info[3]().capstone_support
]


class PluginBase:
    """
    Base class for plugins. Each plugin should override any breakpoints it would like
    to register callbacks for.
    """

    # List of architectures supported by plugin
    supported_arch: List[Arch] = ALL_ARCH

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        self.proj = proj
        self.simgr = simgr

    # Exploration callbacks
    def stepped(self, simgr: angr.SimulationManager):
        pass

    def complete(self, simgr: angr.SimulationManager):
        pass

    # Breakpoint callbacks
    def mem_read(self, state: angr.SimState):
        pass

    def mem_write(self, state: angr.SimState):
        pass

    def address_concretization(self, state: angr.SimState):
        pass

    def reg_read(self, state: angr.SimState):
        pass

    def reg_write(self, state: angr.SimState):
        pass

    def tmp_read(self, state: angr.SimState):
        pass

    def tmp_write(self, state: angr.SimState):
        pass

    def expr(self, state: angr.SimState):
        pass

    def statement(self, state: angr.SimState):
        pass

    def instruction(self, state: angr.SimState):
        pass

    def irsb(self, state: angr.SimState):
        pass

    def constraints(self, state: angr.SimState):
        pass

    def exit(self, state: angr.SimState):
        pass

    def fork(self, state: angr.SimState):
        pass

    def symbolic_variable(self, state: angr.SimState):
        pass

    def call(self, state: angr.SimState):
        pass

    def _return(self, state: angr.SimState):
        pass

    def simprocedure(self, state: angr.SimState):
        pass

    def dirty_after(self, state: angr.SimState):
        pass

    def dirty_before(self, state: angr.SimState):
        pass

    def syscall(self, state: angr.SimState):
        pass

    def engine_process(self, state: angr.SimState):
        pass

    # Help functions
    def _forcast_probability(self, state: angr.SimState):
        path_doc = state.doc.concreteness
        active_doc = 0
        for st in self.simgr.active:
            active_doc += st.doc.concreteness
        return path_doc * 100 / active_doc

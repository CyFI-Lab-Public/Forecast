import logging

import angr
from angr import SimEngineError

from .plugin_base import CAPSTONE_ARCH, PluginBase

log = logging.getLogger(__name__)


class Disassembly(PluginBase):
    """
    Prints the disassembly of every active state
    """

    supported_arch = CAPSTONE_ARCH

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("Disassembly plugin initialized")

    def stepped(self, simgr: angr.SimulationManager):
        for state in simgr.active:
            try:
                block = self.proj.factory.block(state.addr)
                log.debug(f"Printing disassembly for 0x{state.addr:x}")
                block.capstone.pp()
            except SimEngineError:
                log.debug(f"Could not print disassembly for 0x{state.addr:x}")

    def __repr__(self):
        return "<DisassemblyPlugin>"

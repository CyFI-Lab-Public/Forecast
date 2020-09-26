import logging
from collections import defaultdict

import angr
import archinfo

from .plugin_base import PluginBase

log = logging.getLogger(__name__)


class ScreenSpying(PluginBase):
    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)

    def _analyze(self, state: angr.SimState, hdc):
        for hdc_ret in state.globals["screen_spying"]["GetDC"]:
            if state.solver.is_true(hdc_ret == hdc):
                log.info(
                    f"Detected Screen Spying with DoC {state.doc.concreteness:.2f}"
                )
                return

        for hdc_ret in state.globals["screen_spying"]["GetWindowDC"]:
            if state.solver.is_true(hdc_ret == hdc):
                log.info(
                    f"Detected Screen Spying with DoC {state.doc.concreteness:.2f}"
                )
                return

    def simprocedure(self, state: angr.SimState):
        # Init globals
        if "screen_spying" not in state.globals:
            state.globals["screen_spying"] = defaultdict(list)

        # Handle procedure
        proc = state.inspect.simprocedure
        if proc is None:
            # Handle syscall SimProcedures
            log.debug("Reached a syscall SimProcedure")
            return
        proc_name = proc.display_name

        if proc_name == "GetDC":
            return_value = state.inspect.simprocedure_result
            state.globals["screen_spying"]["GetDC"].append(return_value)

        elif proc_name == "GetWindowDC":
            return_value = state.inspect.simprocedure_result
            state.globals["screen_spying"]["GetWindowDC"].append(return_value)

        elif proc_name == "CreateCompatibleBitmap":
            # Final function in sequence
            self._analyze(state, proc.arg(0))

    def __repr__(self):
        return "<ScreenSpyingPlugin>"

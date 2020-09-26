import logging
from typing import Optional

import angr

from forsee.techniques import DegreeOfConcreteness, LoopLimiter, ProcedureHandler

from .forsee_project import ForseeProject

log = logging.getLogger(__name__)


class ForseeProjectMinidump(ForseeProject):
    """
    This class is the base class for projects that use Windows minidumps
    """

    def __init__(
        self,
        memory_dump_path: str,
        max_states: int = 50,
        func_models_path: Optional[str] = None,
        loop_bound: Optional[int] = 20,
        return_unconstrained=True,
        optional_args=None
    ):
        self.func_models_path = func_models_path
        # Load minidump
        log.info(f"Loading minidump: {memory_dump_path}")
        self.angr_project = None
        if optional_args == None:
            self.angr_project = angr.Project(memory_dump_path)
        else:
            self.angr_project = angr.Project(memory_dump_path, main_opts=optional_args)
        self.max_states = max_states
        sections = self.angr_project.loader.main_object.sections
        self.main_object = sections[0].vaddr
        self.loaded_libraries = [
            sect.vaddr for sect in sections if sect.vaddr != self.main_object
        ]
        self._resolve_functions()

        # Create initial state
        opts = angr.sim_options.refs | angr.sim_options.resilience
        self.initial_state = self.angr_project.factory.blank_state(add_options=opts)

        proc_handler = ProcedureHandler(
            self._imports,
            self._exports,
            self.angr_project,
            self.func_models_path,
            return_unconstrained=return_unconstrained,
        )
        doc = DegreeOfConcreteness(self.initial_state, self.max_states)
        self._techniques = [proc_handler, doc]
        if loop_bound:
            ll = LoopLimiter(loop_bound)
            self._techniques.append(ll)

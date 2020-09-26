import logging
from typing import Optional

import angr

from ..techniques import DegreeOfConcreteness, LoopLimiter
from .forsee_project import ForseeProject

log = logging.getLogger(__name__)


class ForseeProjectBinary(ForseeProject):
    """
    Want to explore a boring, normal binary with Forsee? Then use this class.
    """

    def __init__(
        self,
        binary_path: str,
        use_entry_state: bool = False,
        max_states: int = 50,
        func_models_path: Optional[str] = None,
        loop_bound: Optional[int] = 20,
    ):
        self.func_models_path = func_models_path
        # Load minidump
        log.info(f"Loading binary: {binary_path}")
        self.angr_project = angr.Project(binary_path)
        self.max_states = max_states

        # Create initial state
        opts = angr.sim_options.refs | angr.sim_options.resilience
        if use_entry_state:
            self.initial_state = self.angr_project.factory.entry_state(add_options=opts)
        else:
            self.initial_state = self.angr_project.factory.blank_state(add_options=opts)

        # Use DoC technique
        doc = DegreeOfConcreteness(self.initial_state, self.max_states)
        self._techniques = [doc]
        if loop_bound:
            ll = LoopLimiter(loop_bound)
            self._techniques.append(ll)

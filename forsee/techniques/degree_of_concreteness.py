import logging

import angr
from angr import ExplorationTechnique, SimState, SimulationManager
from pyvex.stmt import IMark

log = logging.getLogger(__name__)


class DocPlugin(angr.SimStatePlugin):
    def __init__(self, cumul_ratio: int = 0, block_count: int = 0):
        super(DocPlugin, self).__init__()
        self.cumul_ratio = cumul_ratio
        self.block_count = block_count

    @property
    def concreteness(self) -> float:
        if self.block_count == 0:
            return 1.0
        return 1 - (self.cumul_ratio / self.block_count)

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return DocPlugin(self.cumul_ratio, self.block_count)

    def merge(self, others, merge_conditions, common_ancestor=None):
        other_cumul_ratio = min([other.cumul_ratio for other in others])
        self.cumul_ratio = min(other_cumul_ratio, self.cumul_ratio)
        other_block_count = max([other.block_count for other in others])
        self.block_count = max(other_block_count, self.block_count)


SimState.register_default("doc", DocPlugin)


class DegreeOfConcreteness(ExplorationTechnique):
    def __init__(self, initial_state: SimState, max_states: int = 50):
        super().__init__()
        if not all([(ref in initial_state.options) for ref in angr.sim_options.refs]):
            raise ValueError(
                "Degree of Concreteness requires initial_state to have options angr.sim_options.refs"
            )
        self.max_states = max_states
        self.states_to_prune = []

    def _calculate_doc(self, orig_addr: int, state: SimState):
        proj = state.project
        cumul_ratio = state.doc.cumul_ratio

        sym_stmts = [
            action.stmt_idx
            for action in state.history.recent_actions
            if action.is_symbolic
        ]

        sym_ops = 0
        all_ops = 0
        ins_symbolic = 0
        for i, stmt in enumerate(proj.factory.block(orig_addr).vex.statements):
            if isinstance(stmt, IMark):
                all_ops += 1
                sym_ops += ins_symbolic
                ins_symbolic = 0
            if i in sym_stmts:
                ins_symbolic = 1
        sym_ops += ins_symbolic

        ratio = sym_ops / all_ops
        cumul_ratio += ratio

        state.doc.block_count += 1
        state.doc.cumul_ratio = cumul_ratio
        log.debug(f"DOC: {state.doc.concreteness:.2f}, CumulRatio: {cumul_ratio:.2f}")

    def step_state(self, simgr: SimulationManager, state: SimState, **kwargs):
        """
        Step the state forward and calculate DoC
        """
        start_addr = state.addr
        stashes = simgr.step_state(state, **kwargs)
        if state.project.is_hooked(start_addr):
            log.debug(f"Address {hex(start_addr)} is hooked. Not analyzing DoC")
            return stashes
        try:
            flat_successors = stashes[None]
        except KeyError:
            log.warning("No flat successors found")
            return stashes
        for succ in flat_successors:
            self._calculate_doc(start_addr, succ)

        return stashes

    def _prune_low_doc(self, state: SimState) -> bool:
        """
        Filter state if too symbolic
        """
        return state.doc.block_count >= 10 and state.doc.concreteness < 0.10

    def _prune_max_states(self, state: SimState) -> bool:
        """
        Filter states with lowest DoC if too many states are in the active stash
        """
        return hash(state) in self.states_to_prune

    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs):
        """
        Step the stash forward and apply stash moving filter
        """
        simgr = simgr.step(stash, **kwargs)
        simgr.move("active", "doc_pruned", self._prune_low_doc)
        if len(simgr.active) > self.max_states:
            sorted_states = sorted(simgr.active, key=lambda s: s.doc.concreteness)
            num_to_prune = len(sorted_states) - self.max_states
            for st in sorted_states[:num_to_prune]:
                self.states_to_prune.append(hash(st))
            log.debug(f"Max number of states exceeded. Pruning {num_to_prune} states.")
            simgr.move("active", "doc_pruned", self._prune_max_states)
            self.states_to_prune = []
        return simgr

    def __repr__(self):
        return "<DegreeOfConcreteness>"

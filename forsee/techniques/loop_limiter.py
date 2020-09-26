import logging
from copy import deepcopy
from typing import Optional

import angr
from angr import Project, SimEngineError, SimState, SimulationManager
from networkx import DiGraph

log = logging.getLogger(__name__)


class HistoryNode:
    def __init__(self, addr: int, size: int):
        self.addr = addr
        self.size = size

    @property
    def end_addr(self) -> int:
        return self.addr + self.size - 1

    def __eq__(self, other):
        if not isinstance(other, HistoryNode):
            return False
        return self.addr == other.addr and self.size == other.size

    def __hash__(self):
        return hash(self.addr) ^ hash(self.size)

    def __repr__(self):
        return f"<HistoryNode Addr: {hex(self.addr)}, Size: {self.size}>"


class HistoryGraph(angr.SimStatePlugin):
    def __init__(
        self, graph: Optional[DiGraph] = None, last_node: Optional[int] = None
    ):
        super(HistoryGraph, self).__init__()
        self.graph = graph if graph else DiGraph()
        self.last_node = last_node

    @property
    def nodes(self):
        return self.graph.nodes

    @property
    def edges(self):
        return self.graph.edges

    def add_visit(self, addr: int, proj: Project):
        # TODO: Handle normalization
        try:
            block = proj.factory.block(addr)
        except SimEngineError:
            return
        node = HistoryNode(block.addr, block.size)

        if self.last_node:
            if (self.last_node, node) in self.graph.edges:
                self.graph[self.last_node][node]["count"] += 1
            else:
                self.graph.add_edge(self.last_node, node, count=1)
        else:
            self.graph.add_node(node)
        self.last_node = node

    @angr.SimStatePlugin.memo
    def copy(self, memo):
        return HistoryGraph(deepcopy(self.graph), self.last_node)


SimState.register_default("history_graph", HistoryGraph)


class LoopLimiter(angr.ExplorationTechnique):
    """
    Limit the number of transitions for each edge. Implementation could be much better
    """

    def __init__(self, loop_bound: int = 20):
        super().__init__()
        self.loop_bound = loop_bound

    def step_state(self, simgr: SimulationManager, state: SimState, **kwargs):
        """
        Step the state forward and add node and/or edge to graph
        """
        stashes = simgr.step_state(state, **kwargs)
        try:
            flat_successors = stashes[None]
        except KeyError:
            log.warning("No flat successors found")
            return stashes
        for succ in flat_successors:
            succ.history_graph.add_visit(succ.addr, succ.project)
        return stashes

    def _prune_loops(self, state: SimState):
        for _, _, data in state.history_graph.edges(data=True):
            if data["count"] > self.loop_bound:
                return True
        return False

    def step(self, simgr: SimulationManager, stash: str = "active", **kwargs):
        """
        Step the stash forward and apply stash moving filter
        """
        simgr = simgr.step(stash, **kwargs)
        simgr.move("active", "loop_pruned", self._prune_loops)
        return simgr

    def __repr__(self):
        return "<LoopLimiter>"

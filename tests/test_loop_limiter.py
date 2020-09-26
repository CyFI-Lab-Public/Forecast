from pathlib import Path

import angr

from forsee.techniques.loop_limiter import HistoryNode, LoopLimiter


class TestHistoryGraph:
    def test_history_normalize(self):
        # Assumes no normalization
        test_file = Path(__file__).parent / "programs/simple_loop"
        proj = angr.Project(str(test_file.resolve()), auto_load_libs=False)
        state = proj.factory.entry_state()
        nodes = [
            HistoryNode(0x40064A, 24),
            HistoryNode(0x40066E, 6),
            HistoryNode(0x400662, 18),
            HistoryNode(0x400674, 22),
            HistoryNode(0x40068A, 7),
        ]

        assert len(state.history_graph.nodes()) == 0
        assert state.history_graph.last_node is None

        state.history_graph.add_visit(0x40064A, proj)
        assert list(state.history_graph.nodes) == [nodes[0]]
        assert len(state.history_graph.edges()) == 0

        state.history_graph.add_visit(0x40066E, proj)
        assert list(state.history_graph.nodes) == [nodes[0], nodes[1]]
        assert len(state.history_graph.edges()) == 1
        assert (nodes[0], nodes[1], {"count": 1}) in state.history_graph.edges(
            data=True
        )

        state.history_graph.add_visit(0x400662, proj)
        assert list(state.history_graph.nodes) == [nodes[0], nodes[1], nodes[2]]
        assert len(state.history_graph.edges()) == 2
        assert (nodes[0], nodes[1], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[1], nodes[2], {"count": 1}) in state.history_graph.edges(
            data=True
        )

        state.history_graph.add_visit(0x400662, proj)
        assert list(state.history_graph.nodes) == [nodes[0], nodes[1], nodes[2]]
        assert len(state.history_graph.edges()) == 3
        assert (nodes[0], nodes[1], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[1], nodes[2], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[2], nodes[2], {"count": 1}) in state.history_graph.edges(
            data=True
        )

        state.history_graph.add_visit(0x400662, proj)
        assert list(state.history_graph.nodes) == [nodes[0], nodes[1], nodes[2]]
        assert len(state.history_graph.edges()) == 3
        assert (nodes[0], nodes[1], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[1], nodes[2], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[2], nodes[2], {"count": 2}) in state.history_graph.edges(
            data=True
        )

        state.history_graph.add_visit(0x400662, proj)
        assert list(state.history_graph.nodes) == [nodes[0], nodes[1], nodes[2]]
        assert len(state.history_graph.edges()) == 3
        assert (nodes[0], nodes[1], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[1], nodes[2], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[2], nodes[2], {"count": 3}) in state.history_graph.edges(
            data=True
        )

        state.history_graph.add_visit(0x400674, proj)
        assert list(state.history_graph.nodes) == [
            nodes[0],
            nodes[1],
            nodes[2],
            nodes[3],
        ]
        assert len(state.history_graph.edges()) == 4
        assert (nodes[0], nodes[1], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[1], nodes[2], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[2], nodes[2], {"count": 3}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[2], nodes[3], {"count": 1}) in state.history_graph.edges(
            data=True
        )

        state.history_graph.add_visit(0x40068A, proj)
        assert list(state.history_graph.nodes) == [
            nodes[0],
            nodes[1],
            nodes[2],
            nodes[3],
            nodes[4],
        ]
        assert len(state.history_graph.edges()) == 5
        assert (nodes[0], nodes[1], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[1], nodes[2], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[2], nodes[2], {"count": 3}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[2], nodes[3], {"count": 1}) in state.history_graph.edges(
            data=True
        )
        assert (nodes[3], nodes[4], {"count": 1}) in state.history_graph.edges(
            data=True
        )


class TestLoopLimiter:
    def test_under_limit(self):
        test_file = Path(__file__).parent / "programs/simple_loop"
        proj = angr.Project(str(test_file.resolve()))
        state = proj.factory.call_state(0x40064A)
        simgr = proj.factory.simgr(state)
        limiter = LoopLimiter(loop_bound=10)
        simgr.use_technique(limiter)
        simgr.run(n=20)
        assert len(simgr.deadended) == 1
        for name, states in simgr.stashes.items():
            if name == "deadended":
                continue
            assert len(states) == 0

    def test_over_limit(self):
        # Assumes no normalization
        test_file = Path(__file__).parent / "programs/simple_loop"
        proj = angr.Project(str(test_file.resolve()))
        state = proj.factory.call_state(0x40064A)
        simgr = proj.factory.simgr(state)
        # Bound is 8 due to lack or normalization handling
        limiter = LoopLimiter(loop_bound=8)
        simgr.use_technique(limiter)
        simgr.run(n=20)
        assert len(simgr.loop_pruned) == 1
        for name, states in simgr.stashes.items():
            if name == "loop_pruned":
                continue
            assert len(states) == 0

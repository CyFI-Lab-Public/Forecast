import logging
import sys
import time

from claripy.ast.base import simplify

import forsee
from forsee.explorer import Explorer
from forsee.project import ForseeProjectMinidump


def main():
    logging.getLogger(forsee.__name__).setLevel(logging.DEBUG)
    if len(sys.argv) != 3:
        raise ValueError(
            "Usage: python run_single_obfuscation_eval.py input_dump num_steps"
        )
    file = sys.argv[1]
    start_time = time.time()
    proj = ForseeProjectMinidump(str(file), max_states=10)

    # Symbolize argument
    esp = proj.initial_state.regs.esp
    argv = proj.initial_state.mem[esp + 8].int.concrete
    argv_1_ptr = proj.initial_state.mem[argv + 4].int.concrete
    sym_argv = proj.initial_state.solver.Unconstrained("sym_argv1", 14 * 8)
    proj.initial_state.memory.store(argv_1_ptr, sym_argv)

    explorer = Explorer(proj)
    explorer.run(int(sys.argv[2]))
    end_time = time.time()
    print(explorer.simgr)
    simgr = explorer.simgr
    results = {"name": file, "stashes": [], "time": end_time - start_time}
    for stash_name, stash_contents in simgr.stashes.items():
        if len(stash_contents) == 0:
            continue
        stash_results = {"stash": stash_name, "states": []}
        for state in stash_contents:
            if "flag" in state.globals:
                flag = state.globals["flag"]
            else:
                flag = None
            state_results = {
                "doc": state.doc.concreteness,
                "num_constraints": len(state.solver.constraints),
                "constraints": [],
                "steps": len(state.history.bbl_addrs),
                "flag_doc": flag,
            }
            for con in state.solver.constraints:
                simp_con = simplify(con)
                con_results = {
                    "leaves": len(list(simp_con.leaf_asts())),
                    "children": len(list(simp_con.children_asts())),
                }
                state_results["constraints"].append(con_results)
            stash_results["states"].append(state_results)
        results["stashes"].append(stash_results)
    print(results)


if __name__ == "__main__":
    main()

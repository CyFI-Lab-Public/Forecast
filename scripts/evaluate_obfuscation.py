import json
import sys
import time
from multiprocessing import Pool
from pathlib import Path

from claripy.ast.base import simplify

from forsee.explorer import Explorer
from forsee.project import ForseeProjectMinidump


def process_file(i, input, max_steps):
    print(i, input)
    start_time = time.time()
    proj = ForseeProjectMinidump(str(input), max_states=25)

    # Symbolize argument
    esp = proj.initial_state.regs.esp
    argv = proj.initial_state.mem[esp + 8].int.concrete
    argv_1_ptr = proj.initial_state.mem[argv + 4].int.concrete
    sym_argv = proj.initial_state.solver.Unconstrained("sym_argv1", 14 * 8)
    proj.initial_state.memory.store(argv_1_ptr, sym_argv)

    explorer = Explorer(proj)
    try:
        explorer.run(int(max_steps))
    except Exception as e:
        return json.dumps({"name": input.name, "error": str(e)}) + ","
    end_time = time.time()
    print(explorer.simgr)
    simgr = explorer.simgr
    results = {"name": input.name, "stashes": [], "time": end_time - start_time}
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
                    # "children": len(list(simp_con.children_asts())),
                }
                state_results["constraints"].append(con_results)
            stash_results["states"].append(state_results)
        results["stashes"].append(stash_results)
    json_output = json.dumps(results)
    return json_output + ","


def main():
    if len(sys.argv) != 4:
        raise ValueError(
            "Usage: python evaluate_obfuscation.py input_dir output.json num_steps"
        )
    eval_dir = Path(sys.argv[1])
    with open(sys.argv[2], "w") as jf:
        jf.write("[")

    worker_args = []
    for i, file in enumerate(eval_dir.iterdir()):
        single_arg = (i, file, sys.argv[3])
        worker_args.append(single_arg)

    results = ""

    with Pool(8) as p:
        it = p.starmap(process_file, worker_args)
        for result in it:
            results += result

    with open(sys.argv[2], "a") as jf:
        jf.write(results + "]")


if __name__ == "__main__":
    main()

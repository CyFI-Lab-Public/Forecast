import logging
from typing import Dict, Optional

import angr
from angr import ExplorationTechnique, SimProcedure, SimState, SimulationManager
from angr.calling_conventions import SimCCStdcall
from angr.procedures.definitions import SimSyscallLibrary
from archinfo import ArchX86
from simprocedures import ModelHandler
from simprocedures import procedures as cyfi_procedures

from forsee.techniques.procedure_handler.special_sim_procedures import (
    ReturnUnconstrainedLog,
    custom_dynamic_procedures,
)

log = logging.getLogger(__name__)


class ExportManager:
    def __init__(
        self,
        exports: Dict[int, str],
        proj: angr.Project,
        func_models_path: Optional[str] = None,
        return_unconstrained: bool = True,
    ):
        self._proj = proj
        self.addr_map: Dict[int, str] = {}
        self.name_map: Dict[str, int] = {}
        self.model_handler = None
        self.return_unconstrained = return_unconstrained
        if func_models_path:
            self.model_handler = ModelHandler(func_models_path)
        for addr, name in exports.items():
            self.addr_map[addr] = name
            self.name_map[name] = addr
            self._add_hook(name, addr)

    def _add_hook(self, name: str, addr: int):
        """
        Add hook for SimProcedure for name at addr
        """
        sim_proc = find_sim_procedure(name, self._proj, self, self.return_unconstrained)
        if sim_proc:
            self._proj.hook(addr, hook=sim_proc)

    def addr_to_name(self, addr: int) -> str:
        """
        Get name associated with address
        """
        return self.addr_map[addr]

    def name_to_addr(self, name: str, create_addr: bool = False) -> int:
        """
        Get address associated with name. If create_addr is True, the address will be created in
        the extern object if not in the export map.
        """
        if name in self.name_map:
            return self.name_map[name]
        if create_addr:
            new_addr = self._proj.loader.extern_object.allocate()
            self.addr_map[new_addr] = name
            self.name_map[name] = new_addr
            self._add_hook(name, new_addr)
            return new_addr
        raise KeyError()


def find_sim_procedure(
    name: str,
    proj: angr.Project,
    export_manager: ExportManager,
    return_unconstrained: bool = True,
) -> Optional[SimProcedure]:
    """
    Find the appropriate SimProcedure for the given procedure name and project
    """
    arch = proj.arch

    # Use custom dynamic procedures
    # TODO: Add linux dynamic loading functions
    if name in custom_dynamic_procedures:
        cc = None
        if isinstance(arch, ArchX86):
            cc = SimCCStdcall(arch)
        if name == "GetProcAddress":
            return custom_dynamic_procedures["GetProcAddress"](proj, export_manager, cc)
        return custom_dynamic_procedures[name](proj, cc=cc)

    blacklist = {
        "_error",
    }
    if name in blacklist:
        # Don't hook function
        return

    # Search in cyfi's SimProcedures
    for lib, procs in cyfi_procedures.items():
        #log.info(f"___________________________________________________________________________________")
        #log.debug(lib)
        if name in procs:
            sim_proc = procs[name](proj)
            #sim_proc = ReturnUnconstrainedLog(proj, display_name=name)
            log.log(20, f"Found {sim_proc} in {lib} (cyfi)")
            return sim_proc

    # Search in angr's SimProcedures
    # TODO: Optionally search a single library
    for lib in angr.SIM_LIBRARIES:
        sim_lib = angr.SIM_LIBRARIES[lib]
        if type(sim_lib) == SimSyscallLibrary:
            if sim_lib.has_implementation(name, arch):
                sim_proc = sim_lib.get(name, arch)
                log.log(20, f"Found {sim_proc} in {lib} (angr)")
                return sim_proc
        else:
            if sim_lib.has_implementation(name):
                sim_proc = sim_lib.get(name, arch)
                log.log(20, f"Found {sim_proc} in {lib} (angr)")
                return sim_proc

    # Search for function model
    if export_manager.model_handler:
        try:
            sim_proc = export_manager.model_handler.create_procedure(name, proj)
            log.log(20, f"Found {sim_proc} in models")
            return sim_proc
        except ValueError:
            pass

    if return_unconstrained:
        # Not found anywhere. Return unconstrained value.
        sim_proc = ReturnUnconstrainedLog(proj, display_name=name)
        return sim_proc

    return


class ProcedureHandler(ExplorationTechnique):
    def __init__(
        self,
        main_imports: Dict[int, str],
        library_exports: Dict[int, str],
        project: angr.Project,
        func_models_path: Optional[str] = None,
        return_unconstrained: bool = True,
    ):
        super().__init__()
        self._read_address = None
        self._read_value = None
        self._main_imports = main_imports
        self._proj = project
        self._exports = ExportManager(
            library_exports,
            self._proj,
            func_models_path,
            return_unconstrained=return_unconstrained,
        )

    def setup(self, simgr: SimulationManager):
        """
        Using the initial state, hook mem_read
        """
        init_state = simgr.active[0]
        init_state.inspect.b("mem_read", when=angr.BP_AFTER, action=self._mem_read)

    def _mem_read(self, state: SimState):
        self._read_address = state.inspect.mem_read_address
        self._read_value = state.inspect.mem_read_expr

    def _watch_got(self, state: SimState, stashes):
        """
        Watch all mem_reads to monitor reads to the GOT. If a read to the GOT occurs followed by a
        jump to that address, call the appropriate SimProcedure.
        """
        if self._read_address is None or self._read_value is None:
            log.log(20, "No reads or writes")
            return
        if self._read_address.symbolic or self._read_value.symbolic:
            log.log(20, "Symbolic read address or value")
            return
        # TODO: solver may not have correct constraints here
        read_addr_concrete = state.solver.eval_one(self._read_address)
        read_value_concrete = state.solver.eval_one(self._read_value)
        if read_addr_concrete not in self._main_imports:
            log.log(20, f"Read address {hex(read_addr_concrete)} not in functions")
            return

        flat_successors = stashes[None]
        for succ in flat_successors:
            if succ.addr == read_value_concrete:
                func_name = self._main_imports[read_addr_concrete]
                log.info(
                    f"Jumping to value at GOT address {hex(read_addr_concrete)} which "
                    f"points to {func_name}"
                )
                succ.regs.ip = self._exports.name_to_addr(func_name, create_addr=True)

    def step_state(self, simgr: SimulationManager, state: SimState, **kwargs):
        """
        Step the state forward and do SimProcedure magic
        """

        self._read_address = None
        self._read_value = None

        stashes = simgr.step_state(state, **kwargs)
        self._watch_got(state, stashes)

        return stashes

    def complete(self, simgr: SimulationManager) -> bool:
        return len(simgr.active) == 0

    def __repr__(self):
        return "<ProcedureHandler>"

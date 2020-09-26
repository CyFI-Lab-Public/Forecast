import logging
import os
from typing import Dict, List, Optional, Tuple

import angr
import archinfo

from forsee.techniques import DegreeOfConcreteness, LoopLimiter, ProcedureHandler

from .forsee_project import ForseeProject

log = logging.getLogger(__name__)


class ForseeProjectSegmented(ForseeProject):
    """
    This class is the base class for projects that use segmented memory dumps
    and a text file containing register values.
    """

    def __init__(
        self,
        memory_dump_path: str,
        reg_file_path: str,
        arch: str,
        max_states: int = 50,
        func_models_path: Optional[str] = None,
        loop_bound: Optional[int] = 20,
        return_unconstrained: bool = True,
    ):
        self.func_models_path = func_models_path
        self.max_states = max_states
        # Load segments
        library_options = {}
        segments = self._load_dumps(memory_dump_path)
        log.info(f"Loading {len(segments)} memory dumps")
        main_addr, main_file = segments.pop()
        self.main_object = main_addr
        self.loaded_libraries = []  # TODO: Populate this
        main_options = {
            "backend": "blob",
            "arch": arch,
            "base_addr": main_addr,
            "entry_point": 0,
        }
        for addr, path in segments:
            library_options[path] = {
                "backend": "blob",
                "arch": arch,
                "base_addr": addr,
                "entry_point": 0,
            }
        self.angr_project = angr.Project(
            main_file,
            main_opts=main_options,
            force_load_libs=[path for addr, path in segments],
            lib_opts=library_options,
            ld_path=[os.path.abspath(memory_dump_path)],
        )
        self._resolve_functions()

        # Create initial state
        opts = angr.sim_options.refs | angr.sim_options.resilience
        self.initial_state = self.angr_project.factory.blank_state(add_options=opts)

        # Load registers
        registers = self._load_registers(self.angr_project.arch, reg_file_path)
        log.info(f"Loading {len(registers)} registers")
        for reg, value in registers.items():
            log.debug(f"{reg} = {hex(value)}")
            setattr(self.initial_state.regs, reg, value)

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

    def _load_dumps(self, path: str) -> List[Tuple[int, str]]:
        """
        Get a list contianing the starting address and path of every memory dump
        """
        abspath = os.path.abspath(path)
        files = os.listdir(path)
        dumps = []
        for file in files:
            if file.endswith("phy.dmp"):
                file_full_path = abspath + "/" + file
                start_addr_hex = file.split("-")[0]
                start_addr = int(start_addr_hex, 16)
                dumps.append((start_addr, file_full_path))
        return dumps

    def _load_registers(self, arch: archinfo.Arch, path: str) -> Dict[str, int]:
        """
        Get a dictionary containing each register name and value to initialize
        """
        all_regs = []
        for reg in arch.register_list:
            all_regs.append(reg.name)
            all_regs.extend(list(reg.alias_names))

        regs_to_load = {}
        with open(path) as f:
            for line in f:
                split = line.strip().split("=")
                if len(split) == 2:
                    reg_name = split[0]
                    if reg_name in all_regs:
                        value = int(split[1], 16)
                        regs_to_load[reg_name] = value
        return regs_to_load


class ForseeProjectArm(ForseeProjectSegmented):
    def __init__(self, memory_dump_path: str, reg_file_path: str):
        super().__init__(memory_dump_path, reg_file_path, "ARM")

    def _fix_reg_name(self, reg_name: str) -> str:
        """
        Fix the name of ip since that is a reserved name by angr
        """
        if reg_name == "ip":
            return "r12"
        return reg_name

    def _load_registers(self, arch: archinfo.Arch, path: str) -> Dict[str, int]:
        # TODO: Make sure actual captures include flags with proper names
        all_regs = []
        for reg in arch.register_list:
            all_regs.append(reg.name)
            all_regs.extend(list(reg.alias_names))

        regs_to_load = {}
        with open(path) as f:
            for line in f:
                split = line.strip().split("=")
                if len(split) == 2:
                    reg_name = self._fix_reg_name(split[0])
                    if reg_name in all_regs:
                        value = int(split[1], 16)
                        regs_to_load[reg_name] = value
        return regs_to_load

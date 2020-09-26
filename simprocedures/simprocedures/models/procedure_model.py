import logging
from typing import Optional

import angr
from angr import Project, SimValueError
from angr.sim_type import SimTypeArray, SimTypePointer
from claripy import BV

from simprocedures.models.function_model import FunctionModel

log = logging.getLogger(__name__)


class ProcedureModel(angr.SimProcedure):
    def __init__(self, proj: Project, model: FunctionModel):
        super().__init__(
            project=proj,
            cc=model.create_cc(proj.arch),
            num_args=model.num_params,
            display_name=model.name,
        )
        self.model = model

    def _unconstrained(self, name: str, size: Optional[int] = None) -> BV:
        if size is None:
            size = self.state.arch.bits
        return self.state.solver.Unconstrained(
            f"unconstrained_{name}_{self.display_name}",
            size,
            key=("api", "?", self.display_name),
        )

    def run(self, *args, **kwargs):
        if not self.model.has_complete_metadata or not self.model.has_complete_typing:
            log.warning(f"Incomplete function model for {self.display_name}")
        for i, param in enumerate(self.model.params):
            if param.meta and "out" in param.meta.lower():
                if isinstance(param.type, SimTypePointer):
                    obj_size = param.type.pts_to.with_arch(self.state.arch).size
                    unconst_mem = self._unconstrained(param.name, obj_size)
                    arg_ptr = self.arg(i)
                    try:
                        if self.state.solver.eval_one(arg_ptr) == 0:
                            continue
                    except SimValueError:
                        pass
                    self.state.memory.store(arg_ptr, unconst_mem)
                elif isinstance(param.type, SimTypeArray):
                    obj_size = param.type.with_arch(self.state.arch).size
                    unconst_mem = self._unconstrained(param.name, obj_size)
                    arg_ptr = self.arg(i)
                    try:
                        if self.state.solver.eval_one(arg_ptr) == 0:
                            continue
                    except SimValueError:
                        pass
                    self.state.memory.store(arg_ptr, unconst_mem)
                else:
                    log.warning(f"Param {param.name} is an output but not a pointer")
        return self._unconstrained("ret")

import angr
from angr.sim_type import ALL_TYPES


class GetCurrentPackageId(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=2,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, bufferLength, buffer):
        uint32_bits = ALL_TYPES["uint32_t"].with_arch(self.state.arch).size
        length_bv = self.state.memory.load(
            bufferLength, uint32_bits // 8, endness=self.state.arch.memory_endness
        )
        length_bits = self.state.solver.eval(length_bv) * 8
        buffer_value = self.state.solver.Unconstrained(
            f"unconstrained_buffer_{self.display_name}",
            length_bits,
            key=("api", "?", self.display_name),
        )
        new_length = self.state.solver.Unconstrained(
            f"unconstrained_bufferLength_{self.display_name}",
            uint32_bits,
            key=("api", "?", self.display_name),
        )
        self.state.solver.add(new_length <= length_bits)
        self.state.memory.store(buffer, buffer_value)
        self.state.memory.store(bufferLength, new_length)
        return self.state.solver.Unconstrained(
            f"unconstrained_ret_{self.display_name}",
            self.state.arch.bits,
            key=("api", "?", self.display_name),
        )

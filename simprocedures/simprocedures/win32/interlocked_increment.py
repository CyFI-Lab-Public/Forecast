import angr
from angr.sim_type import ALL_TYPES


class InterlockedIncrement(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, Addend):
        long_size = ALL_TYPES["long"].with_arch(self.state.arch).size // 8
        addend_value = self.state.memory.load(
            Addend, long_size, endness=self.state.arch.memory_endness
        )
        incremented = addend_value + 1
        self.state.memory.store(
            Addend, incremented, endness=self.state.arch.memory_endness
        )
        return incremented


class InterlockedDecrement(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, Addend):
        long_size = ALL_TYPES["long"].with_arch(self.state.arch).size // 8
        addend_value = self.state.memory.load(
            Addend, long_size, endness=self.state.arch.memory_endness
        )
        decremented = addend_value - 1
        self.state.memory.store(
            Addend, decremented, endness=self.state.arch.memory_endness
        )
        return decremented

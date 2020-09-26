import angr


class IsProcessorFeaturePresent(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, feature):
        return self.state.solver.Unconstrained(
            f"unconstrained_ret_{self.display_name}",
            self.state.arch.bits,
            key=("api", "?", self.display_name),
        )

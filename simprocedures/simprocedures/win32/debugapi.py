import angr


class IsDebuggerPresent(angr.SimProcedure):
    """
    Just tells the binary that no debugger is present
    """
    def __init__(self, project: angr.Project):
        super().__init__(project=project, num_args=0)

    def run(self):
        return 0

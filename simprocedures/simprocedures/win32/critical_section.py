import angr


class EnterCriticalSection(angr.SimProcedure):
    """
    This doesn't really do anything. It exists to denote the calling convention
    """

    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, lpCriticalSection):
        pass


class InitializeCriticalSection(angr.SimProcedure):
    """
    This doesn't really do anything. It exists to denote the calling convention
    """

    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, lpCriticalSection):
        pass


class LeaveCriticalSection(angr.SimProcedure):
    """
    This doesn't really do anything. It exists to denote the calling convention
    """

    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, lpCriticalSection):
        pass


class DeleteCriticalSection(angr.SimProcedure):
    """
    This doesn't really do anything. It exists to denote the calling convention
    """

    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, lpCriticalSection):
        pass

import logging

import angr
from angr.calling_conventions import SimCCStdcall

log = logging.getLogger(__name__)


class GetCurrentProcess(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project, num_args=0, cc=SimCCStdcall(project.arch),
        )

    def run(self):
        # Return dummy process handle
        return 0x70726F63


class TerminateProcess(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=2,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, hProcess, uExitCode):
        self.NO_RET = False
        if hProcess.concrete and self.state.solver.eval_one(hProcess) == 0x70726F63:
            # Terminate own process
            log.info("Terminating own process")
            self.NO_RET = True
        return 1


class CorExitProcess(angr.SimProcedure):
    NO_RET = True

    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, exitCode):
        log.info("Terminating own process")

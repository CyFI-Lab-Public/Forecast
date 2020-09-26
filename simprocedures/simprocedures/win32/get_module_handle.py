import logging

import angr

log = logging.getLogger(__name__)


class GetModuleHandleA(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, lpModuleName):
        if self.state.solver.is_true(lpModuleName == 0):
            return self.handle(None)
        else:
            lib = self.state.mem[lpModuleName].string.concrete.decode("utf-8")
            log.debug(f'GetModuleHandleA called with pointer to "{lib}"')
            return self.handle(lib)

    def handle(self, module_name):
        if module_name is None:
            obj = self.project.loader.main_object
        else:
            obj = self.project.loader.find_object(module_name)
            if obj is None:
                log.info('GetModuleHandle: No loaded object named "%s"', module_name)
                return 0
        return obj.mapped_base


class GetModuleHandleW(GetModuleHandleA):
    def run(self, lpModuleName):
        if self.state.solver.is_true(lpModuleName == 0):
            return self.handle(None)
        else:
            lib = self.state.mem[lpModuleName].wstring.concrete
            log.debug(f'GetModuleHandleW called with pointer to "{lib}"')
            return self.handle(lib)


class GetModuleHandleExA(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=3,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, dwFlags, lpModuleName, phModule):
        if self.state.solver.is_true(lpModuleName == 0):
            return self.handle(None)
        else:
            lib = self.state.mem[lpModuleName].string.concrete.decode("utf-8")
            log.debug(f'GetModuleHandleExA called with pointer to "{lib}"')
            return self.handle(lib)

    def handle(self, module_name):
        if module_name is None:
            obj = self.project.loader.main_object
        else:
            obj = self.project.loader.find_object(module_name)
            if obj is None:
                log.info('GetModuleHandle: No loaded object named "%s"', module_name)
                return 0
        return obj.mapped_base


class GetModuleHandleExW(GetModuleHandleExA):
    def run(self, dwFlags, lpModuleName, phModule):
        if self.state.solver.is_true(lpModuleName == 0):
            return self.handle(None)
        else:
            lib = self.state.mem[lpModuleName].wstring.concrete
            log.debug(f'GetModuleHandleExW called with pointer to "{lib}"')
            return self.handle(lib)

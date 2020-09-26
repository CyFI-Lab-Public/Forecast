import logging

import angr
from angr import BP_AFTER, BP_BEFORE

from .plugins import all_plugins

log = logging.getLogger(__name__)


class PluginManager:
    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        self.plugins = [
            plugin(proj, simgr)
            for plugin in all_plugins
            if type(proj.arch) in plugin.supported_arch
        ]
        self.register_callbacks(simgr.active[0])
        log.debug(f"PluginManager initialized with plugins: {self.plugins}")

    def stepped(self, simgr: angr.SimulationManager):
        """
        Hook called on each step of the simgr.
        """
        for plugin in self.plugins:
            plugin.stepped(simgr)

    def complete(self, simgr: angr.SimulationManager):
        """
        Hook called on exploration completion. This is useful for plugins that need to perform
        analysis of collected data after the exploration is finished.
        """
        for plugin in self.plugins:
            plugin.complete(simgr)

    def register_callbacks(self, state: angr.SimState):
        """
        Create breakpoints for all supported events
        """
        state.inspect.b("mem_read", when=BP_AFTER, action=self.mem_read)
        state.inspect.b("mem_write", when=BP_AFTER, action=self.mem_write)
        state.inspect.b(
            "address_concretization", when=BP_AFTER, action=self.address_concretization
        )
        state.inspect.b("reg_read", when=BP_AFTER, action=self.reg_read)
        state.inspect.b("reg_write", when=BP_AFTER, action=self.reg_write)
        state.inspect.b("tmp_read", when=BP_AFTER, action=self.tmp_read)
        state.inspect.b("tmp_write", when=BP_AFTER, action=self.tmp_write)
        state.inspect.b("expr", when=BP_AFTER, action=self.expr)
        state.inspect.b("statement", when=BP_AFTER, action=self.statement)
        state.inspect.b("instruction", when=BP_AFTER, action=self.instruction)
        state.inspect.b("irsb", when=BP_AFTER, action=self.irsb)
        state.inspect.b("constraints", when=BP_AFTER, action=self.constraints)
        state.inspect.b("exit", when=BP_AFTER, action=self.exit)
        state.inspect.b("fork", when=BP_AFTER, action=self.fork)
        state.inspect.b(
            "symbolic_variable", when=BP_AFTER, action=self.symbolic_variable
        )
        state.inspect.b("call", when=BP_AFTER, action=self.call)
        state.inspect.b("return", when=BP_AFTER, action=self._return)
        state.inspect.b("simprocedure", when=BP_AFTER, action=self.simprocedure)
        state.inspect.b("dirty", when=BP_BEFORE, action=self.dirty_before)
        state.inspect.b("dirty", when=BP_AFTER, action=self.dirty_after)
        state.inspect.b("syscall", when=BP_AFTER, action=self.syscall)
        state.inspect.b("engine_process", when=BP_AFTER, action=self.engine_process)

    def mem_read(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.mem_read(state)

    def mem_write(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.mem_write(state)

    def address_concretization(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.address_concretization(state)

    def reg_read(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.reg_read(state)

    def reg_write(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.reg_write(state)

    def tmp_read(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.tmp_read(state)

    def tmp_write(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.tmp_write(state)

    def expr(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.expr(state)

    def statement(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.statement(state)

    def instruction(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.instruction(state)

    def irsb(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.irsb(state)

    def constraints(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.constraints(state)

    def exit(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.exit(state)

    def fork(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.fork(state)

    def symbolic_variable(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.symbolic_variable(state)

    def call(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.call(state)

    def _return(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin._return(state)

    def simprocedure(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.simprocedure(state)

    def dirty_before(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.dirty_before(state)

    def dirty_after(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.dirty_after(state)

    def syscall(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.syscall(state)

    def engine_process(self, state: angr.SimState):
        for plugin in self.plugins:
            plugin.engine_process(state)

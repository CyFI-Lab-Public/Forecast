import logging
from typing import Optional

from .plugin_manager import PluginManager
from .project import ForseeProject

log = logging.getLogger(__name__)


class Explorer:
    def __init__(self, project: ForseeProject):
        self.proj = project.angr_project
        initial_state = project.initial_state
        self.simgr = self.proj.factory.simgr(initial_state)
        self.plugin_manager = PluginManager(self.proj, self.simgr)
        for technique in project.techniques:
            log.debug(f"Adding technique {technique}")
            self.simgr.use_technique(technique)

    def run(self, max_steps: Optional[int] = None):
        """
        Step the initial state forward by max_steps or until completion
        """
        step_count = 0
        max_exceeded = False
        log.info(f"Starting exploration at {hex(self.simgr.active[0].addr)}")
        while not max_exceeded and not self.simgr.complete():
            if len(self.simgr.active) == 0:
                log.warning("No states in the active stash")
                break
            self.simgr.step()
            self.plugin_manager.stepped(self.simgr)
            log.debug(f"{self.simgr}")
            log.debug(f"Active: {self.simgr.active}")
            step_count += 1
            if max_steps:
                max_exceeded = step_count >= max_steps
        if max_exceeded:
            self.simgr.move(from_stash="active", to_stash="max_steps")
        self.plugin_manager.complete(self.simgr)
        log.info("Exploration finished")
        log.info(f"Max steps exceeded: {max_exceeded}")
        log.info(f"Reached completed state: {self.simgr.complete()}")
        if len(self.simgr.errored) > 0:
            log.error(f"The following errors were reported:")
            for error in self.simgr.errored:
                log.error(f"   {error}")

import logging
from typing import List, Optional

import angr

from forsee.function_resolvers import get_compatible_resolver
from forsee.techniques import DegreeOfConcreteness, ProcedureHandler

log = logging.getLogger(__name__)


class ForseeProject:
    angr_project: angr.Project = None
    max_states = None
    initial_state: angr.SimState = None
    main_object: int = None
    loaded_libraries: List[int] = None
    func_models_path: Optional[str] = None
    _techniques: List[angr.ExplorationTechnique] = None
    _imports = {}
    _exports = {}

    def _resolve_functions(self):
        if (
            self.angr_project is None
            or self.main_object is None
            or self.loaded_libraries is None
        ):
            raise ValueError()
        resolver = get_compatible_resolver(self.main_object, self.angr_project)
        if resolver:
            self._imports, self._exports = resolver.find_functions(
                self.main_object, self.loaded_libraries
            )

    @property
    def techniques(self):
        if self._techniques is None:
            proc_handler = ProcedureHandler(
                self._imports, self._exports, self.angr_project, self.func_models_path
            )
            doc = DegreeOfConcreteness(self.initial_state, self.max_states)
            self._techniques = [proc_handler, doc]
        return self._techniques

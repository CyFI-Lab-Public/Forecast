import logging

import angr
import archinfo
from angr.errors import SimUnsatError

from .extract_string import get_string_a, get_string_w
from .plugin_base import PluginBase

log = logging.getLogger(__name__)


class ExternalCnC(PluginBase):
    """
    This analysis monitors for calls to functions that are commonly used by malware that uses
    external sources to get CnC URLs or IP addresses
    """

    supported_arch = [arch_info[3] for arch_info in archinfo.arch_id_map]

    def __init__(self, proj: angr.Project, simgr: angr.SimulationManager):
        super().__init__(proj, simgr)
        log.debug("ExternCnC plugin initialized")
        self.functions_monitored = [
            "InternetOpenUrlA",
            "InternetOpenUrlW",
            "InternetReadFile",
        ]

    def __repr__(self):
        return "<ExternCnCPlugin>"

    def _analyze(self, state: angr.SimState):
        for handle in state.globals["external_c&c"]["read_file"]:
            if handle in state.globals["external_c&c"]["open_url"]:
                url, ptr = state.globals["external_c&c"]["open_url"][handle]
                logstr = "Detected potential source for C&C URLs: "
                if url is None:
                    logstr += "<Symbolic string at 0x%x>" % ptr
                else:
                    logstr += '"' + url + '"'
                log.info(logstr + " with DoC %.2f" % state.doc.concreteness)

    def simprocedure(self, state: angr.SimState):
        proc = state.inspect.simprocedure
        if proc is None:
            # Handle syscall SimProcedures
            log.debug("Reached a syscall SimProcedure")
            return
        proc_name = proc.display_name

        if proc_name not in self.functions_monitored:
            return

        if "external_c&c" not in state.globals:
            state.globals["external_c&c"] = {}

        if proc_name == "InternetOpenUrlA":
            handle = proc.handle
            url_ptr = proc.arg(1)
            try:
                url = get_string_a(state, url_ptr)
            except SimUnsatError:
                url = None
            if "open_url" not in state.globals["external_c&c"]:
                state.globals["external_c&c"]["open_url"] = {}
            state.globals["external_c&c"]["open_url"][handle] = (url, url_ptr)

        elif proc_name == "InternetOpenUrlW":
            handle = proc.handle
            url_ptr = proc.arg(1)
            try:
                url = get_string_w(state, url_ptr)
            except SimUnsatError:
                url = None
            if "open_url" not in state.globals["external_c&c"]:
                state.globals["external_c&c"]["open_url"] = {}
            state.globals["external_c&c"]["open_url"][handle] = (url, url_ptr)

        elif proc_name == "InternetReadFile":
            handle = proc.arg(0)
            try:
                handle = state.solver.eval(handle, cast_to=int, exact=True)
            except SimUnsatError:
                handle = None
            # bufptr = proc.arg(1)
            # bufsz = proc.arg(2)
            if "read_file" not in state.globals["external_c&c"]:
                state.globals["external_c&c"]["read_file"] = []
            state.globals["external_c&c"]["read_file"].append(handle)
            self._analyze(state)

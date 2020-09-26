import logging

import angr
from angr.sim_type import ALL_TYPES

log = logging.getLogger(__name__)


class ntohs(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, netshort):
        endness = self.state.arch.memory_endness
        if endness == "Iend_LE":
            bits = self.state.arch.bits
            ushort_size = ALL_TYPES["unsigned short"].with_arch(self.state.arch).size
            netshort_ushort = netshort[ushort_size - 1 : 0]
            netshort_rev = netshort_ushort.reversed
            return netshort_rev.zero_extend(bits - ushort_size)
        elif endness == "Iend_BE":
            return netshort
        log.warning(f"Endness {endness} not supported. Returning unconstrained")
        return self.state.solver.Unconstrained(
            f"unconstrained_ret_{self.display_name}",
            self.state.arch.bits,
            key=("api", "?", self.display_name),
        )

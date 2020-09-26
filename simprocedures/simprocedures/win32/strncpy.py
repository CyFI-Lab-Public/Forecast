import angr


class strncpy_s(angr.SimProcedure):
    # TODO: This does not handle errors properly
    def run(self, strDest, numberOfElements, strSource, count):
        strlen = angr.SIM_PROCEDURES["libc"]["strlen"]
        memcpy = angr.SIM_PROCEDURES["libc"]["memcpy"]

        src_len = self.inline_call(strlen, strSource).ret_expr
        cpy_size = self.state.solver.If(
            self.state.solver.ULE(count, src_len + 1), count, src_len + 1
        )

        self.inline_call(memcpy, strDest, strSource, cpy_size)
        return self.state.solver.Unconstrained(
            f"unconstrained_ret_{self.display_name}",
            self.state.arch.bits,
            key=("api", "?", self.display_name),
        )

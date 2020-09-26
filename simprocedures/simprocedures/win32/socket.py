import angr


class socket(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=3,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, domain, typ, protocol):
        # From posix SimProcedure. May not be accurate
        conc_domain = self.state.solver.eval(domain)
        conc_typ = self.state.solver.eval(typ)
        conc_protocol = self.state.solver.eval(protocol)

        if self.state.posix.uid != 0 and conc_typ == 3:  # SOCK_RAW
            return self.state.libc.ret_errno("EPERM")

        nonce = self.state.globals.get("socket_counter", 0) + 1
        self.state.globals["socket_counter"] = nonce
        fd = self.state.posix.open_socket(
            ("socket", conc_domain, conc_typ, conc_protocol, nonce)
        )
        return fd


class closesocket(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=1,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, s):
        return 0


class connect(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=3,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, s, name, namelen):
        return 0


class select(angr.SimProcedure):
    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=5,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, nfds, readfds, writefds, exceptfds, timeout):
        return self.state.solver.Unconstrained(
            f"unconstrained_ret_{self.display_name}",
            self.state.arch.bits,
            key=("api", "?", self.display_name),
        )

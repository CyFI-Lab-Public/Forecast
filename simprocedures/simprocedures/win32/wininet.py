import angr


class NetFnReturnsHandle(angr.SimProcedure):
    handle = 2000 # Arbitrarily high, for tracking

    """
    Generic network SimProcedure which returns handles
    """
    def __init__(self, project: angr.Project, num_args):
        super().__init__(
            project=project,
            num_args=num_args,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def return_handle(self):
        ret = self.state.solver.BVV(NetFnReturnsHandle.handle, 32)
        NetFnReturnsHandle.handle += 1
        return ret


class HttpOpenRequest(NetFnReturnsHandle):
    """
    This doesn't really do anything. It exists so that we can extract arguments
    """

    def __init__(self, project: angr.Project):
        super().__init__(project=project, num_args=8)

    def run(self, hConnect, lpszVerb, lpszObjectName, lpszVersion, lpszReferrer, lplpszAcceptTypes, dwFlags, dwContext):
        return self.return_handle()


class HttpOpenRequestA(HttpOpenRequest):
    pass


class HttpOpenRequestW(HttpOpenRequest):
    pass


class InternetOpen(NetFnReturnsHandle):
    """
    This doesn't really do anything. It exists to specify the calling convention
    """

    def __init__(self, project: angr.Project):
        super().__init__(project=project, num_args=5)

    def run(self, lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags):
        return self.return_handle()


class InternetOpenA(InternetOpen):
    pass


class InternetOpenW(InternetOpen):
    pass


class InternetOpenUrl(NetFnReturnsHandle):
    """
    This doesn't really do anything. It exists so that we can extract arguments
    """

    def __init__(self, project: angr.Project):
        super().__init__(project=project, num_args=6)

    def run(self, hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext):
        return self.return_handle()


class InternetOpenUrlA(InternetOpenUrl):
    pass


class InternetOpenUrlW(InternetOpenUrl):
    pass


class InternetConnect(NetFnReturnsHandle):
    """
    This doesn't really do anything. It exists so that we can extract arguments
    """

    def __init__(self, project: angr.Project):
        super().__init__(project=project, num_args=8)

    def run(self, hInternet, lpszServerName, nServerPort, lpszUserName, lpszPassword, dwService, dwFlags, dwContext):
        return self.return_handle()


class InternetConnectA(InternetConnect):
    pass


class InternetConnectW(InternetConnect):
    pass


class InternetReadFile(angr.SimProcedure):
    """
    This doesn't really do anything. It exists so that we can extract the arguments.
    """

    def __init__(self, project: angr.Project):
        super().__init__(
            project=project,
            num_args=4,
            cc=angr.calling_conventions.SimCCStdcall(project.arch),
        )

    def run(self, hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead):
        data = self.state.solver.Unconstrained("lpdwNumberOfBytesRead", 32)
        self.state.memory.store(lpdwNumberOfBytesRead, data)
        return self.state.solver.Unconstrained("InternetReadFileRes", self.arch.byte_width)

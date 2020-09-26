from simprocedures.win32.critical_section import (
    DeleteCriticalSection,
    EnterCriticalSection,
    InitializeCriticalSection,
    LeaveCriticalSection,
)
from simprocedures.win32.get_current_package_id import GetCurrentPackageId
from simprocedures.win32.get_module_handle import (
    GetModuleHandleA,
    GetModuleHandleExA,
    GetModuleHandleExW,
    GetModuleHandleW,
)
from simprocedures.win32.interlocked_increment import (
    InterlockedDecrement,
    InterlockedIncrement,
)
from simprocedures.win32.wininet import (
    HttpOpenRequestA,
    HttpOpenRequestW,
    InternetConnectA,
    InternetConnectW,
    InternetOpenUrlA,
    InternetOpenUrlW,
    InternetReadFile
)
from simprocedures.win32.is_processor_feature_present import IsProcessorFeaturePresent
from simprocedures.win32.ntohs import ntohs
from simprocedures.win32.process import (
    CorExitProcess,
    GetCurrentProcess,
    TerminateProcess,
)
from simprocedures.win32.socket import closesocket, connect, select, socket
from simprocedures.win32.strncpy import strncpy_s
from simprocedures.win32.debugapi import IsDebuggerPresent

procedures = {
    "HttpOpenRequestA": HttpOpenRequestA,
    "HttpOpenRequestW": HttpOpenRequestW,
    "InternetConnectA": InternetConnectA,
    "InternetConnectW": InternetConnectW,
    "InternetOpenUrlA": InternetOpenUrlA,
    "InternetOpenUrlW": InternetOpenUrlW,
    "InternetReadFile": InternetReadFile,
    "InitializeCriticalSection": InitializeCriticalSection,
    "IsDebuggerPresent": IsDebuggerPresent,
    "DeleteCriticalSection": DeleteCriticalSection,
    "EnterCriticalSection": EnterCriticalSection,
    "LeaveCriticalSection": LeaveCriticalSection,
    "RtlDeleteCriticalSection": DeleteCriticalSection,
    "RtlInitializeCriticalSection": InitializeCriticalSection,
    "RtlEnterCriticalSection": EnterCriticalSection,
    "RtlLeaveCriticalSection": LeaveCriticalSection,
    "IsProcessorFeaturePresent": IsProcessorFeaturePresent,
    "strncpy_s": strncpy_s,
    "GetCurrentProcess": GetCurrentProcess,
    "TerminateProcess": TerminateProcess,
    "InterlockedIncrement": InterlockedIncrement,
    "InterlockedDecrement": InterlockedDecrement,
    "socket": socket,
    "closesocket": closesocket,
    "GetCurrentPackageId": GetCurrentPackageId,
    "CorExitProcess": CorExitProcess,
    "ntohs": ntohs,
    "connect": connect,
    "GetModuleHandleA": GetModuleHandleA,
    "GetModuleHandleW": GetModuleHandleW,
    "GetModuleHandleExA": GetModuleHandleExA,
    "GetModuleHandleExW": GetModuleHandleExW,
    "select": select,
}

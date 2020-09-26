from angr.sim_type import *

NON_PTR_TYPES = {
    "SOCKET": SimTypeInt(signed=False),
    "const char *": SimTypeString(),
    "const sockaddr": SimStruct(
        {
            "sa_family": ALL_TYPES["unsigned short"],
            "sa_data": SimTypeFixedSizeArray(SimTypeChar(), 14),
        }
    ),
    "BOOL": SimTypeInt(),
    "BOOLAPI": SimTypeInt(),
    "BSTR": SimTypeWString(),
    "HFILE": SimTypeInt(),
    "SIZE_T": SimTypeLong(signed=False),
    "DWORD": SimTypeLong(signed=False),
    "DWORD_PTR": SimTypeLong(signed=False),  # TODO: Should this be a ptr?
    "UINT": SimTypeInt(signed=False),
    "INT": SimTypeInt(),
    "LPSTR": SimTypeString(),
    "LPWSTR": SimTypeWString(),
    "LPCSTR": SimTypeString(),
    "HANDLE": SimTypeLong(signed=False),
    "HKEY": SimTypeLong(signed=False),
    "HBITMAP": SimTypeLong(signed=False),
    "HDC": SimTypeLong(signed=False),
    "HHOOK": SimTypeLong(signed=False),
    "HINSTANCE": SimTypeLong(signed=False),
    "HWND": SimTypeLong(signed=False),
    "LPCVOID": SimTypeLong(signed=False),
    "LPVOID": SimTypeLong(signed=False),
    "BYTE": SimTypeChar(signed=False),
    "WORD": SimTypeShort(signed=False),
    "POINT": SimStruct({"x": SimTypeLong(), "y": SimTypeLong()}),
    "MSG": SimStruct(
        {
            "HWND": SimTypeLong(signed=False),
            "message": SimTypeInt(signed=False),
            "wParam": SimTypeInt(signed=False),
            "lParam": SimTypeLong(),
            "time": SimTypeLong(signed=False),
            "pt": SimStruct({"x": SimTypeLong(), "y": SimTypeLong()}),
            "lPrivate": SimTypeLong(signed=False),
        }
    ),
    "PROCESS_INFORMATION": SimStruct(
        {
            "hProcess": SimTypeLong(signed=False),
            "hThread": SimTypeLong(signed=False),
            "dwProcessId": SimTypeLong(signed=False),
            "dwThreadId": SimTypeLong(signed=False),
        }
    ),
    "OFSTRUCT": SimStruct(
        {
            "cBytes": SimTypeChar(signed=False),
            "fFixedDisk": SimTypeChar(signed=False),
            "nErrCode": SimTypeShort(signed=False),
            "Reserved1": SimTypeShort(signed=False),
            "Reserved2": SimTypeShort(signed=False),
            "szPathName": SimTypeArray(
                SimTypeChar(), length=128
            ),  # This length may vary
        }
    ),
    "OVERLAPPED": SimStruct(
        {
            "Internal": SimTypeLong(signed=False),
            "InternalHigh": SimTypeLong(signed=False),
            "DUMMYUNIONNAME": SimUnion(
                {
                    "DUMMYSTRUCTNAME": SimStruct(
                        {
                            "Offset": SimTypeLong(signed=False),
                            "OffsetHigh": SimTypeLong(signed=False),
                        }
                    ),
                    "Pointer": SimTypePointer(ALL_TYPES["void"]),
                }
            ),
            "hEvent": SimTypeLong(signed=False),
        }
    ),
    "MEMORY_BASIC_INFORMATION": SimStruct(
        {
            "BaseAddress": SimTypePointer(ALL_TYPES["void"]),
            "AllocationBase": SimTypePointer(ALL_TYPES["void"]),
            "AllocationProtect": SimTypeLong(signed=False),
            "PartitionId": SimTypeShort(signed=False),
            "RegionSize": SimTypeLong(signed=False),
            "State": SimTypeLong(signed=False),
            "Protect": SimTypeLong(signed=False),
            "Type": SimTypeLong(signed=False),
        }
    ),
    "DEBUG_EVENT": SimStruct(
        {
            "dwDebugEventCode": SimTypeLong(signed=False),
            "dwProcessId": SimTypeLong(signed=False),
            "dwThreadId": SimTypeLong(signed=False),
            "u": SimTypeLong(signed=False),  # TODO: fix this
        }
    ),
}

PTR_TYPES = {
    "const sockaddr *": SimTypePointer(NON_PTR_TYPES["const sockaddr"]),
    "LPDWORD": SimTypePointer(ALL_TYPES["unsigned long"]),
    "const BYTE *": SimTypePointer(SimTypeArray(NON_PTR_TYPES["BYTE"])),
    "SIZE_T *": SimTypePointer(NON_PTR_TYPES["SIZE_T"]),
    "PHKEY": SimTypePointer(NON_PTR_TYPES["HKEY"]),
    "LPMSG": SimTypePointer(NON_PTR_TYPES["MSG"]),
    "LPPROCESS_INFORMATION": SimTypePointer(NON_PTR_TYPES["PROCESS_INFORMATION"]),
    "LPOFSTRUCT": SimTypePointer(NON_PTR_TYPES["OFSTRUCT"]),
    "LPOVERLAPPED": SimTypePointer(NON_PTR_TYPES["OVERLAPPED"]),
    "LPBYTE": SimTypePointer(SimTypeArray(NON_PTR_TYPES["BYTE"])),
    "PMEMORY_BASIC_INFORMATION": SimTypePointer(
        NON_PTR_TYPES["MEMORY_BASIC_INFORMATION"]
    ),
    "LPSTR *": SimTypePointer(NON_PTR_TYPES["LPSTR"]),
    "LPWSTR *": SimTypePointer(NON_PTR_TYPES["LPWSTR"]),
    "LPDEBUG_EVENT": SimTypePointer(NON_PTR_TYPES["DEBUG_EVENT"]),
    "PCHAR": SimTypeString(),
    "INT *": SimTypePointer(NON_PTR_TYPES["INT"]),
    "u_long*": SimTypePointer(ALL_TYPES["unsigned long"]),
}

MASTER_TYPES = {}
MASTER_TYPES.update(ALL_TYPES)
MASTER_TYPES.update(NON_PTR_TYPES)
MASTER_TYPES.update(PTR_TYPES)

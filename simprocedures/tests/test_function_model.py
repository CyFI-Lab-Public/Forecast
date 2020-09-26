import archinfo
import pytest
from angr.calling_conventions import SimCCStdcall

from simprocedures.models.data_types import MASTER_TYPES
from simprocedures.models.function_model import FunctionModel, Parameter


@pytest.mark.parametrize(
    "name,type,meta,expected_type",
    [
        ("s", "SOCKET", "in", MASTER_TYPES["SOCKET"]),
        ("name", "const sockaddr *", "in", MASTER_TYPES["const sockaddr *"]),
        ("namelen", "int", "in", MASTER_TYPES["int"]),
        ("my_param", "my_fake_type", None, MASTER_TYPES["void"]),
    ],
)
def test_parameter(name, type, meta, expected_type):
    param = Parameter(name, type, meta)
    assert param.name == name
    assert param.type == expected_type
    assert param.meta == meta


def test_function_model():
    s = Parameter("s", "SOCKET", "in")
    name = Parameter("name", "const sockaddr *", "in")
    namelen = Parameter("namelen", "int", "in")
    func_model = FunctionModel("connect", [s, name, namelen], "__stdcall")
    assert func_model.name == "connect"
    assert func_model.params == [s, name, namelen]
    assert func_model.cc_str == "__stdcall"
    assert func_model.num_params == 3


@pytest.mark.parametrize("meta,expected", [("in", True), (None, False)])
def test_has_complete_metadata(meta, expected):
    s = Parameter("s", "SOCKET", meta)
    name = Parameter("name", "const sockaddr *", "in")
    namelen = Parameter("namelen", "int", "in")
    func_model = FunctionModel("connect", [s, name, namelen], "__stdcall")
    assert func_model.has_complete_metadata == expected


@pytest.mark.parametrize("type_str,expected", [("SOCKET", True), (None, False)])
def test_has_complete_typing(type_str, expected):
    s = Parameter("s", type_str, "in")
    name = Parameter("name", "const sockaddr *", "in")
    namelen = Parameter("namelen", "int", "in")
    func_model = FunctionModel("connect", [s, name, namelen], "__stdcall")
    assert func_model.has_complete_typing == expected


@pytest.mark.parametrize(
    "arch,cc,cc_str",
    [
        (archinfo.ArchAMD64, None, "__stdcall"),
        (archinfo.ArchAMD64, None, "__cdecl"),
        (archinfo.ArchX86, SimCCStdcall(archinfo.ArchX86()), "__stdcall"),
        (archinfo.ArchX86, None, "__cdecl"),
        (archinfo.ArchARM, None, "__stdcall"),
        (archinfo.ArchARMEL, None, "__stdcall"),
        (archinfo.ArchARMHF, None, "__stdcall"),
        (archinfo.ArchARMCortexM, None, "__stdcall"),
        (archinfo.ArchAArch64, None, "__stdcall"),
        (archinfo.ArchPPC32, None, "__stdcall"),
        (archinfo.ArchPPC64, None, "__stdcall"),
        (archinfo.ArchMIPS32, None, "__stdcall"),
        (archinfo.ArchMIPS64, None, "__stdcall"),
        (archinfo.ArchSoot, None, "__stdcall"),
        (archinfo.ArchS390X, None, "__stdcall"),
    ],
)
def test_create_cc(arch, cc, cc_str):
    func_model = FunctionModel("connect", [], cc_str)
    assert func_model.create_cc(arch()) == cc

from pathlib import Path

import angr
import pytest

from forsee.techniques import DegreeOfConcreteness


def test_initialization_missing_refs():
    test_file = (
        Path(__file__).parent / "../sample_dumps/windows_dynamic_loading/Dump/Main.dmp"
    )
    proj = angr.Project(str(test_file.resolve()))
    state = proj.factory.blank_state()
    with pytest.raises(ValueError):
        DegreeOfConcreteness(state)


def test_initialization():
    test_file = (
        Path(__file__).parent / "../sample_dumps/windows_dynamic_loading/Dump/Main.dmp"
    )
    proj = angr.Project(str(test_file.resolve()))
    state = proj.factory.blank_state(add_options=angr.options.refs)
    doc = DegreeOfConcreteness(state)
    assert str(doc) == "<DegreeOfConcreteness>"
    assert state.doc.concreteness == 1
    assert state.doc.cumul_ratio == 0

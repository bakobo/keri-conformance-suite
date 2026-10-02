"""The test helpers in conftest.py (PR #6 round 2, J)."""

import pytest


def test_the_entry_point_beside_the_interpreter_is_preferred(tmp_path):
    from conftest import locate_entry_point
    python = tmp_path / "python"
    script = tmp_path / "kcs-adapter-keripy"
    script.write_text("")
    assert locate_entry_point(str(python), which=lambda name: "/elsewhere/x") == str(script)


def test_the_entry_point_found_only_on_path_is_that_resolved_path(tmp_path):
    from conftest import locate_entry_point
    found = tmp_path / "bin" / "kcs-adapter-keripy"
    found.parent.mkdir()
    found.write_text("")
    assert locate_entry_point(str(tmp_path / "python"), which=lambda name: str(found)) == str(
        found.resolve())


def test_no_entry_point_anywhere_is_an_explicit_failure(tmp_path):
    from conftest import locate_entry_point
    with pytest.raises(pytest.fail.Exception) as info:
        locate_entry_point(str(tmp_path / "python"), which=lambda name: None)
    assert "kcs-adapter-keripy" in str(info.value)

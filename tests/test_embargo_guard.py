"""The embargo guard refuses a push whose new commits mention anything on the private list."""

import io
import subprocess

import pytest

from tools import embargo_guard as guard


@pytest.fixture(autouse=True)
def no_ambient_configuration(monkeypatch, tmp_path):
    """Neither the caller's environment nor their global git config may point the guard anywhere."""
    monkeypatch.delenv(guard.ENV_PATTERNS, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(tmp_path / "no-global-gitconfig"))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True,
                          text=True).stdout


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@example.com")
    git(r, "config", "user.name", "t")
    (r / "a.txt").write_text("base\n")
    git(r, "add", "a.txt")
    git(r, "commit", "-q", "-m", "base")
    return r


@pytest.fixture
def patterns(tmp_path):
    p = tmp_path / "patterns.txt"
    p.write_text("# held cases\nCESR-0099\nsecret phrase\n\n")
    return p


def commit(repo, name, text, message="change"):
    (repo / name).write_text(text)
    git(repo, "add", name)
    git(repo, "commit", "-q", "-m", message)
    return git(repo, "rev-parse", "HEAD").strip()


def base(repo):
    return git(repo, "rev-parse", "HEAD").strip()


def test_clean_changes_pass(repo, patterns):
    start = base(repo)
    commit(repo, "b.txt", "nothing to see\n")
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range",
                       f"{start}..HEAD"]) == 0


def test_a_listed_id_in_an_added_line_is_refused(repo, patterns, capsys):
    start = base(repo)
    commit(repo, "b.txt", "see CESR-0099 for details\n")
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range",
                       f"{start}..HEAD"]) == 1
    err = capsys.readouterr().err
    assert err.startswith("e.rule.embargo.f: ") and "b.txt" in err


def test_a_listed_phrase_in_a_commit_message_is_refused(repo, patterns, capsys):
    start = base(repo)
    commit(repo, "b.txt", "fine\n", message="mentions a Secret Phrase here")
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range",
                       f"{start}..HEAD"]) == 1
    assert "commit message" in capsys.readouterr().err


def test_a_removed_line_is_not_refused(repo, patterns):
    commit(repo, "b.txt", "CESR-0099\n")
    start = base(repo)
    commit(repo, "b.txt", "gone\n")
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range",
                       f"{start}..HEAD"]) == 0


def test_an_unreadable_range_is_a_coded_error(repo, patterns, capsys):
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range",
                       "nope..HEAD"]) == 2
    assert capsys.readouterr().err.startswith("e.input.format.embargo-range.f: ")


def test_pre_push_ranges_from_hook_input(repo):
    zero = "0" * 40
    head = git(repo, "rev-parse", "HEAD").strip()
    lines = [f"refs/heads/x {head} refs/heads/x {zero}", f"refs/heads/y {zero} refs/heads/y {head}"]
    assert guard.ranges_from_hook(lines, default_base="main") == [f"main..{head}"]
    lines = [f"refs/heads/x {head} refs/heads/x {'1' * 40}", ""]
    assert guard.ranges_from_hook(lines, default_base="main") == [f"{'1' * 40}..{head}"]
    with pytest.raises(guard.HookInputError):
        guard.ranges_from_hook(["malformed line"], default_base="main")


def test_hook_mode_reads_stdin(repo, patterns, monkeypatch, capsys):
    start = base(repo)
    head = commit(repo, "b.txt", "CESR-0099\n")
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(
        f"refs/heads/x {head} refs/heads/x {start}\n".encode())))
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--hook"]) == 1


def test_one_of_range_or_hook_is_required(repo, patterns, capsys):
    with pytest.raises(SystemExit) as e:
        guard.main(["--repo", str(repo), "--patterns", str(patterns)])
    assert e.value.code == 2


def test_a_three_dot_range_is_accepted_as_given(repo, patterns):
    start = base(repo)
    commit(repo, "b.txt", "CESR-0099\n")
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range",
                       f"{start}...HEAD"]) == 1


def test_outside_a_git_repository_the_guard_warns_and_passes(tmp_path, capsys):
    assert guard.main(["--repo", str(tmp_path), "--range", "a..b"]) == 0
    assert "w.rule.embargo.patterns-missing.f" in capsys.readouterr().err


def test_an_external_diff_driver_does_not_hide_a_match(repo, patterns):
    git(repo, "config", "diff.external", "false")
    start = base(repo)
    commit(repo, "b.txt", "CESR-0099\n")
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range",
                       f"{start}..HEAD"]) == 1


def refused(repo, patterns, rng):
    return guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range", rng]) == 1


def test_text_added_then_removed_in_a_later_commit_is_still_refused(repo, patterns, capsys):
    # The earlier commit is pushed too, and it carries the text.
    start = base(repo)
    first = commit(repo, "b.txt", "CESR-0099\n")
    commit(repo, "b.txt", "gone\n")
    assert refused(repo, patterns, f"{start}..HEAD")
    assert first[:12] in capsys.readouterr().err


def test_a_control_character_in_a_message_does_not_hide_it(repo, patterns):
    start = base(repo)
    commit(repo, "b.txt", "fine\n", message="clean\x01CESR-0099")
    assert refused(repo, patterns, f"{start}..HEAD")


def test_an_added_line_that_looks_like_a_file_header_is_read(repo, patterns):
    start = base(repo)
    commit(repo, "b.txt", "++ CESR-0099\n")
    assert refused(repo, patterns, f"{start}..HEAD")


def test_a_unicode_line_separator_does_not_split_an_added_line(repo, patterns):
    start = base(repo)
    commit(repo, "b.txt", "prefix\u2028CESR-0099\n")
    assert refused(repo, patterns, f"{start}..HEAD")


def test_non_utf8_bytes_in_a_diff_do_not_stop_the_scan(repo, patterns):
    start = base(repo)
    (repo / "b.bin.txt").write_bytes(b"\xff\xfe CESR-0099\n")
    git(repo, "add", "b.bin.txt")
    git(repo, "commit", "-q", "-m", "bytes")
    assert refused(repo, patterns, f"{start}..HEAD")


def test_a_merge_is_read_against_its_first_parent(repo, patterns):
    git(repo, "checkout", "-q", "-b", "side")
    commit(repo, "c.txt", "CESR-0099\n")
    git(repo, "checkout", "-q", "main")
    commit(repo, "d.txt", "other\n")
    git(repo, "merge", "-q", "--no-ff", "-m", "merge", "side")
    merge = base(repo)
    # Only the merge and main's own clean commit are in this range; the side commit is not, so the
    # first-parent diff of the merge is the only thing that can find the text.
    assert refused(repo, patterns, f"side..{merge}")


def test_the_root_commit_is_read(tmp_path, patterns):
    r = tmp_path / "fresh"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@example.com")
    git(r, "config", "user.name", "t")
    commit(r, "a.txt", "CESR-0099\n")
    assert refused(r, patterns, "HEAD")


def test_truncated_hook_input_is_a_coded_error(repo, patterns, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.TextIOWrapper(io.BytesIO(b"refs/heads/\xff truncated\n")))
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--hook"]) == 2
    assert capsys.readouterr().err.startswith("e.input.format.embargo-hook-input.f: ")


def test_a_patterns_file_that_is_not_utf8_is_a_coded_error(repo, tmp_path, capsys):
    bad = tmp_path / "bad.txt"
    bad.write_bytes(b"\xff\xfe\n")
    assert guard.main(["--repo", str(repo), "--patterns", str(bad), "--range", "HEAD..HEAD"]) == 2
    assert capsys.readouterr().err.startswith("e.input.format.embargo-patterns.f: ")


def test_a_listed_string_in_a_legacy_encoding_is_found(repo, tmp_path):
    listed = tmp_path / "accented.txt"
    listed.write_text("Kärten-0099\n", encoding="utf-8")
    start = base(repo)
    (repo / "b.txt").write_bytes(b"K\xe4rten-0099\n")
    git(repo, "add", "b.txt")
    git(repo, "commit", "-q", "-m", "latin-1")
    assert refused(repo, listed, f"{start}..HEAD")


def test_a_file_marked_minus_diff_is_still_read(repo, patterns):
    start = base(repo)
    (repo / ".gitattributes").write_text("secret.txt -diff\n")
    (repo / "secret.txt").write_text("CESR-0099\n")
    git(repo, "add", ".gitattributes", "secret.txt")
    git(repo, "commit", "-q", "-m", "attrs")
    assert refused(repo, patterns, f"{start}..HEAD")


def test_a_non_utf8_log_encoding_setting_is_overridden(repo, tmp_path):
    listed = tmp_path / "accented.txt"
    listed.write_text("Kärten-0099\n", encoding="utf-8")
    git(repo, "config", "i18n.logOutputEncoding", "ISO-8859-1")
    start = base(repo)
    commit(repo, "b.txt", "fine\n", message="see Kärten-0099")
    assert refused(repo, listed, f"{start}..HEAD")


# --- where the list comes from -------------------------------------------------------------------


def worktree_of(repo):
    w = repo.parent / "elsewhere" / "w"
    git(repo, "worktree", "add", "-q", str(w))
    return w


def listed_commit(repo):
    start = base(repo)
    commit(repo, "b.txt", "CESR-0099\n")
    return f"{start}..HEAD"


def test_the_default_list_lives_in_the_git_directory_shared_by_every_worktree(repo):
    want = repo / ".git" / "info" / "embargo-patterns.txt"
    assert guard.default_patterns(repo) == want
    assert guard.default_patterns(worktree_of(repo)) == want


def test_the_default_list_is_used_when_nothing_is_configured(repo, patterns):
    (repo / ".git" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "info" / "embargo-patterns.txt").write_text(patterns.read_text())
    assert guard.main(["--repo", str(repo), "--range", listed_commit(repo)]) == 1


def test_without_any_list_the_guard_warns_and_passes(repo, capsys):
    assert guard.main(["--repo", str(repo), "--range", listed_commit(repo)]) == 0
    err = capsys.readouterr().err
    assert err.startswith("w.rule.embargo.patterns-missing.f: ")
    assert "embargo-patterns.txt" in err and guard.ENV_PATTERNS in err


def test_the_environment_variable_names_the_list(repo, patterns, monkeypatch):
    monkeypatch.setenv(guard.ENV_PATTERNS, str(patterns))
    assert guard.main(["--repo", str(repo), "--range", listed_commit(repo)]) == 1


def test_an_empty_environment_variable_is_unset(repo, monkeypatch, capsys):
    monkeypatch.setenv(guard.ENV_PATTERNS, "  ")
    assert guard.main(["--repo", str(repo), "--range", listed_commit(repo)]) == 0
    assert "w.rule.embargo.patterns-missing.f" in capsys.readouterr().err


def test_git_config_names_the_list(repo, patterns):
    git(repo, "config", guard.CONFIG_PATTERNS, str(patterns))
    assert guard.main(["--repo", str(repo), "--range", listed_commit(repo)]) == 1


def test_a_relative_git_config_value_resolves_against_the_main_checkout(repo, patterns):
    (repo / "held").mkdir()
    (repo / "held" / "list.txt").write_text(patterns.read_text())
    git(repo, "config", guard.CONFIG_PATTERNS, "held/list.txt")
    rng = listed_commit(repo)
    w = worktree_of(repo)
    assert guard.patterns_path(w, None, {}) == (repo / "held" / "list.txt", True)
    assert guard.main(["--repo", str(w), "--range", rng]) == 1


def test_a_tilde_in_git_config_is_the_home_directory(repo, tmp_path, patterns, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    git(repo, "config", guard.CONFIG_PATTERNS, "~/patterns.txt")
    assert guard.patterns_path(repo, None, {}) == (patterns, True)


def test_a_tilde_in_the_environment_variable_is_the_home_directory(repo, tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    got = guard.patterns_path(repo, None, {guard.ENV_PATTERNS: "~/x.txt"})
    assert got == (tmp_path / "x.txt", True)


def test_the_flag_outranks_the_environment_which_outranks_git_config(repo, tmp_path):
    git(repo, "config", guard.CONFIG_PATTERNS, str(tmp_path / "from-config.txt"))
    env = {guard.ENV_PATTERNS: str(tmp_path / "from-env.txt")}
    flag = tmp_path / "from-flag.txt"
    assert guard.patterns_path(repo, flag, env) == (flag, True)
    assert guard.patterns_path(repo, None, env) == (tmp_path / "from-env.txt", True)
    assert guard.patterns_path(repo, None, {}) == (tmp_path / "from-config.txt", True)


def test_a_configured_list_that_is_missing_refuses_the_push(repo, tmp_path, capsys):
    git(repo, "config", guard.CONFIG_PATTERNS, str(tmp_path / "moved-away.txt"))
    assert guard.main(["--repo", str(repo), "--range", listed_commit(repo)]) == 2
    err = capsys.readouterr().err
    assert err.startswith("e.input.format.embargo-patterns.f: ") and "moved-away.txt" in err


def test_a_missing_list_named_by_the_environment_refuses_the_push(repo, tmp_path, monkeypatch):
    monkeypatch.setenv(guard.ENV_PATTERNS, str(tmp_path / "nowhere.txt"))
    assert guard.main(["--repo", str(repo), "--range", "HEAD..HEAD"]) == 2


def test_a_missing_list_named_by_the_flag_refuses_the_push(repo, tmp_path):
    assert guard.main(["--repo", str(repo), "--patterns", str(tmp_path / "nowhere.txt"),
                       "--range", "HEAD..HEAD"]) == 2


def test_a_relative_value_outside_a_checkout_is_refused(tmp_path, monkeypatch, capsys):
    # Global git config can name a list for a directory that is not a checkout. With no main
    # checkout to resolve against, the guard refuses rather than reading a file relative to
    # wherever it happens to be run, even when one exists there.
    git(tmp_path, "config", "--global", guard.CONFIG_PATTERNS, "held/list.txt")
    (tmp_path / "held").mkdir()
    (tmp_path / "held" / "list.txt").write_text("nothing\n")
    monkeypatch.chdir(tmp_path)
    assert guard.main(["--repo", str(tmp_path), "--range", "a..b"]) == 2
    assert capsys.readouterr().err.startswith("e.input.format.embargo-patterns.f: ")


def test_a_git_config_that_cannot_be_read_is_not_mistaken_for_unset(repo, capsys):
    (repo / ".git" / "config").write_text("[broken\n")
    assert guard.main(["--repo", str(repo), "--range", "HEAD..HEAD"]) == 2
    assert capsys.readouterr().err.startswith("e.input.format.embargo-patterns.f: ")


def test_the_pre_push_hook_reads_no_bakobo_path():
    hook = (guard.pathlib.Path(__file__).resolve().parent.parent / ".githooks" / "pre-push")
    source = hook.read_text() + guard.pathlib.Path(guard.__file__).read_text()
    assert "reviews" not in source and "bakobo" not in source.lower()


def test_run_as_a_script_the_guard_checks_and_sets_its_exit_status(repo, patterns, monkeypatch):
    # Run by hand (python3 tools/embargo_guard.py ...) it must check, not import and exit 0.
    import runpy
    rng = listed_commit(repo)
    monkeypatch.setattr("sys.argv", ["embargo_guard.py", "--repo", str(repo), "--patterns",
                                     str(patterns), "--range", rng])
    with pytest.raises(SystemExit) as e:
        runpy.run_path(guard.__file__, run_name="__main__")
    assert e.value.code == 1


def test_the_script_runs_from_a_shell(repo, patterns):
    import sys
    rng = listed_commit(repo)
    done = subprocess.run([sys.executable, guard.__file__, "--repo", str(repo), "--patterns",
                           str(patterns), "--range", rng], capture_output=True, text=True,
                          check=False)
    assert done.returncode == 1 and done.stderr.startswith("e.rule.embargo.f: ")


def test_an_empty_git_config_value_is_refused_not_taken_for_unset(repo, capsys):
    git(repo, "config", guard.CONFIG_PATTERNS, "")
    assert guard.main(["--repo", str(repo), "--range", "HEAD..HEAD"]) == 2
    err = capsys.readouterr().err
    assert err.startswith("e.input.format.embargo-patterns.f: ") and "empty" in err

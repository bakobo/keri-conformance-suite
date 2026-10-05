"""The embargo guard refuses a push whose new commits mention anything on the private list."""

import io
import subprocess

import pytest

from tools import embargo_guard as guard


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


def test_without_a_patterns_file_the_guard_says_so_and_passes(repo, tmp_path, capsys):
    assert guard.main(["--repo", str(repo), "--patterns", str(tmp_path / "absent.txt"),
                       "--range", "HEAD..HEAD"]) == 0
    assert "w.rule.embargo.patterns-missing.f" in capsys.readouterr().err


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


def test_default_patterns_path_is_beside_the_main_checkout(tmp_path):
    bakobo = tmp_path / "bakobo"
    main_repo = bakobo / "keri-conformance-suite"
    main_repo.mkdir(parents=True)
    git(main_repo, "init", "-q", "-b", "main")
    git(main_repo, "config", "user.email", "t@example.com")
    git(main_repo, "config", "user.name", "t")
    git(main_repo, "commit", "-q", "--allow-empty", "-m", "base")
    worktree = main_repo / ".worktrees" / "w"
    git(main_repo, "worktree", "add", "-q", str(worktree))
    want = bakobo / "reviews" / "keri-conformance-suite" / "embargoed" / "patterns.txt"
    assert guard.default_patterns(main_repo) == want
    assert guard.default_patterns(worktree) == want


def test_one_of_range_or_hook_is_required(repo, patterns, capsys):
    with pytest.raises(SystemExit) as e:
        guard.main(["--repo", str(repo), "--patterns", str(patterns)])
    assert e.value.code == 2


def test_a_three_dot_range_is_accepted_as_given(repo, patterns):
    start = base(repo)
    commit(repo, "b.txt", "CESR-0099\n")
    assert guard.main(["--repo", str(repo), "--patterns", str(patterns), "--range",
                       f"{start}...HEAD"]) == 1


def test_default_patterns_follow_the_repository_name(tmp_path):
    bakobo = tmp_path / "bakobo"
    renamed = bakobo / "renamed-suite"
    renamed.mkdir(parents=True)
    git(renamed, "init", "-q", "-b", "main")
    assert guard.default_patterns(renamed) == (
        bakobo / "reviews" / "renamed-suite" / "embargoed" / "patterns.txt")


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

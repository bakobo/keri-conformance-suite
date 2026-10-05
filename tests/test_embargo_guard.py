"""The embargo guard refuses a push whose new commits mention anything on the private list."""

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


def test_clean_changes_pass(repo, patterns, capsys):
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
    lines = [f"refs/heads/x {head} refs/heads/x {'1' * 40}", "malformed line"]
    assert guard.ranges_from_hook(lines, default_base="main") == [f"{'1' * 40}..{head}"]


def test_hook_mode_reads_stdin(repo, patterns, monkeypatch, capsys):
    import io

    start = base(repo)
    head = commit(repo, "b.txt", "CESR-0099\n")
    monkeypatch.setattr("sys.stdin", io.StringIO(f"refs/heads/x {head} refs/heads/x {start}\n"))
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

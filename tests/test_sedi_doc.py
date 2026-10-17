"""docs/profiles/sedi.md, the prose profile (test-plan item 14), states every sedi-1 choice as the
profile source reads it, and the things item 14 says it must say."""

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
DOC = (ROOT / "docs" / "profiles" / "sedi.md").read_text(encoding="utf-8")
SOURCE = json.loads((ROOT / "scenarios" / "sedi" / "profile.json").read_text(encoding="utf-8"))


def test_every_choice_is_stated_once_with_its_reading_reason_and_decision():
    for choice in SOURCE["choices"]:
        assert DOC.count(f"#### `{choice['id']}`") == 1, choice["id"]
        for field in ("reading", "basis", "overturn"):
            assert choice[field] in DOC, (choice["id"], field)
        assert f"`{choice['decided']}`" in DOC, choice["id"]


def test_no_choice_is_stated_that_the_profile_does_not_make():
    ids = {c["id"] for c in SOURCE["choices"]}
    stated = {line[len("#### `"):-1] for line in DOC.splitlines() if line.startswith("#### `")}
    assert stated == ids


def test_it_says_what_item_14_requires():
    for words in ("`incomplete` is never an accept, provisional or otherwise",
                  "holds only as of the registry head",
                  "witnesses or a watcher, not from the presenter",
                  "Untargeted credentials are bearer credentials",
                  "does not mean unexpired",
                  "What sedi-1 does not add",
                  "widens the ACDC specification",
                  "relaxes to its latest member"):
        assert words in DOC, words

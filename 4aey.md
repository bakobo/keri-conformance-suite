# Embargo guard (tools/embargo_guard.py:223, from #25): os.path.lexists() reads a PermissionError as absent, so an inaccessible .git/info lets a push pass with no list checked (fail-open). Distinguish absent from unreadable and refuse the latter with a coded error. Found by codex hostile fix pass on #24, reproduced against main().
kind: todo
created: 2026-10-10T05:17Z


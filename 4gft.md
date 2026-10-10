# Embargo guard (tools/embargo_guard.py:230, from #25): a FIFO (or other non-regular file) at the default list path makes read_text() block, holding a push indefinitely. Refuse anything that is not a regular file before reading. Found by codex hostile fix pass on #24, reproduced via /proc/self/fd.
kind: todo
created: 2026-10-10T05:17Z


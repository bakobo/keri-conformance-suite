# Latent (Low, codex 2026-10-05): Hello negotiates a Boolean as protocol version 1
kind: todo
tags: latent-defect
created: 2026-10-05T19:53Z

- 2026-10-05T19:53Z Found by a codex hostile pass on PR #6 at the commit Copilot first reviewed; Copilot never reported it. Re-checked on main 2026-10-05: still LIVE. Main-branch evidence: `handle_line(b'{"id":0,"op":"hello","supported":[true]}')` returned a successful result with `"protocol":1`. `hello` still tests `PROTOCOL not in supported` at `adapters/keripy/src/kcs_adapter_keripy/protocol.py:50`. Original finding: 3. Hello negotiates a Boolean as protocol version 1 - class: PROTOCOL - severity: Low - where: adapters/keripy/src/kcs_adapter_keripy/protocol.py:44 - reproduced: YES (`handle_line` with `{"id":0,"op":"hello","supported":[true]}` returned a successful result with `"protocol":1`) - what happens: Python considers `True == 1`, so membership testing accepts a Boolean where the protocol requires an integer version. A peer offering no integer version 1 receives a successful negotiation. Full record: ~/code/me/devenv/.ignored/review-backtest-2026-10-05/latent/keri-conformance-suite-6.result.md

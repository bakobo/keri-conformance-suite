# Clause coverage reports link spec-internal anchors (#RFC4648 etc.) from quoted sentences, which break on the published site; the site build turns anchor checking off because of it. Rewrite or strip spec-relative links when generating docs/coverage/*.md, then re-enable anchor validation in zensical.toml
kind: todo
created: 2026-10-09T16:54Z


# Embargo guard runs rev-list plus two git processes per pushed commit; a push of thousands of commits makes the pre-push hook slow. Batch with one git log -p -z pass if it bites.
kind: debt
tags: embargo-guard
created: 2026-10-05T22:08Z


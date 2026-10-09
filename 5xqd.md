# keri.process reads only the first message of each stream and still delivers the whole stream to keripy, so trailing bytes after a framed event are not treated as unframeable (found while fixing the same weakness in acdc.verify and exn.verify on PR #20). Apply kel.extract's exact mode and recheck the keri-1.0/cesr-1.0/keri-escrow baselines
kind: todo
created: 2026-10-09T17:59Z


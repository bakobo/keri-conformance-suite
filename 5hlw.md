# cesrixir adapter: complete lines queued while a request runs are unbounded in count (hostile pass on #54)
kind: todo
created: 2026-10-15T17:53Z

- 2026-10-15T17:53Z The reader forwards every complete line to the loop, which answers serially; a caller that sends lines faster than they are answered grows the loop's mailbox (each line at most 64 MiB). Declined on #54: an fd port has no flow control, the adapter protocol has the runner send one request at a time, and the container's 2 GiB memory limit bounds it. A fix would be a bounded queue in the reader that answers excess lines in order, which needs the reader and the loop to share ordering of responses.

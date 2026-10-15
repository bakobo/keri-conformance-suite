defmodule KcsAdapterCesrixir.CLI do
  @moduledoc """
  The adapter's main loop. Standard input is read in chunks through a port on file descriptor 0,
  owned by a reader process that splits it into request lines as it arrives, so no more than the
  request limit of any one line is ever held: the bytes of a longer line are dropped as they come.
  The reader sends each complete line, and then end of input, to the loop, which answers each line
  in a fresh process.

  At end of input the loop exits with status 0 once it has answered every complete line. The
  reader also watches for progress then: the loop tells it after every answer, and if `grace_ms`
  milliseconds pass with no answer the reader exits the adapter whatever the loop is doing. The
  grace is longer than the runner's 60-second request timeout, so a request the runner would still
  wait for is never cut short, and a piped batch is answered however long it takes as long as each
  request finishes within the grace. The bound is what stops the container when the runner kills
  the docker client over a hung request, because the client's death closes the container's
  standard input.
  """

  alias KcsAdapterCesrixir.{Errors, Lines, Protocol}

  @grace_ms 65_000

  def grace_ms, do: @grace_ms

  @doc false
  def read(port, lines, loop_pid, halt, grace_ms) do
    receive do
      {^port, {:data, chunk}} ->
        {done, lines} = Lines.feed(lines, chunk)
        # ~5hlw complete lines queue in the loop's mailbox while a request runs
        Enum.each(done, &send(loop_pid, {:split, &1}))
        read(port, lines, loop_pid, halt, grace_ms)

      :answered ->
        read(port, lines, loop_pid, halt, grace_ms)

      {^port, :eof} ->
        send(loop_pid, :eof)
        idle(halt, grace_ms)
    end
  end

  # After end of input: exit once `grace_ms` passes without an answer.
  defp idle(halt, grace_ms) do
    receive do
      :answered -> idle(halt, grace_ms)
    after
      grace_ms -> halt.(0)
    end
  end

  @doc false
  def loop(io) do
    receive do
      {:split, split} ->
        io.write.([Jason.encode!(answer(split)), "\n"])
        io.progress.()
        loop(io)

      :eof ->
        # anything after the last newline is an incomplete request, and is dropped
        io.halt.(0)
    end
  end

  @doc "The response to one split line, computed in a fresh process."
  def answer(split, run \\ &run/1)

  def answer(:oversize, _run), do: Protocol.oversize()

  def answer({:line, line}, run) do
    me = self()
    {pid, ref} =
      spawn_monitor(fn ->
        # cesrixir prints with IO.inspect in places; standard output is reserved for responses
        Process.group_leader(self(), Process.whereis(:standard_error))
        send(me, {:answered, self(), run.(line)})
      end)

    receive do
      {:answered, ^pid, response} ->
        Process.demonitor(ref, [:flush])
        response

      {:DOWN, ^ref, :process, ^pid, reason} ->
        Protocol.answer(Protocol.request_id(line), {:error, Errors.harness(Errors.exception(), "the request's process died: #{inspect(reason)}")})
    end
  end

  @doc "The response to one line, with anything raised turned into a harness error."
  def run(line) do
    Protocol.respond(line)
  rescue
    e ->
      IO.puts(:stderr, Exception.format(:error, e, __STACKTRACE__))
      message = "cesrixir or the adapter raised #{inspect(e.__struct__)}: " <> String.slice(Exception.message(e), 0, 500)
      Protocol.answer(Protocol.request_id(line), {:error, Errors.harness(Errors.exception(), message)})
  end
end

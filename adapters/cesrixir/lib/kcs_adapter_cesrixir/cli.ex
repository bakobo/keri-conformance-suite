defmodule KcsAdapterCesrixir.CLI do
  @moduledoc """
  The adapter's main loop. Standard input is read in chunks through a port on file descriptor 0,
  so a request line is never held beyond the limit. A reader process owns the port and forwards
  chunks and end of input, in order, to the loop, which answers each request in a fresh process.

  At end of input the loop exits with status 0 once it has answered every complete line. The
  reader also starts a timer then, and exits after `grace_ms` milliseconds whatever the loop is
  doing. That bound is what stops the container when the runner kills the docker client over a
  hung request, because the client's death closes the container's standard input.
  """

  alias KcsAdapterCesrixir.{Errors, Lines, Protocol}

  @grace_ms 5_000

  def grace_ms, do: @grace_ms

  @doc false
  def read(port, loop_pid, halt, grace_ms) do
    receive do
      {^port, {:data, chunk}} ->
        send(loop_pid, {:chunk, chunk})
        read(port, loop_pid, halt, grace_ms)

      {^port, :eof} ->
        send(loop_pid, :eof)
        Process.sleep(grace_ms)
        halt.(0)
    end
  end

  @doc false
  def loop(lines, io) do
    receive do
      {:chunk, chunk} ->
        {done, lines} = Lines.feed(lines, chunk)
        Enum.each(done, &io.write.([Jason.encode!(answer(&1)), "\n"]))
        loop(lines, io)

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

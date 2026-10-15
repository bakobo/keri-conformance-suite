defmodule KcsAdapterCesrixir.Main do
  @moduledoc """
  The escript's entry point: wires file descriptors 0 and 1 to the loop in KcsAdapterCesrixir.CLI.
  It touches the real standard input and output, so the in-process tests cannot run it; the stdio
  test runs the built escript instead, and coverage leaves this module out.
  """

  alias KcsAdapterCesrixir.{CLI, Lines}

  def main(_args) do
    loop_pid = self()

    # The reader opens the port itself, so it owns it before any byte arrives; a port opened here
    # and handed over with Port.connect/2 would deliver early input to this process instead.
    reader =
      spawn(fn ->
        port = Port.open({:fd, 0, 1}, [:binary, :stream, :eof])
        send(loop_pid, {:port, port})
        CLI.read(port, Lines.new(), loop_pid, &System.halt/1, CLI.grace_ms())
      end)

    port = receive(do: ({:port, port} -> port))
    CLI.loop(%{write: &Port.command(port, &1), halt: &System.halt/1, progress: fn -> send(reader, :answered) end})
  end
end

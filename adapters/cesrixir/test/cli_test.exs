defmodule KcsAdapterCesrixir.CLITest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO
  alias KcsAdapterCesrixir.{CLI, Lines}

  defp io(test_pid),
    do: %{
      write: &send(test_pid, {:wrote, IO.iodata_to_binary(&1)}),
      halt: &send(test_pid, {:halted, &1}),
      progress: fn -> send(test_pid, :progress) end
    }

  test "the loop answers each split line in order and halts with 0 at end of input" do
    me = self()
    loop = spawn(fn -> CLI.loop(io(me)) end)
    send(loop, {:split, {:line, ~s({"id":1,"op":"hello","protocol":1})}})
    send(loop, {:split, {:line, ~s({"id":2,"op":"x"})}})
    send(loop, :eof)
    assert_receive {:wrote, one}, 5_000
    assert_receive {:wrote, two}, 5_000
    assert %{"id" => 1, "result" => _} = Jason.decode!(one)
    assert %{"id" => 2, "error" => _} = Jason.decode!(two)
    assert String.ends_with?(one, "\n")
    assert_receive {:halted, 0}, 5_000
    assert_received :progress
    refute_received {:wrote, _}
  end

  test "the reader splits input into lines, drops an oversize one as it arrives, and halts after the grace period" do
    port = make_ref()
    me = self()
    reader = spawn(fn -> CLI.read(port, Lines.new(4), me, &send(me, {:halted, &1}), 10) end)
    send(reader, {port, {:data, "ab\nc"}})
    send(reader, {port, {:data, "defghij"}})
    send(reader, {port, {:data, "\nxyz"}})
    send(reader, {port, :eof})
    assert_receive {:split, {:line, "ab"}}
    assert_receive {:split, :oversize}
    assert_receive :eof
    refute_received {:split, _}
    assert_receive {:halted, 0}, 1_000
  end

  test "the grace period outlasts the runner's 60-second request timeout" do
    assert CLI.grace_ms() > 60_000
  end

  test "after end of input each answer restarts the grace period" do
    port = make_ref()
    me = self()
    reader = spawn(fn -> CLI.read(port, Lines.new(), me, &send(me, {:halted, &1}), 150) end)
    send(reader, :answered)
    send(reader, {port, :eof})
    assert_receive :eof
    for _ <- 1..3 do
      Process.sleep(100)
      send(reader, :answered)
    end
    refute_received {:halted, _}
    assert_receive {:halted, 0}, 1_000
  end

  test "an oversize line is answered" do
    assert %{"id" => nil, "error" => %{"message" => "e.input.range.request-size.f: " <> _}} = CLI.answer(:oversize)
  end

  test "an exception raised while answering is a harness error carrying the request's id" do
    err =
      capture_io(:stderr, fn ->
        stream = Base.encode16("-ZZZ", case: :lower)
        assert %{"id" => 4, "error" => %{"kind" => "harness", "message" => "e.self.unknown.exception.f: " <> _}} =
                 CLI.answer({:line, ~s({"id":4,"op":"cesr.parse","stream":"#{stream}"})})
      end)

    assert err =~ "MatchError"
  end

  test "a request process that dies is a harness error" do
    assert %{"id" => 5, "error" => %{"kind" => "harness", "message" => "e.self.unknown.exception.f: " <> _}} =
             CLI.answer({:line, ~s({"id":5})}, fn _ -> exit(:boom) end)
  end

  test "what cesrixir prints goes to standard error, not into the responses" do
    out =
      capture_io(fn ->
        capture_io(:stderr, fn -> CLI.answer({:line, ~s({"id":6})}, fn _ -> IO.puts("noise") && %{"id" => 6} end) end)
      end)

    assert out == ""
  end
end

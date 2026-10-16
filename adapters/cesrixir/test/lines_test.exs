defmodule KcsAdapterCesrixir.LinesTest do
  use ExUnit.Case, async: true
  alias KcsAdapterCesrixir.Lines

  test "splits complete lines and keeps the remainder" do
    {done, st} = Lines.feed(Lines.new(), "a\nbb\nc")
    assert done == [{:line, "a"}, {:line, "bb"}]
    {done, _} = Lines.feed(st, "c\n")
    assert done == [{:line, "cc"}]
  end

  test "joins a line split across many chunks" do
    {[], st} = Lines.feed(Lines.new(), "{\"id\"")
    {[], st} = Lines.feed(st, ":1")
    assert {[{:line, "{\"id\":1}"}], _} = Lines.feed(st, "}\n")
  end

  test "an empty line is a line" do
    assert {[{:line, ""}], _} = Lines.feed(Lines.new(), "\n")
  end

  test "a line over the limit is reported once, when its newline arrives, and the next line is intact" do
    {[], st} = Lines.feed(Lines.new(4), "12345")
    assert st.size == 0 and st.over
    {[], st} = Lines.feed(st, "6789")
    assert {[:oversize, {:line, "ok"}], _} = Lines.feed(st, "0\nok\n")
  end

  test "a line of exactly the limit is accepted" do
    assert {[{:line, "1234"}], _} = Lines.feed(Lines.new(4), "1234\n")
  end

  test "the default limit is 64 MiB" do
    assert Lines.max_request_line() == 64 * 1024 * 1024
    assert Lines.new().max == 64 * 1024 * 1024
  end
end

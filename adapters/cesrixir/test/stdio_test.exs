defmodule KcsAdapterCesrixir.StdioTest do
  @moduledoc """
  Runs the built escript (KCS_ESCRIPT) as the runner does: requests on standard input, responses
  on standard output, end of input ends the session. Skipped when KCS_ESCRIPT is not set; the
  Dockerfile's test stage sets it.
  """
  use ExUnit.Case, async: true

  @escript System.get_env("KCS_ESCRIPT")
  @moduletag skip: if(@escript, do: false, else: "KCS_ESCRIPT is not set")

  defp session(input) do
    path = Path.join(System.tmp_dir!(), "kcs-stdio-#{System.unique_integer([:positive])}")
    File.write!(path, input)
    {out, status} = System.cmd("sh", ["-c", "exec \"$0\" < \"$1\" 2>/dev/null", @escript, path])
    File.rm!(path)
    {out, status}
  end

  test "answers each request on its own line, keeps standard output clean, and exits 0 at end of input" do
    # this stream makes cesrixir print with IO.inspect before it fails
    noisy = Base.encode16("-_AAABAA{\"v\":\"KERI10JSON000023_\",\"t\":\"icp\"}-AAB" <> String.duplicate("A", 4) <> "AABN", case: :lower)

    input =
      Enum.join(
        [
          ~s({"id":0,"op":"hello","protocol":1,"supported":[1]}),
          ~s({"id":1,"op":"cesr.parse","stream":"#{noisy}"}),
          "garbage",
          ~s({"id":2,"op":"cesr.encode","code":"4B","raw":"010203","domain":"text"}),
          ~s({"id":3,"op":"cesr.parse")
        ],
        "\n"
      )

    {out, status} = session(input)
    assert status == 0
    lines = String.split(out, "\n", trim: true)
    decoded = Enum.map(lines, &Jason.decode!/1)
    assert Enum.map(decoded, & &1["id"]) == [0, 1, nil, 2]
  end
end

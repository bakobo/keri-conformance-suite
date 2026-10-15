defmodule KcsAdapterCesrixir.ParseTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO
  import KcsAdapterCesrixir.Vectors
  alias KcsAdapterCesrixir.Parse

  defp parse(stream) do
    {:ok, result} = Parse.parse(stream)
    result
  end

  @genus2 %{"kind" => "genus", "start" => 0, "end" => 8, "code" => "-_AAACAA", "genus" => "AAA", "version" => "2.00"}

  test "a genus code, a count code and its member, at the offsets cesrixir consumed" do
    stream = "-_AAACAA-AAL" <> digest()

    assert parse(stream) == %{
             "items" => [
               @genus2,
               %{"kind" => "counter", "start" => 8, "end" => 12, "code" => "-A", "size" => 11, "group_end" => 56},
               %{"kind" => "primitive", "start" => 12, "end" => 56, "code" => "E", "raw" => String.duplicate("00", 32)}
             ]
           }
  end

  test "a genus 1.00 code is reported with its version" do
    assert %{"items" => [%{"code" => "-_AAABAA", "version" => "1.00", "end" => 8}]} = parse("-_AAABAA")
  end

  test "a 1.x message and a big indexed signature with an ondex, read back from cesrixir's encoding" do
    msg = v1_message()
    stream = msg <> "-AAB" <> sig_2a()
    n = byte_size(msg)

    assert parse(stream) == %{
             "items" => [
               %{"kind" => "message", "start" => 0, "end" => n, "proto" => "KERI", "version" => "1.0", "serialization" => "JSON", "size" => n},
               %{"kind" => "counter", "start" => n, "end" => n + 4, "code" => "-A", "size" => 1, "group_end" => n + 96},
               %{"kind" => "indexed", "start" => n + 4, "end" => n + 96, "code" => "2A", "index" => 3, "ondex" => 5,
                 "raw" => String.duplicate("00", 63) <> "07"}
             ]
           }
  end

  test "a one-character indexed code has no ondex field" do
    %{"items" => [_, _, sig]} = parse(v1_message() <> "-AAB" <> sig_a())
    assert sig["code"] == "A" and sig["index"] == 2
    refute Map.has_key?(sig, "ondex")
  end

  test "a 2.x message's version is its protocol version" do
    %{"items" => [@genus2, msg]} = parse("-_AAACAA" <> v2_message())
    assert %{"version" => "2.0", "proto" => "KERI", "serialization" => "JSON", "start" => 8} = msg
  end

  test "CBOR and MessagePack bodies are framed by their version strings" do
    assert %{"items" => [%{"serialization" => "CBOR", "proto" => "KERI"}]} = parse(v1_message(:cbor))
    assert %{"items" => [%{"serialization" => "MGPK", "proto" => "ACDC"}]} = parse(v1_message(:mgpk, :acdc))
  end

  test "annotations are consumed but are not items" do
    assert %{"items" => [%{"kind" => "genus", "start" => 10, "end" => 18}]} = parse("\n#comment\n-_AAACAA")
  end

  test "a group cesrixir does not re-encode to the same bytes is answered with a summary" do
    # the two bits after the code are pad bits; cesrixir ignores them and re-encodes them as zero
    stream = "-_AAACAA-AALEw" <> String.duplicate("A", 42)
    assert parse(stream) == %{"accepted" => %{"consumed" => 56}}
  end

  test "a group cesrixir cannot re-encode at all is answered with a summary" do
    # a body-plus-attachments group holds a field map, which cesrixir's group encoder cannot encode
    body = v1_message() |> String.replace("icp", "icpx") |> String.replace("000023", "000024")
    assert parse("-UAK" <> body <> "-VAA") == %{"accepted" => %{"consumed" => 44}}
  end

  test "two signatures in one 1.00 group are not re-encoded to the same bytes, so they get a summary" do
    assert %{"accepted" => %{"consumed" => _}} = parse(v1_message() <> "-AAC" <> sig_a() <> sig_2a())
  end

  test "cesrixir's rejection is a rejection, and its message goes to standard error" do
    err = capture_io(:stderr, fn -> assert parse("-JAB1AAM") == %{"reject" => %{"class" => "error"}} end)
    assert err =~ "cesrixir rejected the stream: Cnt Code in not found in table"
    capture_io(:stderr, fn -> assert parse("") == %{"reject" => %{"class" => "error"}} end)
  end

  test "a walk that disagrees with consume_stream is a harness error, not a report" do
    assert {:error, %{"kind" => "harness", "message" => "e.self.unknown.replay-mismatch.f: " <> _}} =
             Parse.report("-_AAACAA", [:keri_aaabaa])

    assert {:error, %{"kind" => "harness"}} = Parse.report("-JAB1AAM", [])
  end

  test "binary-domain encoding uses cesrixir's binary encoder" do
    {:ok, e} = Cesr.Primitive.CD_E_Blake3_256.new(<<0::256>>)
    assert Parse.encode(e, :binary) == Base.url_decode64!(digest())
  end
end

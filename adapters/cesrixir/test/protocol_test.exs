defmodule KcsAdapterCesrixir.ProtocolTest do
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO
  import KcsAdapterCesrixir.Vectors
  alias KcsAdapterCesrixir.Protocol

  defp respond(map), do: Protocol.respond(Jason.encode!(map))

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)

  describe "hello" do
    test "negotiates protocol 1 and says what it is" do
      assert %{"id" => 0, "result" => result} = respond(%{"id" => 0, "op" => "hello", "protocol" => 2, "supported" => [2, 1]})
      assert result["protocol"] == 1
      assert result["operations"] == ["cesr.parse", "cesr.encode"]
      assert result["composes"] == []
      assert result["implementation"]["name"] == "cesrixir"
      assert "cesr.item-extents" in result["features"]
    end

    test "falls back to protocol when supported is absent" do
      assert %{"result" => %{"protocol" => 1}} = respond(%{"id" => 1, "op" => "hello", "protocol" => 1})
    end

    test "refuses when 1 is not offered, and true is not 1" do
      for offer <- [[2], [true], [1.0], "1"] do
        assert %{"id" => 2, "error" => %{"kind" => "unsupported", "message" => "e.feature.unsupported.protocol-version.f: " <> _}} =
                 respond(%{"id" => 2, "op" => "hello", "protocol" => 2, "supported" => offer})
      end
    end

    test "every declared feature is in the suite's vocabulary" do
      suite = System.get_env("KCS_SUITE") || Path.expand("../../..", __DIR__)
      vocabulary = Jason.decode!(File.read!(Path.join(suite, "profiles/features.json")))["features"]
      for feature <- Protocol.features(), do: assert(Map.has_key?(vocabulary, feature), feature)
    end
  end

  describe "requests that cannot be read" do
    test "get an error whose id is null" do
      for line <- ["", "garbage", "[1]", ~s({"op":"hello"}), ~s({"id":-1,"op":"hello"}), ~s({"id":true,"op":"hello"}),
                   ~s({"id":9007199254740992,"op":"hello"}), ~s({"id":1.5,"op":"hello"})] do
        assert %{"id" => nil, "error" => %{"kind" => "harness", "message" => "e.input.format.request.f: " <> _}} = Protocol.respond(line)
      end
    end

    test "the id of a line, when it has a usable one" do
      assert Protocol.request_id(~s({"id":3,"op":"x"})) == 3
      assert Protocol.request_id(~s({"id":-3})) == nil
      assert Protocol.request_id("garbage") == nil
    end

    test "the largest id JSON readers agree on is echoed" do
      assert %{"id" => 9_007_199_254_740_991} = respond(%{"id" => 9_007_199_254_740_991, "op" => "hello", "protocol" => 1})
    end

    test "an error message that is not UTF-8 is escaped, so the response is still JSON" do
      body = KcsAdapterCesrixir.Errors.harness("e.x.f", <<255, 0>>)
      assert body["message"] == "e.x.f: <<255, 0>>"
      assert Jason.encode!(body)
      assert KcsAdapterCesrixir.Errors.unsupported("e.x.f", <<255>>)["message"] == "e.x.f: <<255>>"
    end

    test "an oversize line" do
      assert %{"id" => nil, "error" => %{"kind" => "harness", "message" => "e.input.range.request-size.f: " <> _}} = Protocol.oversize()
    end

    test "a request with no string op, or an op the protocol does not have" do
      assert %{"id" => 3, "error" => %{"message" => "e.input.format.request.f: " <> _}} = respond(%{"id" => 3})
      assert %{"id" => 3, "error" => %{"message" => "e.input.format.request.f: " <> _}} = respond(%{"id" => 3, "op" => 7})
      assert %{"id" => 3, "error" => %{"kind" => "harness", "message" => "e.input.range.unknown-op.f: " <> _}} = respond(%{"id" => 3, "op" => "x"})
    end

    test "operations the adapter does not offer are unsupported" do
      for op <- ["keri.process", "keri.emit", "acdc.verify", "exn.verify"] do
        assert %{"id" => 4, "error" => %{"kind" => "unsupported", "message" => "e.feature.unsupported.undeclared-op.f: " <> _}} =
                 respond(%{"id" => 4, "op" => op})
      end
    end

    test "malformed fields" do
      for req <- [%{"op" => "cesr.parse"}, %{"op" => "cesr.parse", "stream" => "xyz"}, %{"op" => "cesr.parse", "stream" => 5},
                  %{"op" => "cesr.encode", "code" => "E", "raw" => "00", "domain" => "qb64"},
                  %{"op" => "cesr.encode", "code" => 1, "raw" => "00", "domain" => "text"},
                  %{"op" => "cesr.encode", "code" => "E", "raw" => "0", "domain" => "text"}] do
        assert %{"id" => 5, "error" => %{"kind" => "harness", "message" => "e.input.format.request.f: " <> _}} = respond(Map.put(req, "id", 5))
      end
    end
  end

  describe "cesr.parse" do
    test "items" do
      assert %{"id" => 6, "result" => %{"items" => [_, _, _]}} =
               respond(%{"id" => 6, "op" => "cesr.parse", "stream" => hex("-_AAACAA-AAL" <> digest())})
    end

    test "a rejection" do
      capture_io(:stderr, fn ->
        assert %{"id" => 7, "result" => %{"reject" => %{"class" => "error"}}} = respond(%{"id" => 7, "op" => "cesr.parse", "stream" => "2d4a"})
      end)
    end

    test "a summary" do
      assert %{"result" => %{"accepted" => %{"consumed" => 56}}} =
               respond(%{"id" => 8, "op" => "cesr.parse", "stream" => hex("-_AAACAA-AALEw" <> String.duplicate("A", 42))})
    end

    test "a replay mismatch is a harness error" do
      assert {:error, %{"kind" => "harness"}} = KcsAdapterCesrixir.Parse.report("-_AAACAA", [])
    end
  end

  describe "cesr.encode" do
    test "text and binary domains" do
      raw = hex(<<0::256>>)
      assert %{"result" => %{"encoded" => text}} = respond(%{"id" => 9, "op" => "cesr.encode", "code" => "E", "raw" => raw, "domain" => "text"})
      assert Base.decode16!(text, case: :lower) == digest()
      assert %{"result" => %{"encoded" => bin}} = respond(%{"id" => 9, "op" => "cesr.encode", "code" => "E", "raw" => raw, "domain" => "binary"})
      assert Base.decode16!(bin, case: :lower) == Base.url_decode64!(digest())
    end

    test "a variable-size code is found by the module that keeps it" do
      assert %{"result" => %{"encoded" => enc}} = respond(%{"id" => 10, "op" => "cesr.encode", "code" => "4B", "raw" => "010203", "domain" => "text"})
      assert Base.decode16!(enc, case: :lower) == "4BABAQID"
    end

    test "a code cesrixir has no primitive for, and a raw value it refuses" do
      assert %{"error" => %{"kind" => "unsupported", "message" => "e.feature.unsupported.code.f: " <> _}} =
               respond(%{"id" => 11, "op" => "cesr.encode", "code" => "zz", "raw" => "00", "domain" => "text"})

      assert %{"error" => %{"kind" => "unsupported", "message" => "e.input.format.encode-refused.f: " <> _}} =
               respond(%{"id" => 11, "op" => "cesr.encode", "code" => "D", "raw" => "00", "domain" => "text"})
    end
  end
end

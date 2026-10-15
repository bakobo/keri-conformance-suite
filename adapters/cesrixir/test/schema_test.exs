defmodule KcsAdapterCesrixir.SchemaTest do
  @moduledoc """
  Every kind of response the adapter gives, checked against schema/adapter-protocol.schema.json.
  The schema is read from the suite at KCS_SUITE, or from this repository.
  """
  use ExUnit.Case, async: true
  import ExUnit.CaptureIO
  import KcsAdapterCesrixir.Vectors
  alias KcsAdapterCesrixir.{CLI, Protocol}

  @path Path.join(System.get_env("KCS_SUITE") || Path.expand("../../..", __DIR__), "schema/adapter-protocol.schema.json")

  setup_all do
    schema = Jason.decode!(File.read!(@path))
    root = JSV.build!(schema)
    {:ok, root: root, response: JSV.build!(Map.put(schema, "$ref", "#/$defs/response"))}
  end

  defp valid!(%{response: response}, message) do
    # round-trip through JSON, as the runner sees it
    data = Jason.decode!(Jason.encode!(message))
    assert {:ok, _} = JSV.validate(data, response), inspect(message)
  end

  defp parse(stream), do: Protocol.respond(Jason.encode!(%{"id" => 1, "op" => "cesr.parse", "stream" => Base.encode16(stream)}))

  test "hello", ctx do
    valid!(ctx, Protocol.respond(~s({"id":0,"op":"hello","protocol":1,"supported":[1]})))
  end

  test "decoded items of every kind", ctx do
    valid!(ctx, parse("-_AAACAA-AAL" <> digest()))
    valid!(ctx, parse(v1_message() <> "-AAB" <> sig_2a()))
    valid!(ctx, parse(v1_message() <> "-AAB" <> sig_a()))
    valid!(ctx, parse("-_AAACAA" <> v2_message()))
  end

  test "a summary and a rejection", ctx do
    valid!(ctx, parse("-_AAACAA-AALEw" <> String.duplicate("A", 42)))
    capture_io(:stderr, fn -> valid!(ctx, parse("-JAB1AAM")) end)
  end

  test "an encoding", ctx do
    valid!(ctx, Protocol.respond(~s({"id":2,"op":"cesr.encode","code":"4B","raw":"010203","domain":"text"})))
  end

  test "every kind of error", ctx do
    valid!(ctx, Protocol.respond("garbage"))
    valid!(ctx, Protocol.oversize())
    valid!(ctx, Protocol.respond(~s({"id":3,"op":"keri.process"})))
    valid!(ctx, Protocol.respond(~s({"id":3,"op":"hello","supported":[2]})))
    capture_io(:stderr, fn -> valid!(ctx, CLI.answer({:line, ~s({"id":4,"op":"cesr.parse","stream":"2d5a5a5a"})})) end)
  end
end

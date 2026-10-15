defmodule KcsAdapterCesrixir.Errors do
  @moduledoc """
  The codes that begin every error message (bakobo dev/standards/error-codes.md). Every code ends
  in `f`: the same request gives the same answer, so retrying cannot help.
  """

  def malformed, do: "e.input.format.request.f"
  def oversize, do: "e.input.range.request-size.f"
  def unknown_op, do: "e.input.range.unknown-op.f"
  def undeclared_op, do: "e.feature.unsupported.undeclared-op.f"
  def version, do: "e.feature.unsupported.protocol-version.f"
  def code, do: "e.feature.unsupported.code.f"
  def encode_refused, do: "e.input.format.encode-refused.f"
  def commit, do: "e.env.dependency.cesrixir-commit.f"
  def exception, do: "e.self.unknown.exception.f"
  def replay_mismatch, do: "e.self.unknown.replay-mismatch.f"

  @doc "A harness error response body."
  def harness(code, text), do: %{"kind" => "harness", "message" => "#{code}: #{text}"}

  @doc "An unsupported error response body."
  def unsupported(code, text), do: %{"kind" => "unsupported", "message" => "#{code}: #{text}"}
end

defmodule KcsAdapterCesrixir.Protocol do
  @moduledoc """
  Adapter protocol version 1 (docs/adapter-protocol.md): one request line in, one response map out.
  """

  alias KcsAdapterCesrixir.{Encode, Errors, Identity, Parse}

  @features [
    "cesr.domain.binary",
    "cesr.genus-1.00",
    "cesr.genus-2.00",
    "cesr.item-extents",
    "cesr.serialization.cbor",
    "cesr.serialization.json",
    "cesr.serialization.mgpk",
    "keri.version-1.x",
    "keri.version-2.x"
  ]

  @max_id 9_007_199_254_740_991

  def features, do: @features

  @doc "The response to one request line."
  def respond(line) do
    case decode(line) do
      {:ok, request} ->
        case id_of(request) do
          nil -> malformed()
          id -> answer(id, handle(request))
        end

      _ ->
        malformed()
    end
  end

  @doc "The request's id, or nil when the line has no usable one."
  def request_id(line) do
    case decode(line) do
      {:ok, request} -> id_of(request)
      :error -> nil
    end
  end

  defp id_of(%{"id" => id}) when is_integer(id) and id >= 0 and id <= @max_id, do: id
  defp id_of(_), do: nil

  defp malformed,
    do: answer(nil, {:error, Errors.harness(Errors.malformed(), "the request is not a JSON object with an id that is an integer from 0 to 2^53 - 1.")})

  @doc "The response to a line longer than the request limit."
  def oversize do
    answer(nil, {:error, Errors.harness(Errors.oversize(), "a request line was longer than #{KcsAdapterCesrixir.Lines.max_request_line()} bytes and was dropped.")})
  end

  def answer(id, {:ok, result}), do: %{"id" => id, "result" => result}
  def answer(id, {:error, error}), do: %{"id" => id, "error" => error}

  defp decode(line) do
    case Jason.decode(line) do
      {:ok, map} when is_map(map) -> {:ok, map}
      _ -> :error
    end
  end

  defp handle(%{"op" => "hello"} = request) do
    offered = Map.get(request, "supported", [Map.get(request, "protocol")])

    cond do
      not (is_list(offered) and Enum.any?(offered, &(&1 === 1))) ->
        {:error, Errors.unsupported(Errors.version(), "this adapter speaks protocol version 1 only, and the runner did not offer it.")}

      true ->
        with {:ok, implementation} <- Identity.implementation() do
          {:ok,
           %{
             "protocol" => 1,
             "adapter" => Identity.adapter(),
             "implementation" => implementation,
             "operations" => ["cesr.parse", "cesr.encode"],
             "features" => @features,
             "composes" => []
           }}
        end
    end
  end

  defp handle(%{"op" => "cesr.parse"} = request) do
    with {:ok, stream} <- hex_field(request, "stream"), do: Parse.parse(stream)
  end

  defp handle(%{"op" => "cesr.encode"} = request) do
    with {:ok, raw} <- hex_field(request, "raw"),
         {:ok, code} <- string_field(request, "code"),
         {:ok, domain} <- domain_field(request),
         {:ok, encoded} <- Encode.encode(code, raw, domain) do
      {:ok, %{"encoded" => Base.encode16(encoded, case: :lower)}}
    end
  end

  defp handle(%{"op" => op}) when op in ["keri.process", "keri.emit", "acdc.verify", "exn.verify"] do
    {:error, Errors.unsupported(Errors.undeclared_op(), "cesrixir is a CESR library, and this adapter does not offer #{op}.")}
  end

  defp handle(%{"op" => op}) when is_binary(op) do
    {:error, Errors.harness(Errors.unknown_op(), "#{inspect(op)} is not an operation of adapter protocol version 1.")}
  end

  defp handle(_), do: {:error, Errors.harness(Errors.malformed(), "the request has no string op.")}

  defp hex_field(request, name) do
    with {:ok, text} <- string_field(request, name),
         {:ok, bytes} <- Base.decode16(text, case: :mixed) do
      {:ok, bytes}
    else
      _ -> {:error, Errors.harness(Errors.malformed(), "the request's #{name} must be a string of hex digits.")}
    end
  end

  defp string_field(request, name) do
    case Map.get(request, name) do
      text when is_binary(text) -> {:ok, text}
      _ -> {:error, Errors.harness(Errors.malformed(), "the request's #{name} must be a string.")}
    end
  end

  defp domain_field(request) do
    case Map.get(request, "domain") do
      domain when domain in ["text", "binary"] -> {:ok, domain}
      _ -> {:error, Errors.harness(Errors.malformed(), "the request's domain must be \"text\" or \"binary\".")}
    end
  end
end

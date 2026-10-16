defmodule KcsAdapterCesrixir.Encode do
  @moduledoc """
  `cesr.encode`: builds the primitive with cesrixir's own module for the code and serializes it with
  cesrixir's encoder. The module is found in cesrixir's own code tables (its generator modules'
  `typeDescriptions`), never in a table the adapter carries.

  When cesrixir has no primitive for the code, or its constructor refuses the raw value, that is a
  refusal, and the protocol answers it as a rejection (docs/adapter-protocol.md, `cesr.encode`).
  """

  alias Cesr.CesrElement
  alias Cesr.Primitive.Generator.{FourCharFixedPrimitive, OneCharFixedPrimitive, TwoCharFixedPrimitive, VariableLengthPrimitive}
  @doc "Returns `{:ok, encoded_bytes}`, or `{:reject, class}` when cesrixir refuses."
  def encode(code, raw, domain) do
    with {:ok, element} <- build(code, raw) do
      {:ok, if(domain == "binary", do: CesrElement.to_binary(element), else: CesrElement.to_b64(element))}
    end
  end

  defp build(code, raw) do
    case lookup(code, raw) do
      {:fixed, module} -> refused(module.new(raw), code)
      {:variable, element} -> {:ok, element}
      :none ->
        IO.puts(:stderr, "cesrixir has no primitive with the code #{inspect(code)}.")
        {:reject, "unknown-code"}
    end
  end

  defp refused({:ok, element}, _code), do: {:ok, element}

  defp refused({:error, why}, code) do
    IO.puts(:stderr, "cesrixir refused to build a #{code} primitive: #{why}")
    {:reject, "refused"}
  end

  @doc false
  def lookup(code, raw) do
    fixed =
      for gen <- [OneCharFixedPrimitive, TwoCharFixedPrimitive, FourCharFixedPrimitive],
          {^code, short_name, _long, _size} <- gen.typeDescriptions(),
          do: {:fixed, Module.concat(Cesr.Primitive, "CD_#{code}_#{short_name}")}

    # A variable-size module's new/2 checks the code against the module's own list of codes and keeps
    # it only when it is one of them, so the module that keeps it is the one for this code.
    variable =
      for {_selector, module} <- VariableLengthPrimitive.typeDescriptions(),
          {:ok, %{code: ^code} = element} <- [Module.concat(Cesr.Primitive, module).new(raw, code)],
          do: {:variable, element}

    List.first(fixed ++ variable, :none)
  end
end

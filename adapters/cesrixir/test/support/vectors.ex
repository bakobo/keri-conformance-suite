defmodule KcsAdapterCesrixir.Vectors do
  @moduledoc "Streams for the tests, built with cesrixir's own constructors where a body is needed."

  alias Cesr.CesrElement

  def v1_message(kind \\ :json, proto \\ :keri) do
    {:ok, v} = Cesr.Version_String_1.new(%{proto: proto, major: 1, minor: 0, kind: kind, size: 0})
    Cesr.produce_text_stream([OrdMap.new([{"v", v}, {"t", "icp"}])])
  end

  def v2_message do
    {:ok, v} = Cesr.Version_String_2.new(%{proto: :keri, proto_major: 2, proto_minor: 0, genus_major: 2, genus_minor: 0, kind: :json, size: 0})
    Cesr.produce_text_stream([OrdMap.new([{"v", v}, {"t", "icp"}])])
  end

  def sig_a, do: element(Cesr.Primitive.Indexes.IDX_A_Ed25519_Sig.new(<<9::512>>, 2))
  def sig_2a, do: element(Cesr.Primitive.Indexes.IDX_2A_Ed25519_Big_Sig.new(<<7::512>>, 3, 5))
  def digest, do: element(Cesr.Primitive.CD_E_Blake3_256.new(<<0::256>>))

  defp element({:ok, e}), do: CesrElement.to_b64(e)
end

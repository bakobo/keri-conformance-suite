defmodule KcsAdapterCesrixir.Parse do
  @moduledoc """
  `cesr.parse`: cesrixir's verdict on a stream, and the items it decoded.

  The verdict is `Cesr.consume_stream/1`'s, called on the whole stream with no options. To say
  where each item lay, the adapter walks the stream with `Cesr.consume_element/2`, the call
  `consume_stream` itself makes for each top-level element, and checks that the walk produced
  exactly the elements `consume_stream` returned. A top-level element's extent is what
  `consume_element` consumed.

  cesrixir keeps no offsets inside a group. A group's members are placed by the lengths of their
  encodings under cesrixir's own encoder, and only when re-encoding the whole group reproduces the
  stream's bytes over its extent exactly; then every derived offset is where the item cesrixir
  decoded lies on the wire. When the round trip differs, or cesrixir cannot re-encode what it
  decoded, the stream is answered with the protocol's accepted summary instead of offsets the
  adapter cannot vouch for.
  """

  alias Cesr.CesrElement
  alias Cesr.CodeTable.{KeriCodeTableV1, KeriCodeTableV2, KeriIndexCodeTable, UniversalProtocolGenusTable}
  alias Cesr.Index.{OneCharIndexedPrimitiveGenerator, TwoCharIndexedPrimitiveGenerator}
  alias Cesr.Utility.Base64Indicies
  alias KcsAdapterCesrixir.Errors

  @genus_codes ["-_AAABAA", "-_AAACAA"]

  @doc "Returns `{:ok, result}` for the `cesr.parse` result map, or `{:error, error_body}`."
  def parse(stream) do
    case Cesr.consume_stream(stream) do
      {:error, why} ->
        IO.puts(:stderr, "cesrixir rejected the stream: " <> String.slice(why, 0, 2000))
        {:ok, %{"reject" => %{"class" => "error"}}}

      elements when is_list(elements) ->
        report(stream, elements)
    end
  end

  @doc false
  def report(stream, elements) do
    {walked, items, vouched} = walk(stream, 0, :keri_aaabaa, [], [], true)

    cond do
      walked != elements ->
        {:error,
         Errors.harness(
           Errors.replay_mismatch(),
           "walking the stream with Cesr.consume_element/2 gave different elements from Cesr.consume_stream/1, so the adapter cannot say where they lie."
         )}

      vouched ->
        {:ok, %{"items" => items}}

      true ->
        {:ok, %{"accepted" => %{"consumed" => byte_size(stream)}}}
    end
  end

  # Returns {elements, items, vouched?}. Annotations ("" elements) are elements but not items, and
  # consume_stream drops them from its result, so the walk drops them too.
  defp walk(stream, pos, _genus, elements, items, vouched) when pos == byte_size(stream),
    do: {Enum.reverse(elements), Enum.reverse(items), vouched}

  defp walk(stream, pos, genus, elements, items, vouched) do
    rest = binary_part(stream, pos, byte_size(stream) - pos)

    case Cesr.consume_element(rest, genus) do
      {:protocol_genus_switch, new_genus, left} ->
        stop = pos + byte_size(rest) - byte_size(left)
        walk(stream, stop, new_genus, [new_genus | elements], [genus_item(new_genus, pos, stop) | items], vouched)

      {:ok, "", left} ->
        walk(stream, pos + byte_size(rest) - byte_size(left), genus, elements, items, vouched)

      {:ok, %OrdMap{} = map, left} ->
        stop = pos + byte_size(rest) - byte_size(left)
        walk(stream, stop, genus, [map | elements], [message_item(map, pos, stop) | items], vouched)

      {:ok, element, left} ->
        stop = pos + byte_size(rest) - byte_size(left)
        span = binary_part(stream, pos, stop - pos)
        domain = if binary_part(span, 0, 1) == "-", do: :text, else: :binary

        if reencode(element, domain) == span and read_back?(element, pos, domain, stream, genus) do
          {group_items, ^stop} = element_items(element, pos, domain)
          walk(stream, stop, genus, [element | elements], Enum.reverse(group_items, items), vouched)
        else
          walk(stream, stop, genus, [element | elements], items, false)
        end

      {:error, _} ->
        {:error, [], false}
    end
  end

  # The encoder is the adapter's measuring tool here, not the operation under test: cesrixir has
  # already accepted the stream, so an encoder that cannot encode what the decoder returned leaves
  # the adapter unable to vouch for offsets, and the answer is the summary.
  defp reencode(element, domain) do
    encode(element, domain)
  rescue
    _ -> :unencodable
  end

  # Checks each member of a group against cesrixir's decoder: from where the encoding lengths place
  # the member, the code-table reader cesrixir's group consumers call must read back exactly that
  # member and consume exactly its encoding. Nested groups are checked the same way.
  @doc false
  def read_back?(%{cesr_elements: members} = group, pos, domain, stream, genus) do
    header = byte_size(encode(group, domain)) - Enum.sum(Enum.map(members, &byte_size(encode(&1, domain))))

    {agree, _} =
      Enum.reduce(members, {true, pos + header}, fn member, {agree, at} ->
        size = byte_size(encode(member, domain))
        rest = binary_part(stream, at, byte_size(stream) - at)
        left = byte_size(rest) - size
        read = read(reader(member, genus), domain, rest)
        ok = match?({{:ok, ^member}, <<_::binary-size(left)>>}, read) and read_back?(member, at, domain, stream, genus)
        {agree and ok, at + size}
      end)

    agree
  rescue
    _ -> false
  end

  def read_back?(_primitive, _pos, _domain, _stream, _genus), do: true

  defp reader(%{index: _}, _genus), do: KeriIndexCodeTable
  defp reader(_member, :keri_aaabaa), do: KeriCodeTableV1
  defp reader(_member, :keri_aaacaa), do: KeriCodeTableV2

  defp read(table, :text, bytes), do: table.get_T(bytes)
  defp read(table, :binary, bytes), do: table.get_B(bytes)

  @doc false
  def encode(element, :text), do: CesrElement.to_b64(element)
  def encode(element, :binary), do: CesrElement.to_binary(element)

  # The items of one element that starts at pos, in stream order, and where the element ends.
  defp element_items(%{cesr_elements: members} = group, pos, domain) do
    total = byte_size(encode(group, domain))
    header = total - Enum.sum(Enum.map(members, &byte_size(encode(&1, domain))))
    code = "-" <> to_string(CesrElement.properties(group).code)
    text_header = binary_part(CesrElement.to_b64(group), 0, if(domain == :text, do: header, else: div(header * 4, 3)))
    <<_::binary-size(byte_size(code)), digits::binary>> = text_header
    {:ok, size} = Base64Indicies.deserialize_value_in_b64_index_scheme(digits)

    counter = %{"kind" => "counter", "start" => pos, "end" => pos + header, "code" => code, "size" => size, "group_end" => pos + total}

    {member_items, stop} =
      Enum.reduce(members, {[], pos + header}, fn member, {acc, at} ->
        {its, next} = element_items(member, at, domain)
        {Enum.reverse(its, acc), next}
      end)

    {[counter | Enum.reverse(member_items)], stop}
  end

  defp element_items(%{index: index} = sig, pos, domain) do
    stop = pos + byte_size(encode(sig, domain))
    item = %{"kind" => "indexed", "start" => pos, "end" => stop, "code" => sig.code, "raw" => hex(sig.payload), "index" => index}

    item =
      case ondex_size(sig.code) do
        0 ->
          item

        size ->
          # reported as encoded: cesrixir's encoder writes the field, so it is read back from there
          {index_size, _} = index_sizes(sig.code)
          at = String.length(sig.code) + index_size
          {:ok, ondex} = Base64Indicies.deserialize_value_in_b64_index_scheme(binary_part(CesrElement.to_b64(sig), at, size))
          Map.put(item, "ondex", ondex)
      end

    {[item], stop}
  end

  defp element_items(%{code: code, payload: payload} = primitive, pos, domain) when is_binary(code) and is_binary(payload) do
    stop = pos + byte_size(encode(primitive, domain))
    {[%{"kind" => "primitive", "start" => pos, "end" => stop, "code" => code, "raw" => hex(payload)}], stop}
  end

  defp ondex_size(code), do: elem(index_sizes(code), 1)

  # {index size, ondex size} from cesrixir's own indexed code tables
  defp index_sizes(code) do
    one = for {^code, _long, _short, index, _text, _same} <- OneCharIndexedPrimitiveGenerator.typeDescriptions(), do: {index, 0}
    two = for {^code, _long, _short, index, ondex, _text, _same} <- TwoCharIndexedPrimitiveGenerator.typeDescriptions(), do: {index, ondex}
    hd(one ++ two)
  end

  defp genus_item(genus, start, stop) do
    [code] = Enum.filter(@genus_codes, &(UniversalProtocolGenusTable.get_T(&1) == {{:ok, genus}, ""}))
    <<"-_", genus_chars::binary-size(3), major::binary-size(1), minor::binary-size(2)>> = code
    {:ok, major} = Base64Indicies.deserialize_value_in_b64_index_scheme(major)
    {:ok, minor} = Base64Indicies.deserialize_value_in_b64_index_scheme(minor)
    version = "#{major}." <> String.pad_leading(Integer.to_string(minor), 2, "0")
    %{"kind" => "genus", "start" => start, "end" => stop, "code" => code, "genus" => genus_chars, "version" => version}
  end

  defp message_item(map, start, stop) do
    v = OrdMap.get(map, "v")

    {major, minor} =
      case v do
        %Cesr.Version_String_1{major: major, minor: minor} -> {major, minor}
        %Cesr.Version_String_2{proto_major: major, proto_minor: minor} -> {major, minor}
      end

    %{
      "kind" => "message",
      "start" => start,
      "end" => stop,
      "proto" => String.upcase(to_string(v.proto)),
      "version" => "#{major}.#{minor}",
      "serialization" => String.upcase(to_string(v.kind)),
      "size" => v.size
    }
  end

  defp hex(bytes), do: Base.encode16(bytes, case: :lower)
end

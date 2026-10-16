defmodule KcsAdapterCesrixir.Lines do
  @moduledoc """
  Splits standard input into request lines without ever holding more than `max` bytes of one.

  A line longer than `max` bytes, not counting its newline, is reported as `:oversize` once its
  newline arrives, and the bytes beyond the limit are dropped as they arrive.
  """

  @max_request_line 64 * 1024 * 1024

  def max_request_line, do: @max_request_line

  defstruct max: @max_request_line, buf: [], size: 0, over: false

  def new(max \\ @max_request_line), do: %__MODULE__{max: max}

  @doc "Feeds a chunk; returns the completed lines (`{:line, binary}` or `:oversize`) and the new state."
  def feed(%__MODULE__{} = st, chunk), do: feed(st, chunk, [])

  defp feed(st, chunk, out) do
    case :binary.match(chunk, "\n") do
      :nomatch ->
        {Enum.reverse(out), keep(st, chunk)}

      {at, 1} ->
        <<head::binary-size(at), "\n", rest::binary>> = chunk
        st = keep(st, head)
        done = if st.over, do: :oversize, else: {:line, IO.iodata_to_binary(Enum.reverse(st.buf))}
        feed(%{st | buf: [], size: 0, over: false}, rest, [done | out])
    end
  end

  defp keep(%{over: true} = st, _bytes), do: st

  defp keep(st, bytes) do
    size = st.size + byte_size(bytes)
    if size > st.max, do: %{st | buf: [], size: 0, over: true}, else: %{st | buf: [bytes | st.buf], size: size}
  end
end

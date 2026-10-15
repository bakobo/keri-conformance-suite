defmodule KcsAdapterCesrixir.Identity do
  @moduledoc """
  What the adapter reports in `hello` about itself and the implementation it was built against.

  The version is read from the cesrixir application that is actually loaded, never from a constant,
  so a stale build cannot report the pin. hex.pm records no commit, so the commit comes from a
  table of releases checked by hand against vLEIDA/cesrixir; a version missing from it fails
  `hello` rather than report a guess.
  """

  alias KcsAdapterCesrixir.Errors

  @adapter_version "1.0.1-1"

  # hex release -> the vLEIDA/cesrixir commit whose lib/ and mix.exs the release tarball matches
  @commits %{"1.0.1" => "1e4944a25a7f1aa6c00db1192afb930a88aa444e"}

  def adapter, do: %{"name" => "cesrixir-adapter", "version" => @adapter_version}

  def commits, do: @commits

  @doc "The implementation record for `hello`, or an error body when the loaded version has no recorded commit."
  def implementation(version \\ loaded_version()) do
    case Map.fetch(@commits, version) do
      {:ok, commit} ->
        {:ok, %{"name" => "cesrixir", "version" => version, "commit" => commit}}

      :error ->
        {:error,
         Errors.harness(
           Errors.commit(),
           "cesrixir #{inspect(version)} is loaded, and the adapter has no record of the commit it was built from. Pin a release listed in KcsAdapterCesrixir.Identity, or add this one after checking it against vLEIDA/cesrixir."
         )}
    end
  end

  def loaded_version do
    Application.load(:cesrixir)
    to_string(Application.spec(:cesrixir, :vsn))
  end
end

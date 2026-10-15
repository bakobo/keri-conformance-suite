defmodule KcsAdapterCesrixir.MixProject do
  use Mix.Project

  def project do
    [
      app: :kcs_adapter_cesrixir,
      version: "1.0.1-1",
      elixir: "~> 1.19",
      start_permanent: false,
      deps: deps(),
      # -noinput keeps the shell's tty driver off standard input, which the adapter reads itself
      escript: [main_module: KcsAdapterCesrixir.Main, name: "kcs-adapter-cesrixir", emu_args: "-noinput"],
      elixirc_paths: if(Mix.env() == :test, do: ["lib", "test/support"], else: ["lib"]),
      test_coverage: [summary: [threshold: 100], ignore_modules: [KcsAdapterCesrixir.Vectors, KcsAdapterCesrixir.Main]]
    ]
  end

  def application, do: [extra_applications: [:logger]]

  defp deps do
    [
      # cesrixir's own mix.lock pins jason 1.4.4, msgpack 0.8.1, ord_map 0.1.0 and cbor_ordmap 1.0.1
      {:cesrixir, "1.0.1"},
      {:jason, "1.4.4"},
      {:jsv, "~> 0.11", only: :test}
    ]
  end
end

defmodule KcsAdapterCesrixir.IdentityTest do
  use ExUnit.Case, async: true
  alias KcsAdapterCesrixir.Identity

  test "hello reports the loaded cesrixir release and its recorded commit" do
    assert {:ok, %{"name" => "cesrixir", "version" => "1.0.1", "commit" => "1e4944a25a7f1aa6c00db1192afb930a88aa444e"}} =
             Identity.implementation()
  end

  test "a release with no recorded commit fails rather than guess" do
    assert {:error, %{"kind" => "harness", "message" => "e.env.dependency.cesrixir-commit.f: " <> _}} =
             Identity.implementation("9.9.9")
  end

  test "mix.lock pins the cesrixir release the commit table and the loaded application name" do
    lock = File.read!(Path.expand("../mix.lock", __DIR__))
    [_, version, checksum] = Regex.run(~r/"cesrixir": \{:hex, :cesrixir, "([^"]+)", "([0-9a-f]{64})"/, lock)
    assert version == Identity.loaded_version()
    assert Map.has_key?(Identity.commits(), version)
    assert checksum == "3a4e2ee014bf24bd0f881fac3cde2b2d5bd97479c24629dd0f14edfed0ef58c3"
  end

  test "the adapter's version follows the implementation's release" do
    assert %{"name" => "kcs-adapter-cesrixir", "version" => "1.0.1-" <> _} = Identity.adapter()
    assert Mix.Project.config()[:version] == Identity.adapter()["version"]
  end
end

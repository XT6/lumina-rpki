defmodule Lumina.MixProject do
  use Mix.Project

  def project do
    [
      app: :lumina,
      version: "0.1.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      dialyzer: dialyzer()
    ]
  end

  def cli do
    [preferred_envs: [check: :test]]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      extra_applications: [:logger]
    ]
  end

  # Run "mix help deps" to learn about dependencies.
  # test/support holds helpers shared by tests; compiled in the test env only.
  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_env), do: ["lib"]

  # Only development tools go here; Lumina has no runtime dependencies.
  defp deps do
    [
      {:dialyxir, "1.4.8", only: [:dev, :test], runtime: false}
    ]
  end

  defp aliases do
    [
      check: [
        "compile --warnings-as-errors",
        "format --check-formatted",
        "test",
        "lumina.test_catalog --check",
        "lumina.asn1.extract --check",
        "dialyzer"
      ]
    ]
  end

  defp dialyzer do
    [
      plt_core_path: "priv/plts",
      plt_local_path: "priv/plts",
      plt_add_apps: [:mix],
      flags: [:error_handling, :extra_return, :missing_return, :unmatched_returns]
    ]
  end
end

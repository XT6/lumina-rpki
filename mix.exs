defmodule Mix.Tasks.Compile.LuminaAsn1 do
  @moduledoc """
  Compiles the patched ASN.1 modules in `asn1/build/` into Erlang with OTP's
  asn1ct (DER, maps for SEQUENCE/SET values, undecoded rest returned),
  writing them to `gen/asn1/`,
  where the Erlang compiler picks them up. It's defined here because a
  compiler in `lib/` can't run before `lib/` is compiled. See
  `asn1/README.md`.
  """
  use Mix.Task.Compiler

  @source_dir "asn1/build"
  @gen_dir "gen/asn1"

  # :undec_rest makes decode/2 return the bytes left after the value, so
  # trailing data can be rejected: without it, asn1ct ignores it silently.
  @options [:der, :maps, :undec_rest, :noobj]
  @stamp "options"

  @impl true
  def run(_args) do
    sources = Path.wildcard(Path.join(@source_dir, "*.asn1"))

    if stale?(sources) do
      compile_all(sources)
    else
      {:noop, []}
    end
  end

  @impl true
  def manifests, do: []

  @impl true
  def clean, do: File.rm_rf!(@gen_dir)

  # Recompile everything if any module is new, changed or removed: modules
  # import from each other, so a partial recompile could go stale.
  defp stale?(sources) do
    generated = Path.wildcard(Path.join(@gen_dir, "*.erl"))
    expected = Enum.map(sources, &gen_path/1)

    Enum.sort(generated) != Enum.sort(expected) or
      File.read(Path.join(@gen_dir, @stamp)) != {:ok, inspect(@options)} or
      Enum.any?(sources, &(mtime(&1) > mtime(gen_path(&1))))
  end

  defp gen_path(source), do: Path.join(@gen_dir, Path.basename(source, ".asn1") <> ".erl")

  defp mtime(path) do
    case File.stat(path, time: :posix) do
      {:ok, %{mtime: mtime}} -> mtime
      {:error, _} -> 0
    end
  end

  # Modules must be compiled after the modules they import. Rather than keep
  # an order here, compile in passes until every module is done or a pass
  # makes no progress.
  defp compile_all(sources) do
    File.rm_rf!(@gen_dir)
    File.mkdir_p!(@gen_dir)
    Mix.shell().info("Compiling #{length(sources)} ASN.1 modules (asn1/build -> gen/asn1)")
    passes(sources, %{})
  end

  defp passes([], _errors), do: stamp()

  defp passes(pending, _errors) do
    results = Enum.map(pending, &{&1, compile_one(&1)})
    failed = for {source, {:error, reason}} <- results, into: %{}, do: {source, reason}

    cond do
      map_size(failed) == 0 ->
        stamp()

      map_size(failed) == length(pending) ->
        diagnostics =
          for {source, reason} <- failed do
            %Mix.Task.Compiler.Diagnostic{
              compiler_name: "lumina_asn1",
              file: Path.expand(source),
              position: 0,
              message: "asn1ct failed: #{inspect(reason)}",
              severity: :error
            }
          end

        Enum.each(diagnostics, &Mix.shell().error("#{&1.file}: #{&1.message}"))
        {:error, diagnostics}

      true ->
        passes(Map.keys(failed), failed)
    end
  end

  # Records the options, so changing them triggers a full recompile.
  defp stamp do
    File.write!(Path.join(@gen_dir, @stamp), inspect(@options))
    {:ok, []}
  end

  defp compile_one(source) do
    opts = @options ++ [{:outdir, to_charlist(@gen_dir)}, {:i, to_charlist(@gen_dir)}]

    case :asn1ct.compile(to_charlist(source), opts) do
      :ok -> :ok
      {:error, reason} -> {:error, reason}
    end
  end
end

defmodule Lumina.MixProject do
  use Mix.Project

  def project do
    [
      app: :lumina,
      version: "0.1.0",
      elixir: "~> 1.20",
      elixirc_paths: elixirc_paths(Mix.env()),
      # Erlang generated from asn1/build/ by Mix.Tasks.Compile.LuminaAsn1 (above).
      compilers: [:lumina_asn1 | Mix.compilers()],
      erlc_paths: ["gen/asn1"],
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      # Fixture metadata (case.exs) is data, not tests.
      test_ignore_filters: [&String.starts_with?(&1, "test/fixtures/")],
      dialyzer: dialyzer(),
      escript: [main_module: Lumina.CLI, name: "lumina"]
    ]
  end

  def cli do
    [preferred_envs: [check: :test]]
  end

  # Run "mix help compile.app" to learn about applications.
  def application do
    [
      # :asn1 provides asn1ct (compiler) and the runtime the generated
      # decoders use; see asn1/README.md. :ssl and :public_key are for
      # Lumina.HTTPS.
      extra_applications: [:logger, :asn1, :public_key, :ssl]
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
      plt_add_apps: [:mix, :ex_unit],
      flags: [:error_handling, :extra_return, :missing_return, :unmatched_returns],
      ignore_warnings: ".dialyzer_ignore.exs"
    ]
  end
end

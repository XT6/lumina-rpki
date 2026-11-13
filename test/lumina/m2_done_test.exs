defmodule Lumina.M2DoneTest do
  @moduledoc """
  The end-to-end check that closes M2, TAL parsing (#60). It runs every
  TAL Lumina has against the whole M2 pipeline:

    * each Barry fixture's TAL parses, and its TA certificate passes
      `check_ta/2` unless the fixture's metadata says the TA is invalid;
    * each RIR TAL parses, prefers an HTTPS URI (D-003) and prints;
    * the test TAL corpus exercises every parser rule and gives its
      expected outcome;
    * RFC 8630 §2.2, §2.3, §2.4 and §3 are covered by tests other than
      this one.

  The individual behaviours are tested in detail elsewhere (`TALTest`,
  `TALCheckTest`, `TALURIOrderTest`, `TALRIRTest`, `PrintTest`). This
  module checks that they hold together, over all the data at once.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, CLI, TAL}
  alias Mix.Lumina.{Fixtures, RFC, TALCases, TestScanner}

  @rir_dir "test/fixtures/tals/rir"

  defp ta_invalid?(%{expected: {:invalid, problems}}),
    do: Enum.any?(problems, &(&1.object == "ta.cer"))

  defp ta_invalid?(_fixture), do: false

  @tag rfc: ["8630#2.2", "8630#2.3", "8630#3"],
       doc: """
       Driven by the fixture metadata: a fixture whose expected outcome names
       ta.cer as invalid must fail the TA check with one problem; every other
       fixture's TA must pass.
       """
  test "every Barry TA passes against its TAL exactly when its metadata says it should" do
    {fixtures, []} = Fixtures.load_all()

    verdicts =
      for fixture <- fixtures do
        assert {:ok, %TAL{warnings: []} = tal} =
                 TAL.decode_file(Path.join(fixture.dir, "case.tal")),
               fixture.id

        {:ok, ta} = Certificate.decode(File.read!(Path.join([fixture.dir, "rsync", "ta.cer"])))

        if ta_invalid?(fixture) do
          assert {:error, [_one]} = TAL.check_ta(tal, ta), fixture.id
          :invalid
        else
          assert TAL.check_ta(tal, ta) == :ok, fixture.id
          :ok
        end
      end

    assert Enum.count(verdicts, &(&1 == :invalid)) >= 3
    assert Enum.count(verdicts, &(&1 == :ok)) >= 7
  end

  @tag rfc: ["8630#2.2", "8630#3", "8630#4"],
       doc: "All five RIRs publish an HTTPS URI, so D-003 always starts with HTTPS on them."
  test "every RIR TAL parses, is tried HTTPS first, and prints" do
    files = Path.wildcard(Path.join(@rir_dir, "*.tal"))
    assert length(files) == 5

    for file <- files do
      assert {:ok, %TAL{warnings: []} = tal} = TAL.decode_file(file), file
      assert "https://" <> _ = hd(TAL.uris_by_preference(tal)), file
      assert TAL.key_bits(tal) == 2048, file

      {:ok, out} = StringIO.open("")
      {:ok, err} = StringIO.open("")
      assert CLI.run(["print", file], out, err) == 0, file
      assert elem(StringIO.contents(out), 1) =~ "type: tal\n"
    end
  end

  @tag rfc: ["8630#2.2"],
       doc: """
       Every error and warning rule the parser can report is the expected
       outcome of at least one corpus case, and the parser gives it there.
       """
  test "the test TAL corpus exercises every parser rule, each with its expected outcome" do
    {cases, []} = TALCases.load_all()

    seen =
      for tal_case <- cases do
        got =
          case TAL.parse(tal_case.tal) do
            {:ok, %TAL{warnings: []}} ->
              :valid

            {:ok, %TAL{warnings: w}} ->
              {:valid, warnings: Enum.map(w, &Map.take(&1, [:line, :rule]))}

            {:error, finding} ->
              {:invalid, Map.take(finding, [:line, :rule])}
          end

        assert got == tal_case.expected, tal_case.id

        case got do
          :valid -> []
          {:valid, warnings: warnings} -> Enum.map(warnings, & &1.rule)
          {:invalid, %{rule: rule}} -> [rule]
        end
      end

    rules = seen |> List.flatten() |> MapSet.new()

    for rule <- TALCases.error_rules() ++ TALCases.warning_rules(),
        do: assert(rule in rules, "no corpus case gives #{inspect(rule)}")
  end

  @tag doc: """
       The coverage `mix lumina.rfc_coverage --rfc 8630` reports, computed the
       same way, ignoring this module's own tags.
       """
  test "RFC 8630 §2.2, §2.3, §2.4 and §3 are covered by other tests" do
    {modules, []} = TestScanner.scan_dir("test")

    covered =
      for test <- TestScanner.tests(modules),
          test.module != inspect(__MODULE__),
          string <- test.refs,
          {:ok, %{rfc: 8630, section: section}} <- [RFC.parse(string)],
          into: MapSet.new(),
          do: section

    for section <- ["2.2", "2.3", "2.4", "3"],
        do: assert(section in covered, "RFC 8630 §#{section} isn't covered")
  end
end

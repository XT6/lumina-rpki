defmodule Lumina.ManifestEEInheritTest do
  @moduledoc """
  Tests the RFC 9286 §5.1 check on a manifest's EE certificate (#157):
  it "MUST describe its Internet Number Resources (INRs) using the
  'inherit' attribute, rather than an explicit description of a resource
  set (see [RFC3779]). (RPs are required to verify this.)"

  `Lumina.PublicationPoint.process/5` warns
  `manifest_ee_resources_not_inherit` once, naming each kind (IPv4, IPv6,
  AS numbers) the EE certificate lists explicitly. It is a warning, not
  an error, while Barry writes explicit resources on every manifest it
  isn't told about (D-029); a kind left out doesn't warn (D-029). Barry's
  default manifests warn naming all three kinds, `m6-mft-ee-inherit`'s ca1
  manifest inherits every kind, and `m6-mft-ee-explicit-ipv4`'s lists
  IPv4, leaves IPv6 out and inherits AS numbers. Points are processed at
  2030-01-01.
  """
  use ExUnit.Case, async: true

  alias Lumina.{Certificate, CLI, PublicationPoint}
  alias Lumina.Test.{Fixture, RsyncDaemon}

  @now ~U[2030-01-01 00:00:00Z]
  @rule :manifest_ee_resources_not_inherit

  defp point(id, ca, dir) do
    root = Fixture.load!(id).rsync_root
    {:ok, cert} = Certificate.decode(File.read!(Path.join(root, ca)))

    PublicationPoint.process(
      cert,
      Path.join(root, dir),
      "rsync://localhost:8873/rpki/" <> dir,
      @now
    )
  end

  defp ta_point(id), do: point(id, "ta.cer", "ta")
  defp ca1_point(id), do: point(id, "ta/ca1.cer", "ca1")

  defp inherit_warnings(result), do: for(%{rule: @rule} = p <- result.problems, do: p)

  describe "PublicationPoint.process/5" do
    @tag rfc: "9286#5.1",
         doc: "Barry writes explicit IPv4, IPv6 and AS numbers on manifests it isn't told about."
    test "a manifest EE certificate listing every kind explicitly warns once, naming them, and the point is accepted" do
      for result <- [ta_point("m0-minimal-valid"), ca1_point("m0-minimal-valid")] do
        assert result.status == :accepted

        assert [
                 %{
                   rfc: "9286#5.1",
                   field: :resources,
                   severity: :warning,
                   message:
                     "the manifest's EE certificate lists IPv4, IPv6, AS numbers " <>
                       "explicitly instead of using inherit"
                 }
               ] = inherit_warnings(result)
      end
    end

    @tag rfc: ["9286#5.1", "3779#2.2.3.5", "3779#3.2.3.3"]
    test "m6-mft-ee-inherit: a manifest EE certificate inheriting every kind gets no warning" do
      result = ca1_point("m6-mft-ee-inherit")
      assert result.status == :accepted
      assert inherit_warnings(result) == []

      # The TA's manifest isn't declared in the fixture, so it keeps
      # Barry's explicit resources.
      assert [_] = inherit_warnings(ta_point("m6-mft-ee-inherit"))
    end

    @tag rfc: "9286#5.1"
    test "m6-mft-ee-explicit-ipv4: only the kind listed explicitly warns" do
      result = ca1_point("m6-mft-ee-explicit-ipv4")
      assert result.status == :accepted

      assert [%{message: message}] = inherit_warnings(result)

      assert message ==
               "the manifest's EE certificate lists IPv4 explicitly instead of using inherit"
    end

    @tag rfc: "9286#5.1",
         doc: """
         D-029: m6-mft-ee-explicit-ipv4's manifest has no IPv6 at all. §5.1
         asks for inherit "rather than an explicit description", and an
         absent kind describes nothing; RFC 6487 §4.8.10 lets a
         certificate leave a family out.
         """
    test "a kind the manifest EE certificate leaves out doesn't warn" do
      result = ca1_point("m6-mft-ee-explicit-ipv4")
      refute Enum.any?(inherit_warnings(result), &(&1.message =~ "IPv6"))
    end
  end

  describe "lumina validate" do
    @describetag :tmp_dir

    @tag :rsync
    @tag rfc: "9286#5.1"
    test "the warning is shown on the manifest's line, and doesn't change the exit code",
         %{tmp_dir: tmp} do
      fixture = Fixture.load!("m6-mft-ee-inherit")
      daemon = RsyncDaemon.start!(Path.join(tmp, "daemon"), fixture.modules)
      authority = "127.0.0.1:#{daemon.port}"
      tal = Path.join(tmp, "case.tal")

      File.write!(
        tal,
        fixture.tal_path
        |> File.read!()
        |> String.split("\n")
        |> Enum.reject(&String.starts_with?(&1, "https://"))
        |> Enum.map_join("\n", &String.replace(&1, "localhost:8873", authority))
      )

      cache = Path.join(tmp, "cache")
      internal = [now: @now, remap: %{"localhost:8873" => authority}]
      assert {0, _out} = run(["sync", "--cache", cache, "--tal", tal], internal)
      assert {0, out} = run(["validate", "--cache", cache, "--tal", tal], internal)

      assert out =~
               "    warning: rsync://localhost:8873/rpki/ta/ta.mft " <>
                 "(#{@rule}, signature_algorithm_parameters_absent)\n"

      assert out =~
               "    warning: rsync://localhost:8873/rpki/ca1/ca1.mft " <>
                 "(signature_algorithm_parameters_absent)\n"
    end
  end

  defp run(args, internal) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(Lumina.Test.Quiet.args(args), out, err, internal)
    {code, elem(StringIO.contents(out), 1)}
  end
end

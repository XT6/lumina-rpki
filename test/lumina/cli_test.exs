defmodule Lumina.CLITest do
  @moduledoc """
  Tests the `lumina` command line through `Lumina.CLI.run/3`, which returns
  the exit code instead of halting. The CLI follows the command plus flags
  model (D-001 in doc/decisions.md): `lumina print [--brief] FILE...`,
  `lumina help [command]`. Exit codes: 0 success, 1 a file failed to
  decode, 2 usage error. Output goes to StringIO devices.
  """
  use ExUnit.Case, async: true

  alias Lumina.CLI

  @moduletag :tmp_dir

  @roa "test/fixtures/barry/m0-minimal-valid/rsync/ca1/roa1.roa"
  @cer "test/fixtures/barry/m0-minimal-valid/rsync/ta.cer"

  defp run(args) do
    {:ok, out} = StringIO.open("")
    {:ok, err} = StringIO.open("")
    code = CLI.run(args, out, err)
    {code, StringIO.flush(out), StringIO.flush(err)}
  end

  describe "print" do
    test "prints one file in full and exits 0" do
      {code, out, err} = run(["print", @roa])
      assert {code, err} == {0, ""}
      assert out =~ "type: roa (signed object)\n"
      assert out =~ "  digest algorithm: sha256"
      refute out =~ "==>"
    end

    test "--brief leaves out cryptographic detail and keeps the payload" do
      {0, full, ""} = run(["print", @roa])
      {0, brief, ""} = run(["print", "--brief", @roa])

      assert brief =~ "roa:\n  version: 0\n  as id: AS1234\n"
      assert brief =~ "ee certificate validity:\n  not before: 2026-01-01T00:00:00Z\n"
      refute brief =~ "digest"
      refute brief =~ "subject key identifier"
      assert byte_size(brief) < byte_size(full)
    end

    test "--brief may come after the files" do
      assert run(["print", @roa, "--brief"]) == run(["print", "--brief", @roa])
    end

    test "several files print one section each, with a header" do
      {0, out, ""} = run(["print", @cer, @roa])
      assert out =~ "==> #{@cer} <==\ntype: certificate"
      assert out =~ "\n\n==> #{@roa} <==\ntype: roa"
    end

    test "a file that doesn't decode is reported on stderr, and the exit code is 1", %{
      tmp_dir: dir
    } do
      broken = Path.join(dir, "broken.cer")
      File.write!(broken, binary_part(File.read!(@cer), 0, 100))

      {code, out, err} = run(["print", @cer, broken])

      assert code == 1
      assert out =~ "type: certificate"
      assert err =~ "lumina: #{broken}: DER layer:"
    end

    test "an unknown file type and a missing file are decode failures" do
      {1, _, err} = run(["print", "README.md"])
      assert err =~ "is not a registered RPKI file extension"

      {1, _, err} = run(["print", "/nonexistent/x.cer"])
      assert err =~ "file: no such file or directory"
    end

    test "print with no files, or an unknown flag, prints the print usage and exits 2" do
      {2, "", err} = run(["print"])
      assert err =~ "Usage: lumina print [--brief] FILE..."

      {2, "", err} = run(["print", "--bogus", @roa])
      assert err =~ "lumina print: unknown flag --bogus"
    end

    test "print --help shows the print usage" do
      {0, out, ""} = run(["print", "--help"])
      assert out =~ "Usage: lumina print [--brief] FILE..."
    end
  end

  describe "help and usage" do
    test "help, -h and --help print the general usage and exit 0" do
      for args <- [["help"], ["-h"], ["--help"]] do
        {0, out, ""} = run(args)
        assert out =~ "Usage: lumina <command> [flags] [arguments]", inspect(args)
        assert out =~ "print   print RPKI objects"
      end
    end

    test "help <command> prints that command's usage" do
      {0, out, ""} = run(["help", "print"])
      assert out =~ "--brief"

      {2, "", err} = run(["help", "nope"])
      assert err =~ "unknown command \"nope\""
    end

    @tag doc: "The first version used a --print flag (PR #53); under D-001 it's a usage error."
    test "no arguments, an unknown command, or the old --print flag exit 2 with usage" do
      for args <- [[], ["frobnicate"], ["--print", @roa], [@roa]] do
        {code, out, err} = run(args)
        assert {code, out} == {2, ""}, inspect(args)
        assert err =~ "Usage: lumina <command>"
      end
    end
  end
end

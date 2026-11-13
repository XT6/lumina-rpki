defmodule Lumina.CLITest do
  @moduledoc """
  Tests the `lumina` command line through `Lumina.CLI.run/3`, which returns
  the exit code instead of halting: 0 when every file printed, 1 when any
  failed to decode, 2 for usage errors. Output goes to StringIO devices.
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

  test "--print prints one file and exits 0" do
    {code, out, err} = run(["--print", @roa])
    assert {code, err} == {0, ""}
    assert out =~ "type: roa (signed object)\n"
    refute out =~ "==>"
  end

  test "several files print one section each, with a header" do
    {0, out, ""} = run(["--print", @cer, @roa])
    assert out =~ "==> #{@cer} <==\ntype: certificate"
    assert out =~ "\n\n==> #{@roa} <==\ntype: roa"
  end

  test "a file that doesn't decode is reported on stderr and the exit code is 1", %{tmp_dir: dir} do
    broken = Path.join(dir, "broken.cer")
    File.write!(broken, binary_part(File.read!(@cer), 0, 100))

    {code, out, err} = run(["--print", @cer, broken])

    assert code == 1
    assert out =~ "type: certificate"
    assert err =~ "lumina: #{broken}: DER layer:"
  end

  test "an unknown file type and a missing file are decode failures" do
    {1, _, err} = run(["--print", "README.md"])
    assert err =~ "is not a registered RPKI file extension"

    {1, _, err} = run(["--print", "/nonexistent/x.cer"])
    assert err =~ "file: no such file or directory"
  end

  test "--help prints usage to stdout and exits 0" do
    {0, out, ""} = run(["--help"])
    assert out =~ "Usage: lumina --print FILE..."
  end

  test "missing arguments and unknown options print usage to stderr and exit 2" do
    for args <- [[], ["--print"], ["--bogus"], ["--print", "--bogus"], [@roa]] do
      {code, out, err} = run(args)
      assert {code, out} == {2, ""}, inspect(args)
      assert err =~ "Usage: lumina --print FILE..."
    end
  end
end

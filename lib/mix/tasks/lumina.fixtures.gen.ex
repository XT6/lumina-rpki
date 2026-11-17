defmodule Mix.Tasks.Lumina.Fixtures.Gen do
  @shortdoc "Regenerates Barry test fixtures"

  @moduledoc """
  Runs Barry on fixture descriptors and replaces the generated output.

      mix lumina.fixtures.gen                     # every fixture
      mix lumina.fixtures.gen m0-minimal-valid    # one or more fixtures, by id

  For each fixture folder (`test/fixtures/barry/<id>/`) the task removes
  the old `case.tal`, `rsync/` and `rrdp/`, runs Barry on `case.repo` with
  the fixture's validity period and a version 4 UUID RRDP session derived
  from its id, then checks the fixture's metadata and output. It fails if
  Barry fails or a fixture doesn't pass the check. A fixture with
  `case.v2.repo` (`case.v3.repo`, ...) gets RRDP deltas between its
  versions (`barry-delta`); see `doc/testing.md`.

  Barry generates fresh keys on every run, so regenerated files differ byte
  for byte from the committed ones. The validity period is fixed (see
  `Mix.Lumina.Fixtures.default_barry_opts/0`), so fixtures don't expire.

  Barry is taken from `_tools/bin/barry` (see `doc/barry.md`), or from
  `$LUMINA_TOOLS/bin/barry`.

  ## Options

    * `--dir` - fixture root (default: `test/fixtures/barry`)
  """

  use Mix.Task

  alias Mix.Lumina.{Fixtures, RFC}

  @impl Mix.Task
  def run(args) do
    {opts, ids} = OptionParser.parse!(args, strict: [dir: :string])
    root = Keyword.get(opts, :dir, Fixtures.dir())
    barry = barry_path()
    library = RFC.load_library()

    case_dirs = select(root, ids)

    if case_dirs == [] do
      Mix.shell().info("No fixtures found under #{root}.")
    end

    problems =
      Enum.flat_map(case_dirs, fn case_dir ->
        generate!(case_dir, barry)

        case Fixtures.load(case_dir, library) do
          {:ok, fixture} ->
            Mix.shell().info("generated #{fixture.id}")
            []

          {:error, problems} ->
            problems
        end
      end)

    if problems != [] do
      Enum.each(problems, &Mix.shell().error("#{&1.file}: #{&1.message}"))
      Mix.raise("#{length(problems)} fixture problem(s)")
    end
  end

  @doc """
  Regenerates one fixture folder with the Barry binary at `barry`.

  Every run adds a `[notification: ...]` section for the fixture's
  notification URI with `session = Fixtures.session_id(id)`, a fixed
  version 4 UUID (RFC 8182 §3.5.1.3; Barry's default "1" isn't a UUID,
  F-038). A fixture with `case.v2.repo` (and `case.v3.repo`, ...) is
  generated version by version with `barry-delta` (see `versions!/5`).
  """
  @spec generate!(Path.t(), Path.t()) :: :ok
  def generate!(case_dir, barry) do
    unless File.regular?(Path.join(case_dir, "case.repo")) do
      Mix.raise("#{case_dir}: missing case.repo")
    end

    {meta, opts} =
      case Fixtures.read_metadata(case_dir) do
        {:ok, meta} -> {meta, Fixtures.barry_opts(meta)}
        {:error, message} -> Mix.raise("#{Fixtures.meta_path(case_dir)}: #{message}")
      end

    descriptors =
      case Fixtures.descriptors(case_dir) do
        {:ok, descriptors} -> descriptors
        {:error, message} -> Mix.raise("#{case_dir}: #{message}")
      end

    session = Fixtures.session_id(Map.get(meta, :id, Path.basename(case_dir)))
    work = Path.join(case_dir, ".gen")

    Enum.each(["case.tal", "rsync", "rrdp", ".gen"], &File.rm_rf!(Path.join(case_dir, &1)))
    File.mkdir_p!(work)

    _ =
      try do
        case descriptors do
          [single] ->
            File.write!(Path.join(work, "case.repo"), descriptor(case_dir, single, session, nil))

            barry!(case_dir, barry, [
              "--now=#{opts[:now]}",
              "--later=#{opts[:later]}",
              "--tal-path=case.tal",
              ".gen/case.repo"
            ])

          _ ->
            versions!(case_dir, barry, descriptors, session, opts)
        end
      after
        File.rm_rf!(work)
      end

    :ok
  end

  # The descriptor Barry runs: the fixture's, plus the notification's
  # session and, for an earlier version, its own snapshot URI.
  defp descriptor(case_dir, file, session, snapshot_uri) do
    text = File.read!(Path.join(case_dir, file))

    if text =~ ~r/^\[notification:/m do
      Mix.raise(
        "#{case_dir}/#{file}: declares a [notification: ...] section; the generator adds it"
      )
    end

    Enum.join([
      text,
      "\n\n[notification: #{Fixtures.notification_uri()}]\n",
      "session = #{session}\n",
      if(snapshot_uri, do: "snapshot.uri = #{snapshot_uri}\n", else: "")
    ])
  end

  # Versions 1..N of a delta fixture, each a Barry run with --serial K, an
  # hour later than the one before (so a changed manifest moves forward),
  # the previous version's rsync tree as --previous-path (for the shield
  # marker) and a shared key pool (so a shielded certificate's children
  # can still be signed). barry-delta then chains the notifications.
  # Output: rsync/ and case.tal of version N; rrdp/ with notification.xml
  # and snapshot.xml (version N), notification-K.xml and snapshot-K.xml
  # (K < N, as served at serial K), delta-K.xml (K = 2..N) and ta.cer.
  defp versions!(case_dir, barry, descriptors, session, opts) do
    n = length(descriptors)
    rrdp = Path.join(case_dir, "rrdp")
    base = Fixtures.notification_uri() |> String.replace_suffix("notification.xml", "")
    {:ok, now, 0} = DateTime.from_iso8601(opts[:now])

    _ =
      key_pool!(Path.join(case_dir, ".gen/keys"), Enum.map(descriptors, &Path.join(case_dir, &1)))

    File.mkdir_p!(rrdp)

    for {file, k} <- Enum.with_index(descriptors, 1) do
      snapshot = if k < n, do: base <> "snapshot-#{k}.xml"

      File.write!(
        Path.join(case_dir, ".gen/v#{k}.repo"),
        descriptor(case_dir, file, session, snapshot)
      )

      previous = if k > 1, do: ["--previous-path=.gen/rsync#{k - 1}/"], else: []

      barry!(
        case_dir,
        barry,
        [
          "--serial=#{k}",
          "--now=#{now |> DateTime.add(k - 1, :hour) |> DateTime.to_iso8601()}",
          "--later=#{opts[:later]}",
          "--keys=.gen/keys",
          "--tal-path=.gen/#{k}.tal",
          "--rsync-path=.gen/rsync#{k}/",
          "--rrdp-path=.gen/rrdp#{k}/"
        ] ++ previous ++ [".gen/v#{k}.repo"]
      )

      if k > 1 do
        previous_notification =
          if k == 2, do: ".gen/rrdp1/notification.xml", else: ".gen/notification#{k - 1}.xml"

        delta = Path.join(Path.dirname(barry), "barry-delta")

        args = [
          "--old.notification=#{previous_notification}",
          "--old.snapshot=.gen/rrdp#{k - 1}/snapshot.xml",
          "--new.notification=.gen/rrdp#{k}/notification.xml",
          "--new.snapshot=.gen/rrdp#{k}/snapshot.xml",
          "--output.notification=.gen/notification#{k}.xml",
          "--output.delta.path=rrdp/delta-#{k}.xml",
          "--output.delta.uri=#{base}delta-#{k}.xml"
        ]

        case System.cmd(delta, args, cd: case_dir, stderr_to_stdout: true) do
          {_output, 0} ->
            :ok

          {output, status} ->
            Mix.raise("#{case_dir}: barry-delta exited with #{status}:\n#{output}")
        end
      end
    end

    gen = &Path.join([case_dir, ".gen", &1])
    _ = File.cp_r!(gen.("rsync#{n}"), Path.join(case_dir, "rsync"))
    File.cp!(gen.("#{n}.tal"), Path.join(case_dir, "case.tal"))
    File.cp!(gen.("rrdp1/ta.cer"), Path.join(rrdp, "ta.cer"))
    File.cp!(gen.("rrdp#{n}/snapshot.xml"), Path.join(rrdp, "snapshot.xml"))
    File.cp!(gen.("notification#{n}.xml"), Path.join(rrdp, "notification.xml"))

    for k <- 1..(n - 1)//1 do
      notification = if k == 1, do: "rrdp1/notification.xml", else: "notification#{k}.xml"
      File.cp!(gen.(notification), Path.join(rrdp, "notification-#{k}.xml"))
      File.cp!(gen.("rrdp#{k}/snapshot.xml"), Path.join(rrdp, "snapshot-#{k}.xml"))
    end
  end

  defp barry!(case_dir, barry, args) do
    case System.cmd(barry, args, cd: case_dir, stderr_to_stdout: true) do
      {_output, 0} -> :ok
      {output, status} -> Mix.raise("#{case_dir}: barry exited with #{status}:\n#{output}")
    end
  end

  # Barry's --keys: a directory of RSA key pairs, the one for a file chosen
  # by the first four bytes of the SHA-1 of its name (little-endian), modulo
  # the number of keys (`keys_new` in Barry's keys.c). The pool is made
  # just large enough that every object in the descriptors gets its own.
  defp key_pool!(dir, descriptors) do
    names = descriptors |> Enum.flat_map(&tree_names/1) |> Enum.uniq()

    size =
      Enum.find(max(length(names), 2)..4096, fn size ->
        indices = Enum.map(names, &key_index(&1, size))
        length(Enum.uniq(indices)) == length(indices)
      end)

    File.mkdir_p!(dir)

    for i <- 1..size do
      key = :public_key.generate_key({:rsa, 2048, 65_537})
      pem = :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, key)])
      File.write!(Path.join(dir, "key#{String.pad_leading("#{i}", 4, "0")}.pem"), pem)
    end
  end

  defp key_index(name, size) do
    <<index::little-unsigned-32, _::binary>> = :crypto.hash(:sha, name)
    rem(index, size)
  end

  # The file names in a descriptor's tree: the lines before the first
  # [section], less the shield marker.
  defp tree_names(path) do
    path
    |> File.read!()
    |> String.split("\n")
    |> Enum.take_while(&(not String.starts_with?(&1, "[")))
    |> Enum.map(&(&1 |> String.replace("\u{1F6E1}\u{FE0F}", "") |> String.trim()))
    |> Enum.reject(&(&1 == "" or String.starts_with?(&1, "#")))
    |> Enum.map(&(&1 |> String.split() |> hd()))
  end

  @doc "Path of the Barry binary."
  @spec barry_path() :: Path.t()
  def barry_path do
    tools = System.get_env("LUMINA_TOOLS") || Path.expand("_tools")
    path = Path.join([tools, "bin", "barry"])

    if File.regular?(path),
      do: path,
      else:
        Mix.raise("Barry not found at #{path}. Run scripts/install-barry.sh (see doc/barry.md).")
  end

  defp select(root, []), do: Fixtures.case_dirs(root)

  defp select(root, ids) do
    for id <- ids do
      case_dir = Path.join(root, id)

      if File.dir?(case_dir),
        do: case_dir,
        else: Mix.raise("no fixture #{inspect(id)} in #{root}")
    end
  end
end

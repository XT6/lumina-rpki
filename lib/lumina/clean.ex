defmodule Lumina.Clean do
  @moduledoc """
  Empties the cache, or removes what some TALs' trees use from it
  (`lumina clean`, #226, D-047).

  `plan/2` says what would go and `remove/2` removes it; the caller holds
  the cache's lock (`Lumina.Sync.with_lock/2`) across both, so no sync
  runs in between.

    * `:all`: everything under the cache directory but the lock, files
      no TAL claims included (those of a TAL no longer in `./tals/`). The
      directory itself stays.
    * `[{path, %TAL{}}]`: for each TAL, its stored TA (`.ta/<ski>.cer` and
      `.json`) and sync record, and from the tree that record lists
      (`Lumina.Sync.tree/2`): its rsync modules (the mirror and their
      fetch records under `.status`), its RRDP repositories (store and
      state), and per publication point the last valid copy, the source
      record and the manifest state. What the tree of a TAL not being
      cleaned also uses stays (#102: a module several trees share). The
      status records of the TAL's own URIs go too, unless another TAL
      lists them.

  A TAL never synced into the cache has nothing to remove (`never_synced`).
  One synced by a Lumina before 0.8.1 has no tree recorded
  (`tree_unknown`): only its TA and record go. If another TAL's record
  has no tree, nothing a tree uses can be known to be unshared, so every
  repository is kept (`others_unknown`).
  """

  alias Lumina.{LastValid, Source, Sync, TAL, URI}
  alias Lumina.RRDP.{State, Store}

  @type tal_plan :: %{
          path: Path.t(),
          never_synced: boolean(),
          tree_unknown: boolean(),
          ta: boolean(),
          modules: non_neg_integer(),
          notifications: non_neg_integer(),
          points: non_neg_integer(),
          shared: non_neg_integer()
        }

  @type plan :: %{
          paths: [Path.t()],
          files: non_neg_integer(),
          bytes: non_neg_integer(),
          tals: [tal_plan()] | :all,
          others_unknown: boolean()
        }

  @doc """
  What cleaning `what` (`:all` or `[{path, %TAL{}}]`) would remove from
  the cache at `root`: the `paths` (files and directories), how many
  `files` and `bytes` they hold, and per TAL what they are.
  """
  @spec plan(Path.t(), :all | [{Path.t(), TAL.t()}]) :: plan()
  def plan(root, :all) do
    paths =
      case File.ls(root) do
        {:ok, names} -> for name <- Enum.sort(names), name != ".lock", do: Path.join(root, name)
        {:error, _} -> []
      end

    sized(%{paths: paths, tals: :all, others_unknown: false})
  end

  def plan(root, tals) do
    trees = Sync.trees(root)
    files = MapSet.new(tals, fn {_path, tal} -> Sync.record_file(root, tal) end)
    others = for {file, tree} <- trees, file not in files, do: tree
    others_unknown = Enum.any?(others, &is_nil/1)
    kept = others |> Enum.reject(&is_nil/1) |> union()
    states = manifest_states(root)

    {tal_plans, paths} =
      Enum.map_reduce(tals, [], fn {path, tal}, acc ->
        {ta, ta_paths} = ta_paths(root, tal)
        record = Sync.record_file(root, tal)
        recorded = File.exists?(record)
        tree = trees[record]

        {owned, shared} =
          if tree && not others_unknown, do: owned(tree, kept), else: {empty(), 0}

        tal_paths =
          ta_paths ++
            if(recorded, do: [record], else: []) ++
            Enum.flat_map(owned.tal_uris, &status_paths(root, &1)) ++
            Enum.flat_map(owned.modules, &module_paths(root, &1)) ++
            Enum.flat_map(owned.notifications, &rrdp_paths(root, &1)) ++
            Enum.flat_map(owned.manifests, &point_paths(root, &1, states))

        plan = %{
          path: path,
          never_synced: not ta and not recorded,
          tree_unknown: recorded and tree == nil,
          ta: ta,
          modules: length(owned.modules),
          notifications: length(owned.notifications),
          points: length(owned.manifests),
          shared: shared
        }

        {plan, acc ++ tal_paths}
      end)

    paths = paths |> Enum.filter(&exists?/1) |> Enum.uniq()
    sized(%{paths: paths, tals: tal_plans, others_unknown: others_unknown and tals != []})
  end

  @doc """
  Removes a plan's paths from the cache at `root`, then the directories
  left empty up to `root`. Returns `:ok` or the first path that couldn't
  be removed, with the reason; the rest are still tried.
  """
  @spec remove(Path.t(), plan()) :: :ok | {:error, Path.t(), File.posix()}
  def remove(root, %{paths: paths}) do
    root = Path.expand(root)

    failed =
      Enum.flat_map(paths, fn path ->
        case File.rm_rf(path) do
          {:ok, _} ->
            prune(Path.dirname(Path.expand(path)), root)
            []

          {:error, reason, file} ->
            [{:error, file, reason}]
        end
      end)

    List.first(failed, :ok)
  end

  defp sized(plan) do
    {files, bytes} =
      Enum.reduce(plan.paths, {0, 0}, fn path, {f, b} ->
        {pf, pb} = usage(path)
        {f + pf, b + pb}
      end)

    Map.merge(plan, %{files: files, bytes: bytes})
  end

  # Regular files under `path` (links aren't followed) and their bytes.
  defp usage(path) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :directory}} ->
        case File.ls(path) do
          {:ok, names} ->
            Enum.reduce(names, {0, 0}, fn name, {f, b} ->
              {nf, nb} = usage(Path.join(path, name))
              {f + nf, b + nb}
            end)

          {:error, _} ->
            {0, 0}
        end

      {:ok, %File.Stat{type: :regular, size: size}} ->
        {1, size}

      {:ok, _other} ->
        {1, 0}

      {:error, _} ->
        {0, 0}
    end
  end

  defp exists?(path), do: match?({:ok, _}, File.lstat(path))

  defp prune(dir, root) do
    if String.starts_with?(dir, root <> "/") and File.rmdir(dir) == :ok,
      do: prune(Path.dirname(dir), root)
  end

  defp empty, do: %{tal_uris: [], modules: [], notifications: [], manifests: []}

  defp union(trees) do
    Enum.reduce(trees, empty(), fn tree, acc ->
      Map.new(acc, fn {key, list} -> {key, list ++ Map.get(tree, key, [])} end)
    end)
    |> Map.new(fn {key, list} -> {key, MapSet.new(list)} end)
  end

  # The tree's entries no other tree lists, and how many repositories
  # (modules and notification URIs) are kept as shared.
  defp owned(tree, kept) do
    owned = Map.new(tree, fn {key, list} -> {key, Enum.reject(list, &(&1 in kept[key]))} end)

    shared =
      length(tree.modules) - length(owned.modules) +
        (length(tree.notifications) - length(owned.notifications))

    {owned, shared}
  end

  defp ta_paths(root, tal) do
    base =
      Path.join([root, ".ta", Base.encode16(TAL.subject_key_identifier(tal), case: :lower)])

    paths = [base <> ".cer", base <> ".json"]
    {File.exists?(hd(paths)), paths}
  end

  # A fetch's status record, and for a directory those of what's in it.
  defp status_paths(root, uri) do
    case URI.parse(uri) do
      {:ok, uri} ->
        path = URI.cache_path(uri, Path.join(root, ".status"))
        [path, path <> ".json"]

      {:error, _} ->
        []
    end
  end

  defp module_paths(root, module) do
    case URI.parse(module) do
      {:ok, uri} -> [URI.cache_path(uri, root) | status_paths(root, module)]
      {:error, _} -> []
    end
  end

  defp rrdp_paths(root, notify) do
    case URI.parse(notify) do
      {:ok, uri} -> [Store.path(root, uri), State.file(root, uri)]
      {:error, _} -> []
    end
  end

  defp point_paths(root, manifest, states) do
    List.wrap(LastValid.dir(root, manifest)) ++
      [Source.file(root, manifest)] ++ Map.get(states, manifest, [])
  end

  # The manifest state files (`Lumina.ManifestState`, keyed by CA), by
  # the manifest URI each records.
  defp manifest_states(root) do
    root
    |> Path.join(".state/manifests/*.json")
    |> Path.wildcard()
    |> Enum.reduce(%{}, fn file, acc ->
      with {:ok, text} <- File.read(file),
           {:ok, %{"manifest" => manifest}} <- JSON.decode(text) do
        Map.update(acc, manifest, [file], &[file | &1])
      else
        _ -> acc
      end
    end)
  end
end

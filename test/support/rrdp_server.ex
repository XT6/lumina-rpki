defmodule Lumina.Test.RRDPServer do
  @moduledoc """
  An RRDP repository for tests of `Lumina.RRDP.Sync` (#203, #204):
  `Lumina.Test.HTTPSServer` with its routes (path => response) in an
  Agent, so a test can change what is served between syncs and see which
  paths were requested, plus builders for hand-made notification,
  snapshot and delta files and readers for a store and a fixture's
  snapshot.

      server = RRDPServer.start!(RRDPServer.routes(fixture))
      Lumina.RRDP.Sync.run(fixture.notification_uri, root, server.opts)
      RRDPServer.serve(server, other_routes)
      RRDPServer.requested(server)   # paths requested since serve/2

  `server.opts` connect `localhost:8443`, the host in the fixtures' URIs,
  to the server, trust its certificate, fix `:now`, and turn off the
  once-a-minute polling limit (`min_interval: 0`), since tests sync the
  same repository several times at one `:now`.
  """

  alias Lumina.RRDP.{Snapshot, Store}

  @namespace ~s(xmlns="http://www.ripe.net/rpki/rrdp" version="1")

  @doc "Starts a server with `routes`; returns `%{agent, port, opts}`."
  def start!(routes, now \\ ~U[2030-01-01 00:00:00Z]) do
    agent = ExUnit.Callbacks.start_supervised!({Agent, fn -> %{routes: routes, log: []} end})
    pki = Lumina.Test.HTTPSServer.pki()

    port =
      Lumina.Test.HTTPSServer.start!(pki, fn request ->
        route =
          Agent.get_and_update(agent, fn state ->
            {Map.get(state.routes, request.path, {404, [], "not found"}),
             %{state | log: state.log ++ [request.path]}}
          end)

        if is_function(route, 1), do: route.(request), else: route
      end)

    %{
      agent: agent,
      port: port,
      opts: [
        cacerts: pki.cacerts,
        remap: %{"localhost:8443" => "localhost:#{port}"},
        now: now,
        min_interval: 0
      ]
    }
  end

  @doc "Replaces the routes and clears the request log."
  def serve(server, routes), do: Agent.update(server.agent, &%{&1 | routes: routes, log: []})

  @doc "The paths requested since the server started or `serve/2`."
  def requested(server), do: Agent.get(server.agent, & &1.log)

  @doc """
  A fixture's `rrdp/` files under `/rrdp/`; with `serial`, its notification
  of that serial (`notification-K.xml`) is the one served.
  """
  def routes(fixture, serial \\ nil) do
    routes = Lumina.Test.HTTPSServer.dir_routes(fixture.rrdp_root, "/rrdp/")

    if serial && serial < map_size(fixture.versions),
      do:
        Map.put(
          routes,
          "/rrdp/notification.xml",
          {:file, Path.join(fixture.rrdp_root, "notification-#{serial}.xml")}
        ),
      else: routes
  end

  @doc "The lowercase hex SHA-256 of `bytes`."
  def hash(bytes), do: :sha256 |> :crypto.hash(bytes) |> Base.encode16(case: :lower)

  @doc """
  A notification file: `snapshot` and each delta are `{uri, bytes}` (the
  hash is computed) or `{uri, hex hash}` given as `{uri, {:hash, hex}}`;
  deltas are `{serial, uri, bytes_or_hash}`.
  """
  def notification(session, serial, {snapshot_uri, snapshot}, deltas \\ []) do
    """
    <notification #{@namespace} session_id="#{session}" serial="#{serial}">
      <snapshot uri="#{snapshot_uri}" hash="#{hex(snapshot)}"/>
    #{for {k, uri, file} <- deltas, do: ~s(  <delta serial="#{k}" uri="#{uri}" hash="#{hex(file)}"/>\n)}\
    </notification>
    """
  end

  @doc "A snapshot file publishing `objects`, `[{rsync uri, bytes}]`."
  def snapshot(session, serial, objects) do
    """
    <snapshot #{@namespace} session_id="#{session}" serial="#{serial}">
    #{for {uri, bytes} <- objects, do: ~s(  <publish uri="#{uri}">#{Base.encode64(bytes)}</publish>\n)}\
    </snapshot>
    """
  end

  @doc """
  A delta file with `elements`: `{:publish, uri, bytes}`,
  `{:publish, uri, bytes, old_bytes_or_hash}` and
  `{:withdraw, uri, old_bytes_or_hash}`.
  """
  def delta(session, serial, elements) do
    """
    <delta #{@namespace} session_id="#{session}" serial="#{serial}">
    #{for element <- elements, do: element(element)}\
    </delta>
    """
  end

  defp element({:publish, uri, bytes}),
    do: ~s(  <publish uri="#{uri}">#{Base.encode64(bytes)}</publish>\n)

  defp element({:publish, uri, bytes, old}),
    do: ~s(  <publish uri="#{uri}" hash="#{hex(old)}">#{Base.encode64(bytes)}</publish>\n)

  defp element({:withdraw, uri, old}), do: ~s(  <withdraw uri="#{uri}" hash="#{hex(old)}"/>\n)

  defp hex({:hash, hex}), do: hex
  defp hex(bytes), do: hash(bytes)

  @doc "The store of `notify` in `root`: path relative to the store => bytes."
  def store_files(root, notify) do
    store = Store.path(root, notify)

    for path <- Path.wildcard(Path.join(store, "**/*"), match_dot: true),
        File.regular?(path),
        into: %{},
        do: {Path.relative_to(path, store), File.read!(path)}
  end

  @doc """
  The objects of a fixture's snapshot file (`snapshot.xml` by default), as
  `store_files/2` lays them out.
  """
  def snapshot_files(fixture, file \\ "snapshot.xml") do
    path = Path.join(fixture.rrdp_root, file)
    [_, serial] = Regex.run(~r/serial="(\d+)"/, File.read!(path))
    expected = %{session_id: fixture.session_id, serial: String.to_integer(serial)}

    collect = fn {:publish, uri, bytes}, acc ->
      {:cont, Map.put(acc, Path.relative_to(Store.object_path("/s", uri), "/s"), bytes)}
    end

    {:ok, files} = Snapshot.stream(path, expected, collect, %{})
    files
  end
end

defmodule Lumina.Test.RsyncDaemon do
  @moduledoc ~S"""
  Runs a real `rsync --daemon` for tests tagged `:rsync`, serving local
  directories as rsync modules on 127.0.0.1 and a free port.

      daemon = Lumina.Test.RsyncDaemon.start!(tmp_dir, %{"rpki" => fixture.rsync_root})
      "rsync://127.0.0.1:#{daemon.port}/rpki/ta.cer"

  The daemon is stopped when the test exits. Each test gets its own daemon
  and port, so `:rsync` tests can run concurrently. Modules are read-only
  and served without chroot, so no privileges are needed.
  """

  import ExUnit.Callbacks, only: [on_exit: 1]

  @type t :: %{port: :inet.port_number(), pid_file: Path.t()}

  @doc """
  Starts a daemon serving `modules` (name => directory) and waits until it
  accepts connections. Option `:max_connections` limits the connections
  the daemon accepts at once, over all its modules (they share one lock
  file); it refuses the rest.
  """
  @spec start!(Path.t(), %{String.t() => Path.t()}, keyword()) :: t()
  def start!(work_dir, modules, opts \\ []) do
    dir = Path.join(work_dir, "rsyncd")
    File.mkdir_p!(dir)
    port = free_port()
    pid_file = Path.join(dir, "rsyncd.pid")
    config = Path.join(dir, "rsyncd.conf")

    File.write!(config, [
      "use chroot = no\n",
      "pid file = #{pid_file}\n",
      "log file = #{Path.join(dir, "rsyncd.log")}\n",
      if(max = opts[:max_connections],
        do: "max connections = #{max}\nlock file = #{Path.join(dir, "rsyncd.lock")}\n",
        else: []
      ),
      for {name, path} <- modules do
        "[#{name}]\npath = #{Path.expand(path)}\nread only = yes\n"
      end
    ])

    {_, 0} =
      System.cmd("rsync", [
        "--daemon",
        "--config=#{config}",
        "--address=127.0.0.1",
        "--port=#{port}"
      ])

    daemon = %{port: port, pid_file: pid_file}
    on_exit(fn -> stop(daemon) end)
    wait_until_ready(port, 50)
    daemon
  end

  @doc """
  A TCP server on a free port that accepts connections and never answers,
  for timeout tests. Returns the port.
  """
  @spec silent_server!() :: :inet.port_number()
  def silent_server! do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, port} = :inet.port(listen)
    owner = self()

    server =
      spawn(fn ->
        accept_forever(listen)
        send(owner, :done)
      end)

    :ok = :gen_tcp.controlling_process(listen, server)
    on_exit(fn -> Process.exit(server, :kill) end)
    port
  end

  @doc """
  A TCP proxy on a free port in front of the daemon on `target` that
  resets some connections as soon as it accepts them, for retry tests
  (D-039): `drop` is the list of connection numbers to reset, counting
  from 1, or `:all`. rsync sees a reset connection as exit 12, or as
  exit 10 if the reset comes while it is still connecting. The other
  connections are passed through. Returns the port.
  """
  @spec dropping_proxy!(:inet.port_number(), [pos_integer()] | :all) :: :inet.port_number()
  def dropping_proxy!(target, drop) do
    {:ok, listen} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false])
    {:ok, port} = :inet.port(listen)
    server = spawn(fn -> proxy(listen, target, drop, 1) end)
    :ok = :gen_tcp.controlling_process(listen, server)
    on_exit(fn -> Process.exit(server, :kill) end)
    port
  end

  defp proxy(listen, target, drop, n) do
    case :gen_tcp.accept(listen) do
      {:ok, client} ->
        if drop == :all or n in drop do
          :ok = :inet.setopts(client, linger: {true, 0})
          :gen_tcp.close(client)
        else
          pipe = spawn(fn -> pipe(client, target) end)
          :ok = :gen_tcp.controlling_process(client, pipe)
          send(pipe, :go)
        end

        proxy(listen, target, drop, n + 1)

      {:error, _} ->
        :ok
    end
  end

  defp pipe(client, target) do
    receive do
      :go -> :ok
    end

    {:ok, upstream} = :gen_tcp.connect({127, 0, 0, 1}, target, [:binary, active: true])
    :ok = :inet.setopts(client, active: true)
    pipe_loop(client, upstream)
  end

  defp pipe_loop(client, upstream) do
    receive do
      {:tcp, ^client, data} ->
        _ = :gen_tcp.send(upstream, data)
        pipe_loop(client, upstream)

      {:tcp, ^upstream, data} ->
        _ = :gen_tcp.send(client, data)
        pipe_loop(client, upstream)

      {:tcp_closed, _socket} ->
        close(client, upstream)

      {:tcp_error, _socket, _reason} ->
        close(client, upstream)
    end
  end

  defp close(client, upstream) do
    :gen_tcp.close(client)
    :gen_tcp.close(upstream)
  end

  @doc "A port on 127.0.0.1 that nothing listens on (at the time of the call)."
  @spec closed_port() :: :inet.port_number()
  def closed_port, do: free_port()

  defp accept_forever(listen) do
    case :gen_tcp.accept(listen) do
      {:ok, _socket} -> accept_forever(listen)
      {:error, _} -> :ok
    end
  end

  defp stop(%{pid_file: pid_file}) do
    with {:ok, pid} <- File.read(pid_file) do
      System.cmd("kill", [String.trim(pid)], stderr_to_stdout: true)
    end
  end

  defp free_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1})
    {:ok, port} = :inet.port(socket)
    :ok = :gen_tcp.close(socket)
    port
  end

  defp wait_until_ready(port, 0), do: raise("rsync daemon didn't start on port #{port}")

  defp wait_until_ready(port, tries) do
    case :gen_tcp.connect({127, 0, 0, 1}, port, [], 100) do
      {:ok, socket} ->
        :gen_tcp.close(socket)

      {:error, _} ->
        Process.sleep(100)
        wait_until_ready(port, tries - 1)
    end
  end
end

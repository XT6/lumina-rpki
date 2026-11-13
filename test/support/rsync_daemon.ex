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

  @doc "Starts a daemon serving `modules` (name => directory) and waits until it accepts connections."
  @spec start!(Path.t(), %{String.t() => Path.t()}) :: t()
  def start!(work_dir, modules) do
    dir = Path.join(work_dir, "rsyncd")
    File.mkdir_p!(dir)
    port = free_port()
    pid_file = Path.join(dir, "rsyncd.pid")
    config = Path.join(dir, "rsyncd.conf")

    File.write!(config, [
      "use chroot = no\n",
      "pid file = #{pid_file}\n",
      "log file = #{Path.join(dir, "rsyncd.log")}\n",
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

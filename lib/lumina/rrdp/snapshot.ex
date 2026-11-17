defmodule Lumina.RRDP.Snapshot do
  @moduledoc """
  The Snapshot File (RFC 8182 §3.5.2), decoded as a stream (#199).

  The root must be `snapshot`, in the RRDP namespace, version 1, with the
  session_id and serial the notification's `snapshot` element is for
  (§3.5.2.3). Each `publish` element (`uri` only, §3.5.4) goes to the
  callback as `{:publish, uri, bytes}`, `uri` a `Lumina.URI` (an rsync
  URI of an object in a module) and `bytes` the decoded object, at most
  20 MiB (D-043). A snapshot may publish nothing.

  The caller checks the file's SHA-256 against the notification before
  decoding it (§3.4.3), and decides what to do with the objects.
  """

  alias Lumina.RRDP.Content

  @doc """
  Decodes the snapshot file at `path`, expected to be for `expected`
  (`%{session_id: id, serial: n}`), calling `fun.(element, acc)` for each
  published object. Returns `{:ok, acc}`, `{:halted, acc}` if `fun`
  stopped, or `{:error, problem}`. Options: `:max_object` and the XML
  parser's limits.
  """
  @spec stream(Path.t(), Content.expected(), function(), term(), keyword()) ::
          {:ok, term()} | {:halted, term()} | {:error, Lumina.RRDP.problem()}
  def stream(path, expected, fun, acc, opts \\ []),
    do: Content.stream(:snapshot, {:file, path}, expected, fun, acc, opts)

  @doc "As `stream/5`, for a snapshot in memory."
  @spec parse(binary(), Content.expected(), function(), term(), keyword()) ::
          {:ok, term()} | {:halted, term()} | {:error, Lumina.RRDP.problem()}
  def parse(xml, expected, fun, acc, opts \\ []),
    do: Content.stream(:snapshot, {:binary, xml}, expected, fun, acc, opts)
end

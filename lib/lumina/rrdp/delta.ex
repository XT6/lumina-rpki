defmodule Lumina.RRDP.Delta do
  @moduledoc """
  The Delta File (RFC 8182 §3.5.3), decoded as a stream (#199).

  The root must be `delta`, in the RRDP namespace, version 1, with the
  session_id of the notification and the serial of the `delta` element
  that refers to it (§3.5.3.3), and at least one element (§3.5.4). Each
  element goes to the callback:

    * `{:publish, uri, bytes}`: a new object;
    * `{:publish, uri, bytes, hash}`: an object replacing the one whose
      SHA-256 is `hash` (32 raw bytes);
    * `{:withdraw, uri, hash}`: the object whose SHA-256 is `hash` is
      removed.

  `uri` is a `Lumina.URI` (an rsync URI of an object in a module); objects
  are at most 20 MiB (D-043). Whether a hash must be present (F-037,
  erratum 6919) and matches the stored object is the caller's check
  (RFC 8182 §3.4.2, #204), as is the file's SHA-256 against the
  notification.
  """

  alias Lumina.RRDP.Content

  @doc """
  Decodes the delta file at `path`, expected to be for `expected`
  (`%{session_id: id, serial: n}`), calling `fun.(element, acc)` for each
  element. Returns `{:ok, acc}`, `{:halted, acc}` if `fun` stopped, or
  `{:error, problem}`. Options: `:max_object` and the XML parser's
  limits.
  """
  @spec stream(Path.t(), Content.expected(), function(), term(), keyword()) ::
          {:ok, term()} | {:halted, term()} | {:error, Lumina.RRDP.problem()}
  def stream(path, expected, fun, acc, opts \\ []),
    do: Content.stream(:delta, {:file, path}, expected, fun, acc, opts)

  @doc "As `stream/5`, for a delta in memory."
  @spec parse(binary(), Content.expected(), function(), term(), keyword()) ::
          {:ok, term()} | {:halted, term()} | {:error, Lumina.RRDP.problem()}
  def parse(xml, expected, fun, acc, opts \\ []),
    do: Content.stream(:delta, {:binary, xml}, expected, fun, acc, opts)
end

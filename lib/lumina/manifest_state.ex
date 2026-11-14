defmodule Lumina.ManifestState do
  @moduledoc """
  Manifest replay protection across runs (D-024, #136).

  RFC 9286 §4.2.1: each RP "MUST verify that a purported 'new' manifest
  contains a higher manifestNumber than previously validated manifests",
  and that its thisUpdate is "greater (more recent) than the most recent
  manifest it has validated"; otherwise it "SHOULD use locally cached
  versions of objects". RFC 9981 §2-3 updates the first check: when the
  manifest's file name (the last path segment of the CA's SIA rpkiManifest
  URI) changes, the stored number is reset, the thisUpdate check still
  applies, and the RP "MUST alert its operators".

  For each CA, by its Subject Key Identifier, the manifest URI, number and
  thisUpdate of the last manifest accepted are kept in
  `<root>/.state/manifests/<SKI hex>.json`. Keying by the CA alone, not
  also by the manifest URI, is what lets a changed file name be noticed.

  `check/3` compares an accepted point (`Lumina.PublicationPoint`) with
  that record. The same manifest seen again is fine; it is only a "new"
  manifest that must move forward. `record/3` stores an accepted point;
  only `lumina sync` records, so an offline `lumina validate` at another
  time can't move the state (D-024).
  """

  alias Lumina.Certificate

  @type entry :: %{manifest: String.t(), number: non_neg_integer(), this_update: DateTime.t()}

  @doc "The record for `ca`, or `nil` if none was kept."
  @spec load(Path.t(), Certificate.t()) :: entry() | nil
  def load(root, ca) do
    with {:ok, file} <- file(root, ca),
         {:ok, json} <- File.read(file),
         {:ok, %{"manifest" => manifest, "number" => number, "this_update" => this_update}} <-
           JSON.decode(json),
         {number, ""} <- Integer.parse(number),
         {:ok, at, _} <- DateTime.from_iso8601(this_update) do
      %{manifest: manifest, number: number, this_update: at}
    else
      _ -> nil
    end
  end

  @doc """
  Records `point`, an accepted publication point of `ca`, as the last
  manifest validated. The file is written next to its final name and
  renamed into place.
  """
  @spec record(Path.t(), Certificate.t(), map()) :: :ok | {:error, term()}
  def record(root, ca, %{status: :accepted, manifest: uri, number: n, this_update: t}) do
    with {:ok, file} <- file(root, ca) do
      json =
        JSON.encode!(%{
          "manifest" => uri,
          "number" => Integer.to_string(n),
          "this_update" => DateTime.to_iso8601(t)
        })

      temp = file <> ".tmp"

      with :ok <- File.mkdir_p(Path.dirname(file)),
           :ok <- File.write(temp, json),
           do: File.rename(temp, file)
    end
  end

  @doc """
  The problems of accepted `point` against `ca`'s record: errors when a
  new manifest doesn't move forward, a warning when its file name
  changed (RFC 9981 §2: operators are alerted). `[]` without a record.
  """
  @spec check(Path.t(), Certificate.t(), map()) :: [Lumina.Profile.problem()]
  def check(root, ca, %{manifest: uri, number: n, this_update: t}) do
    case load(root, ca) do
      nil -> []
      prior -> compare(prior, uri, n, t)
    end
  end

  # The manifest validated last time, seen again.
  defp compare(%{manifest: uri, number: n, this_update: t}, uri, n, t2)
       when is_struct(t2, DateTime) do
    if DateTime.compare(t, t2) == :eq, do: [], else: forward(n, t, n, t2)
  end

  defp compare(prior, uri, n, t) do
    if name(prior.manifest) == name(uri) do
      forward(prior.number, prior.this_update, n, t)
    else
      [
        warning(
          :manifest_name_changed,
          "9981#2",
          "the manifest's file name changed from #{name(prior.manifest)} to #{name(uri)}; " <>
            "its manifest number isn't compared (RFC 9981)"
        )
        | this_update(prior.this_update, t)
      ]
    end
  end

  defp forward(prior_n, prior_t, n, t) do
    number =
      if n > prior_n,
        do: [],
        else: [
          error(
            :manifest_number_replay,
            "9286#4.2.1",
            :manifest_number,
            "the manifest number #{n} is not higher than #{prior_n}, the last one validated"
          )
        ]

    number ++ this_update(prior_t, t)
  end

  defp this_update(prior_t, t) do
    if DateTime.compare(t, prior_t) == :gt,
      do: [],
      else: [
        error(
          :manifest_this_update_replay,
          "9286#4.2.1",
          :this_update,
          "thisUpdate #{DateTime.to_iso8601(t)} is not more recent than " <>
            "#{DateTime.to_iso8601(prior_t)}, the last one validated"
        )
      ]
  end

  # RFC 9981 §3: the final segment of the URI's path.
  defp name(uri), do: uri |> String.split("/") |> List.last()

  defp file(root, ca) do
    case Certificate.extension_value(ca, :subject_key_identifier) do
      ski when is_binary(ski) ->
        {:ok, Path.join([root, ".state", "manifests", Base.encode16(ski) <> ".json"])}

      _ ->
        {:error, :no_ski}
    end
  end

  defp warning(rule, rfc, message),
    do: %{rule: rule, rfc: rfc, field: :manifest, message: message, severity: :warning}

  defp error(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :error}
end

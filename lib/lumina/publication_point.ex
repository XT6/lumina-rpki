defmodule Lumina.PublicationPoint do
  @moduledoc """
  Decides whether a CA's publication point can be used (RFC 9286 §6,
  #133), from the copy in the cache.

  `process/4` takes a valid CA certificate and the cache directory of its
  caRepository, and returns either an accepted point (the manifest and
  the files it lists) or a failed fetch with every reason:

    * §6.1: the manifest named by the CA's SIA rpkiManifest URI must be
      in the caRepository directory (`:manifest_outside`);
    * §6.2: it must be there (`:manifest_missing`), decode
      (`:manifest_decode`) and be valid: its EE certificate validates
      against the CA (`Lumina.Chain.child/5`, so a revoked manifest fails
      as §6 says), its envelope passes `Lumina.CMS.check/1` and its
      content `Lumina.Manifest.check/1`; those problems are reported with
      their own rules;
    * RFC 9981 §4: one of the EE certificate's signedObject URIs must be
      exactly the URI the manifest was fetched from
      (`:manifest_uri_mismatch`);
    * §6.3: the validation time must lie between thisUpdate and
      nextUpdate (`:manifest_premature`, `:manifest_stale`);
    * §6: the CRL the manifest's EE certificate names must be on the
      manifest (`:crl_not_listed`: "the CRL is considered missing");
    * §6.4: every listed file must be in the directory (`:file_missing`);
    * §6.5: with the SHA-256 the manifest gives (`:hash_mismatch`).

  Problems have the `Lumina.Profile` shape. Warnings (a stale CRL, D-016;
  absent rsaEncryption parameters, D-025) don't fail the point. Files in
  the directory but not on the manifest aren't part of the result: §6
  says they "MUST NOT be used". What the walk and `lumina validate` do
  with a failed point is #134's.
  """

  alias Lumina.{Certificate, Chain, CMS, CRL, Manifest, Object, Profile, SignedObject, URI}

  @type problem :: Lumina.Profile.problem()
  @type t :: %{
          status: :accepted | :failed,
          manifest: String.t() | nil,
          problems: [problem()],
          files: %{String.t() => Path.t()},
          unlisted: [String.t()]
        }

  @rules [
    :manifest_outside,
    :manifest_missing,
    :manifest_decode,
    :manifest_uri_mismatch,
    :manifest_premature,
    :manifest_stale,
    :crl_not_listed,
    :file_missing,
    :hash_mismatch
  ]

  @doc """
  The rules only publication point processing reports; the others it
  passes on come from validating the manifest as a signed object.
  """
  @spec rules() :: [atom()]
  def rules, do: @rules

  @doc """
  Processes the publication point of the valid CA certificate `ca`, whose
  caRepository URI is `key` and whose copy is the directory `path`, at
  time `now`. `files` maps each listed name to its path when the point is
  accepted, and is empty when it fails; `unlisted` names the other files
  in an accepted point's directory (the manifest itself aside), which
  aren't used.
  """
  @spec process(Certificate.t(), Path.t(), String.t(), DateTime.t()) :: t()
  def process(%Certificate{} = ca, path, key, %DateTime{} = now) do
    case manifest_uri(ca) do
      {:ok, uri} ->
        with {:ok, file} <- in_point(uri, key),
             {:ok, manifest} <- read_manifest(path, file) do
          problems =
            manifest_problems(manifest, uri, ca, path, key, now) ++ files(manifest, path)

          if Profile.passes?(problems),
            do: %{
              status: :accepted,
              manifest: uri,
              problems: problems,
              files: Map.new(Manifest.names(manifest), &{&1, Path.join(path, &1)}),
              unlisted: unlisted(path, [file | Manifest.names(manifest)])
            },
            else: failed(uri, problems)
        else
          {:error, problem} -> failed(uri, [problem])
        end

      {:error, problem} ->
        failed(nil, [problem])
    end
  end

  @doc """
  The CRL that `uri` (a CRLDP's rsync URI) names, read from the
  publication point `key` held at `path`, or `nil` if the URI is
  elsewhere, the file is missing or it isn't a CRL (D-015).
  """
  @spec read_crl(String.t() | nil, Path.t(), String.t()) :: CRL.t() | nil
  def read_crl(uri, path, key) do
    with true <- is_binary(uri),
         {:ok, file} <- file_in(uri, key),
         {:ok, %Object{value: %CRL{} = crl}} <- Object.decode_file(Path.join(path, file)) do
      crl
    else
      _ -> nil
    end
  end

  defp failed(uri, problems),
    do: %{status: :failed, manifest: uri, problems: problems, files: %{}, unlisted: []}

  # §6: files present but not on the manifest "MUST NOT be used"; they're
  # only counted.
  defp unlisted(path, listed) do
    for file <- path |> File.ls!() |> Enum.sort(),
        file not in listed,
        File.regular?(Path.join(path, file)),
        do: file
  end

  # §6.2: the manifest the CA's SIA names (RFC 6487 §4.8.8.1: rsync).
  defp manifest_uri(ca) do
    case Enum.find(Certificate.sia_uris(ca, :rpki_manifest), &String.starts_with?(&1, "rsync://")) do
      nil ->
        {:error,
         error(
           :manifest_missing,
           "9286#6.2",
           :manifest,
           "the CA certificate names no rsync manifest"
         )}

      uri ->
        {:ok, uri}
    end
  end

  # §6.1: the manifest and the files it lists are in the caRepository.
  defp in_point(uri, key) do
    case file_in(uri, key) do
      {:ok, file} ->
        {:ok, file}

      :error ->
        {:error,
         error(
           :manifest_outside,
           "9286#6.1",
           :manifest,
           "the manifest #{uri} is not in the publication point #{key}"
         )}
    end
  end

  # The file name of `uri` if it names a file directly in `key`.
  defp file_in(uri, key) do
    with {:ok, parsed} <- URI.parse(uri),
         prefix = key <> "/",
         string = to_string(parsed),
         true <- String.starts_with?(string, prefix),
         file = String.replace_prefix(string, prefix, ""),
         false <- file == "" or String.contains?(file, "/") do
      {:ok, file}
    else
      _ -> :error
    end
  end

  defp read_manifest(path, file) do
    full = Path.join(path, file)

    if File.regular?(full) do
      case Object.decode_file(full) do
        {:ok, %Object{value: %Manifest{} = manifest}} ->
          {:ok, manifest}

        {:ok, %Object{}} ->
          {:error, error(:manifest_decode, "9286#6.2", :manifest, "#{file} is not a manifest")}

        {:error, reason} ->
          {:error,
           error(
             :manifest_decode,
             "9286#6.2",
             :manifest,
             "#{file} doesn't decode: #{Lumina.Print.error(reason, file)}"
           )}
      end
    else
      {:error,
       error(
         :manifest_missing,
         "9286#6.2",
         :manifest,
         "the manifest #{file} is not in the publication point"
       )}
    end
  end

  defp manifest_problems(manifest, uri, ca, path, key, now) do
    object = manifest.object
    ee = SignedObject.ee_certificate(object)

    certificate =
      if ee do
        crl_uri = Chain.crl_uri(ee)
        crl = Chain.crl(read_crl(crl_uri, path, key), ca, now)
        Chain.child(ee, :ee, ca, crl, now).problems ++ crl_listed(crl_uri, manifest, key)
      else
        []
      end

    certificate ++
      CMS.check(object) ++
      Manifest.check(manifest) ++
      signed_object_uri(ee, uri) ++
      current(manifest, now)
  end

  # RFC 9981 §4.
  defp signed_object_uri(nil, _uri), do: []

  defp signed_object_uri(ee, uri) do
    if uri in Certificate.sia_uris(ee, :signed_object),
      do: [],
      else: [
        error(
          :manifest_uri_mismatch,
          "9981#4",
          :manifest,
          "the EE certificate's signedObject URI is not #{uri}, where the manifest was fetched"
        )
      ]
  end

  # §6.3.
  defp current(%{this_update: %{at: this}, next_update: %{at: next}}, now) do
    cond do
      DateTime.compare(now, this) == :lt ->
        [
          error(
            :manifest_premature,
            "9286#6.3",
            :this_update,
            "the manifest is premature: thisUpdate #{DateTime.to_iso8601(this)} is after the validation time"
          )
        ]

      DateTime.compare(now, next) == :gt ->
        [
          error(
            :manifest_stale,
            "9286#6.3",
            :next_update,
            "the manifest is stale: nextUpdate #{DateTime.to_iso8601(next)} is before the validation time"
          )
        ]

      true ->
        []
    end
  end

  # §6: "if the CRL is not listed on a valid, current manifest ... the CRL
  # is considered missing". A CRLDP outside the point is Chain's to report.
  defp crl_listed(crl_uri, manifest, key) do
    case crl_uri && file_in(crl_uri, key) do
      {:ok, file} ->
        if file in Manifest.names(manifest),
          do: [],
          else: [
            error(
              :crl_not_listed,
              "9286#6",
              :crl,
              "the CRL #{file} is not on the manifest"
            )
          ]

      _ ->
        []
    end
  end

  # §6.4 and §6.5. A name that isn't a plain file name is already a
  # Manifest.check/1 problem, and is never looked up outside the directory.
  defp files(manifest, path) do
    Enum.flat_map(manifest.files, fn %{name: name, hash: hash} ->
      full = Path.join(path, name)

      cond do
        String.contains?(name, "/") or name in ["", ".", ".."] ->
          []

        not File.regular?(full) ->
          [error(:file_missing, "9286#6.4", :file_list, "#{name} is listed but not published")]

        :crypto.hash(:sha256, File.read!(full)) != hash ->
          [
            error(
              :hash_mismatch,
              "9286#6.5",
              :file_list,
              "the hash of #{name} doesn't match the manifest"
            )
          ]

        true ->
          []
      end
    end)
  end

  defp error(rule, rfc, field, message),
    do: %{rule: rule, rfc: rfc, field: field, message: message, severity: :error}
end

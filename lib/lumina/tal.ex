defmodule Lumina.TAL do
  @moduledoc """
  Parses Trust Anchor Locators (RFC 8630 §2.2).

  A TAL is, in order:

    1. optional comment lines starting with `#` (UTF-8, RFC 5198 §2),
    2. one or more TA URIs, one per line, each rsync or HTTPS,
    3. one blank line, and
    4. the base64 DER `SubjectPublicKeyInfo` of the trust anchor, which may
       span several lines.

  Lines end in LF or CRLF. The grammar is followed strictly (D-002 in
  doc/decisions.md): anything outside it is an error, except trailing
  whitespace on a line, which is ignored with a warning.

  Errors and warnings name a rule and a line, with the vocabulary of the
  test TAL corpus (`test/fixtures/tals/README.md`); lines are numbered
  from 1, and a problem found at the end of the file is reported at the
  line after the last one.
  """

  import Bitwise

  alias Lumina.{ASN1, DER}

  defstruct comments: [], uris: [], public_key: nil, public_key_info: nil, warnings: []

  @type finding :: %{line: pos_integer(), rule: atom(), rfc: String.t(), message: String.t()}
  @type t :: %__MODULE__{
          comments: [String.t()],
          uris: [String.t()],
          public_key: binary(),
          public_key_info: %{algorithm: tuple(), parameters: binary() | nil, key: bitstring()},
          warnings: [finding()]
        }

  @schemes ["rsync", "https"]

  @doc """
  Parses the text of a TAL.

  ## Examples

      iex> {:error, %{line: 1, rule: :empty}} = Lumina.TAL.parse("")

  """
  @spec parse(binary()) :: {:ok, t()} | {:error, finding()}
  def parse(""), do: error(1, :empty, "8630#2.2", "the file is empty")

  def parse(text) when is_binary(text) do
    {lines, warnings} = text |> split_lines() |> strip_trailing_whitespace()
    eof = length(lines) + 1

    with {:ok, comments, rest} <- comments(lines, []),
         {:ok, uris, rest} <- uris(rest, [], eof),
         {:ok, key_lines} <- key_lines(rest, [], eof),
         {:ok, der, info} <- key(key_lines) do
      {:ok,
       %__MODULE__{
         comments: comments,
         uris: uris,
         public_key: der,
         public_key_info: info,
         warnings: warnings
       }}
    end
  end

  @doc "Reads and parses a TAL file."
  @spec decode_file(Path.t()) :: {:ok, t()} | {:error, finding() | atom()}
  def decode_file(path) do
    with {:ok, text} <- File.read(path), do: parse(text)
  end

  @doc """
  The Subject Key Identifier the trust anchor certificate is expected to
  carry: the SHA-1 of the key bits (RFC 6487 §4.8.2).
  """
  @spec subject_key_identifier(t()) :: binary()
  def subject_key_identifier(%__MODULE__{public_key_info: %{key: key}}),
    do: :crypto.hash(:sha, key)

  # Lines, numbered from 1. A final line break ends the last line rather
  # than starting an empty one; CRLF and LF are both line breaks.
  defp split_lines(text) do
    parts = String.split(text, "\n")
    parts = if String.ends_with?(text, "\n"), do: Enum.drop(parts, -1), else: parts

    parts
    |> Enum.map(&String.trim_trailing(&1, "\r"))
    |> Enum.with_index(1)
  end

  defp strip_trailing_whitespace(lines) do
    Enum.map_reduce(lines, [], fn {line, n}, warnings ->
      case Regex.run(~r/\A(.*?)[ \t]+\z/s, line) do
        [_, stripped] ->
          warning = finding(n, :trailing_whitespace, "8630#2.2", "trailing whitespace ignored")
          {{stripped, n}, warnings ++ [warning]}

        nil ->
          {{line, n}, warnings}
      end
    end)
  end

  # 1. The comment section.
  defp comments([{"#" <> _ = line, n} | rest], acc) do
    with :ok <- comment_text(line, n), do: comments(rest, acc ++ [line])
  end

  defp comments(rest, acc), do: {:ok, acc, rest}

  defp comment_text(line, n) do
    cond do
      not String.valid?(line) ->
        error(n, :invalid_utf8, "8630#2.2", "the comment is not valid UTF-8")

      # RFC 5198 §2 (cited by RFC 8630 §2.2): no control characters. Tab is
      # tolerated inside a comment.
      Regex.match?(~r/[\x00-\x08\x0A-\x1F\x7F\x{80}-\x{9F}]/u, line) ->
        error(n, :invalid_comment_text, "8630#2.2", "the comment contains a control character")

      true ->
        :ok
    end
  end

  # 2. The URI section, up to the blank line.
  defp uris([{"", n} | _rest], [], _eof),
    do: error(n, :no_uri, "8630#2.2", "no TA URI before the blank line")

  defp uris([{"", _n} | rest], acc, _eof), do: {:ok, acc, rest}

  defp uris([{"#" <> _, n} | _rest], _acc, _eof),
    do: error(n, :comment_after_uris, "8630#2.2", "comments are only allowed before the URIs")

  defp uris([{line, n} | rest], acc, eof) do
    cond do
      base64_line?(line) and acc == [] ->
        error(n, :no_uri, "8630#2.2", "no TA URI before the key")

      base64_line?(line) ->
        error(
          n,
          :missing_separator,
          "8630#2.2",
          "the key must be separated from the URIs by a blank line"
        )

      true ->
        with :ok <- uri(line, n), do: uris(rest, acc ++ [line], eof)
    end
  end

  defp uris([], [], eof), do: error(eof, :no_uri, "8630#2.2", "the TAL has no TA URI")

  defp uris([], _acc, eof),
    do:
      error(
        eof,
        :missing_separator,
        "8630#2.2",
        "the file ends before the blank line and the key"
      )

  defp base64_line?(line),
    do: not String.contains?(line, "://") and Regex.match?(~r/\A[A-Za-z0-9+\/]+=*\z/, line)

  defp uri(line, n) do
    case URI.new(line) do
      {:ok, %URI{scheme: scheme, host: host}}
      when is_binary(scheme) and is_binary(host) and host != "" ->
        if String.downcase(scheme) in @schemes,
          do: :ok,
          else:
            error(n, :unsupported_scheme, "8630#2.2", "#{inspect(scheme)} is not rsync or https")

      {:ok, %URI{scheme: scheme}} when is_binary(scheme) ->
        if String.downcase(scheme) in @schemes,
          do: error(n, :invalid_uri, "8630#2.2", "the URI has no host"),
          else:
            error(n, :unsupported_scheme, "8630#2.2", "#{inspect(scheme)} is not rsync or https")

      _ ->
        error(n, :invalid_uri, "3986#3", "#{inspect(line)} is not an absolute URI")
    end
  end

  # 3 and 4. After the blank line: the key lines, then the end of the file.
  defp key_lines([], [], eof),
    do: error(eof, :empty_key, "8630#2.2", "no key after the blank line")

  defp key_lines([], acc, _eof), do: {:ok, acc}

  defp key_lines([{"", n} | _rest], _acc, _eof),
    do:
      error(
        n,
        :extra_blank_line,
        "8630#2.2",
        "only one blank line is allowed, between the URIs and the key"
      )

  defp key_lines([{"#" <> _, n} | _rest], _acc, _eof),
    do: error(n, :comment_after_uris, "8630#2.2", "comments are only allowed before the URIs")

  defp key_lines([{line, n} | rest], acc, eof) do
    if Regex.match?(~r/\A[A-Za-z0-9+\/=]+\z/, line),
      do: key_lines(rest, acc ++ [{line, n}], eof),
      else:
        error(n, :bad_base64, "4648#4", "the key contains characters outside the base64 alphabet")
  end

  defp key([{_, first} | _] = lines) do
    base64 = Enum.map_join(lines, &elem(&1, 0))

    with {:ok, der} <- base64(base64, first),
         :ok <- der(der, first),
         {:ok, info} <- spki(der, first) do
      {:ok, der, info}
    end
  end

  defp base64(text, line) do
    case Base.decode64(text) do
      {:ok, der} -> {:ok, der}
      :error -> error(line, :bad_base64, "4648#4", "the key's base64 length or padding is wrong")
    end
  end

  defp der(der, line) do
    case DER.check(der) do
      :ok ->
        :ok

      {:error, %{message: message}} ->
        error(line, :not_der, "8630#2.2", "the key is not DER: #{message}")
    end
  end

  defp spki(der, line) do
    with {:ok, value} <- ASN1.decode(:pkix, :SubjectPublicKeyInfo, der),
         :ok <- DER.check_canonical(:pkix, :SubjectPublicKeyInfo, der) do
      {:ok,
       %{
         algorithm: value.algorithm.algorithm,
         parameters: Map.get(value.algorithm, :parameters),
         key: value.subjectPublicKey
       }}
    else
      _ -> error(line, :not_spki, "5280#4.1.2.7", "the key is not a SubjectPublicKeyInfo")
    end
  end

  @doc """
  Checks a trust anchor certificate against its TAL, per RFC 8630 §2.3 and
  §3. Returns `:ok`, or `{:error, problems}` where each problem is
  `%{rule:, rfc:, message:}`:

    * `:key_mismatch`: the certificate's SubjectPublicKeyInfo isn't
      byte-identical to the TAL's key (§2.3, §3 step 3)
    * `:not_self_issued`: issuer and subject differ (§2.3, "self-signed")
    * `:not_ca`: no Basic Constraints with cA=true (§2.3, RFC 6487 §4.8.1)
    * `:aki_mismatch`: an AKI that isn't equal to the SKI (RFC 6487 §4.8.3)
    * `:no_resources`: neither IP nor AS resources (§2.3)
    * `:inherit_resources`: an `inherit` IP family, asnum or rdi (§2.3)
    * `:empty_resources`: a present resource extension that holds no
      resources (§2.3; each extension must be non-empty, F-023)
    * `:malformed_resources`: a resource extension that doesn't decode

  Lumina treats every §3 step as a MUST (F-022). Verifying the
  self-signature (RFC 7935) and checking that the certificate is current
  (validity dates) are left to certificate validation (M4).
  """
  @spec check_ta(t(), Lumina.Certificate.t()) :: :ok | {:error, [map()]}
  def check_ta(%__MODULE__{} = tal, %Lumina.Certificate{} = cert) do
    alias Lumina.Certificate

    ip = Certificate.extension_value(cert, :ip_resources)
    as = Certificate.extension_value(cert, :as_resources)
    ski = Certificate.extension_value(cert, :subject_key_identifier)
    aki = Certificate.extension_value(cert, :authority_key_identifier)

    problems =
      [
        if(tal.public_key != cert.public_key.der,
          do:
            problem(
              :key_mismatch,
              "8630#2.3",
              "the certificate's public key is not the TAL's key"
            )
        ),
        if(cert.issuer_der != cert.subject_der,
          do:
            problem(
              :not_self_issued,
              "8630#2.3",
              "issuer and subject differ; a TA certificate is self-signed"
            )
        ),
        if(not match?(%{ca: true}, Certificate.extension_value(cert, :basic_constraints)),
          do:
            problem(
              :not_ca,
              "8630#2.3",
              "the certificate is not a CA certificate (Basic Constraints cA=true)"
            )
        ),
        if(match?(%{key_identifier: kid} when kid != nil, aki) and aki.key_identifier != ski,
          do:
            problem(
              :aki_mismatch,
              "6487#4.8.3",
              "the AKI of a self-signed certificate must equal its SKI"
            )
        ),
        if(ip == nil and as == nil,
          do: problem(:no_resources, "8630#2.3", "the certificate has no IP or AS resources")
        )
      ] ++ resource_problems(:ip, ip) ++ resource_problems(:as, as)

    case Enum.reject(problems, &is_nil/1) do
      [] -> :ok
      found -> {:error, found}
    end
  end

  defp resource_problems(_kind, nil), do: []

  defp resource_problems(kind, {:malformed, reason}),
    do: [
      problem(
        :malformed_resources,
        "8630#2.3",
        "the #{kind} resource extension doesn't decode: #{inspect(reason)}"
      )
    ]

  defp resource_problems(:ip, families) do
    cond do
      Enum.any?(families, &(&1.resources == :inherit)) ->
        [problem(:inherit_resources, "8630#2.3", "a TA must not inherit IP resources")]

      families == [] or Enum.any?(families, &(&1.resources == [])) ->
        [problem(:empty_resources, "8630#2.3", "the IP resource extension holds no resources")]

      true ->
        []
    end
  end

  defp resource_problems(:as, %{asnum: asnum, rdi: rdi}) do
    cond do
      :inherit in [asnum, rdi] ->
        [problem(:inherit_resources, "8630#2.3", "a TA must not inherit AS resources")]

      asnum in [nil, []] and rdi in [nil, []] ->
        [problem(:empty_resources, "8630#2.3", "the AS resource extension holds no resources")]

      true ->
        []
    end
  end

  defp problem(rule, rfc, message), do: %{rule: rule, rfc: rfc, message: message}

  @doc """
  The size in bits of an RSA key's modulus, or `nil` if the key isn't RSA
  or can't be read.
  """
  @spec key_bits(t()) :: pos_integer() | nil
  def key_bits(%__MODULE__{public_key_info: %{key: key}}) when is_binary(key) do
    with {:ok, [<<0x02, _::binary>> = modulus, _exponent]} <- DER.children(key),
         {:ok, contents} <- integer_contents(modulus) do
      bits(:binary.decode_unsigned(contents), 0)
    else
      _ -> nil
    end
  end

  def key_bits(_tal), do: nil

  defp integer_contents(<<0x02, n, contents::binary-size(n)>>) when n < 128, do: {:ok, contents}
  defp integer_contents(<<0x02, 0x81, n, contents::binary-size(n)>>), do: {:ok, contents}
  defp integer_contents(<<0x02, 0x82, n::16, contents::binary-size(n)>>), do: {:ok, contents}
  defp integer_contents(_), do: :error

  defp bits(0, count), do: count
  defp bits(value, count), do: bits(value >>> 1, count + 1)

  defp finding(line, rule, rfc, message),
    do: %{line: line, rule: rule, rfc: rfc, message: message}

  defp error(line, rule, rfc, message), do: {:error, finding(line, rule, rfc, message)}
end

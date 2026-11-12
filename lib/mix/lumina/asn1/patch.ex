defmodule Mix.Lumina.ASN1.Patch do
  @moduledoc """
  Applies and checks the patches in `asn1/patches/` that make the extracted
  RFC modules compile with OTP's `asn1ct`. See `asn1/README.md`.

  Patches are unified diffs against `asn1/rfc/`. They apply strictly: every
  hunk must match at exactly the line it names, with no offset or fuzz, so
  a change in the extracted text fails loudly instead of being patched in
  the wrong place.

  Every hunk must say why it exists with a comment line

      -- LUMINA PATCH (<kind>): <reason>

  and the kind limits which lines the hunk may remove or add. A patch may
  only work around the compiler. It must not change how any type encodes,
  so for example a hunk can't delete a field or add a constraint. The kinds
  are:

    * `builtin-type` - removes 1988-era redefinitions of types that are
      built into current ASN.1 (RFC 5280, F-007)
    * `content-type` - removes the `CONTENT-TYPE` import from RFC 6268 and
      the `ct-…` information objects (F-005)
    * `attribute-certificate` - replaces imports from the obsolete RFC 3281
      with opaque local types (F-006)
  """

  @type line :: {:context | :remove | :add, String.t()}
  @type hunk :: %{old_start: pos_integer(), lines: [line()]}

  @oid_line ~r/^\s*\{?\s*([a-z][\w-]*(\(\d+\))?|\d+)(\s+([a-z][\w-]*(\(\d+\))?|\d+))*\s*\}?\s*;?\s*$/
  @comment ~r/^\s*--/
  @blank ~r/^\s*$/

  # Lines each kind may remove and add, besides comments and blank lines.
  @kinds %{
    "builtin-type" => %{
      remove: [
        ~r/^(UniversalString|BMPString|UTF8String) ::= \[UNIVERSAL \d+\] IMPLICIT OCTET STRING$/,
        ~r/^\s*BMPString, UTF8String,\s+-- end "new" types --$/
      ],
      add: []
    },
    "content-type" => %{
      remove: [
        ~r/^\s*IMPORTS\s*$/,
        ~r/^\s*CONTENT-TYPE\s*$/,
        ~r/^\s*FROM CryptographicMessageSyntax-2010\b/,
        ~r/^\s*ct-[\w-]+ CONTENT-TYPE ::=\s*$/,
        ~r/^\s*\{\s*TYPE \w+(\s+IDENTIFIED BY [\w-]+\s*\})?\s*$/,
        ~r/^\s*IDENTIFIED BY [\w-]+\s*\}\s*$/,
        @oid_line
      ],
      add: []
    },
    "attribute-certificate" => %{
      remove: [
        ~r/^\s*(AttributeCertificate|AttributeCertificateV1)\s*$/,
        ~r/^\s*FROM (PKIXAttributeCertificate|AttributeCertificateVersion1)\s*$/,
        @oid_line
      ],
      add: [
        ~r/^\s*;\s*$/,
        ~r/^(AttributeCertificate|AttributeCertificateV1) ::= SEQUENCE OF ANY$/
      ]
    }
  }

  @doc "The patch kinds and the reason each exists, for documentation."
  @spec kinds() :: [String.t()]
  def kinds, do: @kinds |> Map.keys() |> Enum.sort()

  @doc """
  Parses a unified diff into hunks. File header lines (`---`, `+++`) are
  skipped.
  """
  @spec parse(String.t()) :: {:ok, [hunk()]} | {:error, String.t()}
  def parse(diff) do
    diff
    |> String.split("\n")
    |> drop_trailing_empty()
    |> Enum.reject(&(String.starts_with?(&1, "--- ") or String.starts_with?(&1, "+++ ")))
    |> Enum.reduce_while({:ok, []}, fn line, {:ok, hunks} ->
      case parse_line(line, hunks) do
        {:ok, hunks} -> {:cont, {:ok, hunks}}
        error -> {:halt, error}
      end
    end)
    |> case do
      {:ok, []} ->
        {:error, "no hunks"}

      {:ok, hunks} ->
        {:ok, hunks |> Enum.reverse() |> Enum.map(&%{&1 | lines: Enum.reverse(&1.lines)})}

      error ->
        error
    end
  end

  defp parse_line("@@ -" <> rest, hunks) do
    case Regex.run(~r/^(\d+)(?:,\d+)? \+\d+(?:,\d+)? @@/, rest) do
      [_, start] -> {:ok, [%{old_start: String.to_integer(start), lines: []} | hunks]}
      nil -> {:error, "malformed hunk header: @@ -#{rest}"}
    end
  end

  defp parse_line(_line, []), do: {:error, "content before the first hunk header"}

  defp parse_line(line, [hunk | rest]) do
    entry =
      case line do
        " " <> text -> {:context, text}
        "-" <> text -> {:remove, text}
        "+" <> text -> {:add, text}
        "" -> {:context, ""}
        "\\" <> _ -> :skip
        other -> {:error, "unexpected line in hunk: #{inspect(other)}"}
      end

    case entry do
      :skip -> {:ok, [hunk | rest]}
      {:error, _} = error -> error
      entry -> {:ok, [%{hunk | lines: [entry | hunk.lines]} | rest]}
    end
  end

  @doc """
  Applies `hunks` to `text`. Every context and removed line must match the
  original at exactly the position the hunk names.
  """
  @spec apply_hunks(String.t(), [hunk()]) :: {:ok, String.t()} | {:error, String.t()}
  def apply_hunks(text, hunks) do
    lines = String.split(text, "\n")

    result =
      Enum.reduce_while(hunks, {:ok, [], 0}, fn hunk, {:ok, out, pos} ->
        start = hunk.old_start - 1
        expected = for {kind, text} <- hunk.lines, kind != :add, do: text
        actual = Enum.slice(lines, start, length(expected))

        cond do
          start < pos ->
            {:halt, {:error, "hunk at line #{hunk.old_start} overlaps the previous hunk"}}

          actual != expected ->
            {:halt, {:error, "hunk at line #{hunk.old_start} does not match the original text"}}

          true ->
            kept = Enum.slice(lines, pos, start - pos)
            new = for {kind, text} <- hunk.lines, kind != :remove, do: text
            {:cont, {:ok, out ++ kept ++ new, start + length(expected)}}
        end
      end)

    case result do
      {:ok, out, pos} -> {:ok, Enum.join(out ++ Enum.drop(lines, pos), "\n")}
      error -> error
    end
  end

  @doc """
  Checks that every hunk states its kind and only removes and adds the
  lines that kind allows. Returns a list of problems, empty if the patch is
  acceptable.
  """
  @spec check_allowed([hunk()]) :: [String.t()]
  def check_allowed(hunks) do
    Enum.flat_map(hunks, fn hunk ->
      where = "hunk at line #{hunk.old_start}"

      case hunk_kinds(hunk) do
        [] ->
          ["#{where}: no `-- LUMINA PATCH (<kind>): <reason>` comment"]

        [kind] ->
          case Map.fetch(@kinds, kind) do
            {:ok, rules} ->
              disallowed(hunk, rules, where, kind)

            :error ->
              [
                "#{where}: unknown patch kind #{inspect(kind)} (known: #{Enum.join(kinds(), ", ")})"
              ]
          end

        several ->
          [
            "#{where}: mixes patch kinds #{several |> Enum.sort() |> Enum.join(", ")}; split the hunk"
          ]
      end
    end)
  end

  defp hunk_kinds(hunk) do
    for {:add, text} <- hunk.lines,
        [_, kind] <- [Regex.run(~r/-- LUMINA PATCH \(([^)]*)\):/, text)],
        uniq: true,
        do: kind
  end

  defp disallowed(hunk, rules, where, kind) do
    for {op, text} <- hunk.lines, op != :context, not allowed?(text, rules[op_key(op)]) do
      "#{where}: a #{kind} patch may not #{op_key(op)} #{inspect(String.trim(text))}"
    end
  end

  defp op_key(:remove), do: :remove
  defp op_key(:add), do: :add

  defp allowed?(text, patterns) do
    Regex.match?(@comment, text) or Regex.match?(@blank, text) or
      Enum.any?(patterns, &Regex.match?(&1, text))
  end

  defp drop_trailing_empty(lines) do
    lines |> Enum.reverse() |> Enum.drop_while(&(&1 == "")) |> Enum.reverse()
  end
end

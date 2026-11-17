defmodule Lumina.RRDP do
  @moduledoc """
  The RPKI Repository Delta Protocol (RRDP, RFC 8182, updated by RFC 9674
  and RFC 9697): M8.

  The three files are decoded by `Lumina.RRDP.Notification`,
  `Lumina.RRDP.Snapshot` and `Lumina.RRDP.Delta`, on top of the XML parser
  `Lumina.RRDP.XML` (D-041). This module holds what they share: the
  namespace, the version, and the checks on a session_id, a serial and a
  hash (RFC 8182 §3.5.1.3, §3.5.4).

  Errors and warnings are `%{rule, rfc, message}`; errors from the XML
  parser keep its `clause` and `offset`.
  """

  @namespace "http://www.ripe.net/rpki/rrdp"

  @type problem :: %{
          required(:rule) => atom(),
          required(:rfc) => String.t(),
          required(:message) => String.t(),
          optional(:clause) => String.t(),
          optional(:offset) => non_neg_integer()
        }

  @doc "The RRDP XML namespace (RFC 8182 §3.5.1.3)."
  @spec namespace() :: String.t()
  def namespace, do: @namespace

  @doc """
  Checks a root element's attributes, shared by the three files: exactly
  `xmlns` (the RRDP namespace), `version` ("1"), `session_id` and
  `serial` (RFC 8182 §3.5.1.3, §3.5.2.3, §3.5.3.3, §3.5.4). Returns the
  session_id (as given), the serial and any warnings, or an error; `rfc`
  is the section that rules the file.
  """
  @spec root(%{String.t() => String.t()}, String.t()) ::
          {:ok, String.t(), pos_integer(), [problem()]} | {:error, problem()}
  def root(attrs, rfc) do
    with :ok <- attributes(attrs, ~w(xmlns version session_id serial), [], "root", rfc),
         :ok <- namespace(attrs, rfc),
         :ok <- version(attrs["version"], rfc),
         {:ok, warnings} <- session(attrs["session_id"], rfc),
         {:ok, serial} <- serial(attrs["serial"], rfc) do
      {:ok, attrs["session_id"], serial, warnings}
    end
  end

  @doc """
  Checks that `attrs` has every name in `required`, nothing beyond those
  and `optional` (and `xmlns`), for the schema (RFC 8182 §3.5.4).
  """
  @spec attributes(map(), [String.t()], [String.t()], String.t(), String.t()) ::
          :ok | {:error, problem()}
  def attributes(attrs, required, optional, element, rfc) do
    names = Map.keys(attrs)

    cond do
      missing = Enum.find(required, &(&1 not in names)) ->
        error(:missing_attribute, rfc, "#{element} has no #{missing} attribute")

      extra = Enum.find(names, &(&1 not in (required ++ optional ++ ["xmlns"]))) ->
        error(
          :unexpected_attribute,
          rfc,
          "#{element} has an attribute #{extra} the schema doesn't allow"
        )

      true ->
        :ok
    end
  end

  @doc "Checks that an element's `xmlns`, if it has one, is the RRDP namespace."
  @spec namespace(map(), String.t()) :: :ok | {:error, problem()}
  def namespace(attrs, rfc) do
    case Map.get(attrs, "xmlns", @namespace) do
      @namespace ->
        :ok

      other ->
        error(:namespace, rfc, "the XML namespace must be #{@namespace}, not #{inspect(other)}")
    end
  end

  defp version("1", _rfc), do: :ok

  defp version(other, rfc),
    do: error(:version, rfc, "the version attribute must be \"1\", not #{inspect(other)}")

  @doc """
  Checks a session_id (RFC 8182 §3.5.1.3: "a random version 4 UUID"). A
  UUID of another version or variant is a warning, `session_not_v4`
  (D-042); anything that isn't a UUID is an error.

      iex> Lumina.RRDP.session("9df4b597-af9e-4dca-bdda-719cce2c4e28", "8182#3.5.1.3")
      {:ok, []}
      iex> {:ok, [%{rule: :session_not_v4}]} = Lumina.RRDP.session("3025d864-54b5-502e-9a2f-6f4b48f31bdd", "8182#3.5.1.3")
      iex> {:error, %{rule: :session_id}} = Lumina.RRDP.session("1", "8182#3.5.1.3")

  """
  @spec session(String.t(), String.t()) :: {:ok, [problem()]} | {:error, problem()}
  def session(id, rfc) do
    hex = ~r/\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\z/

    cond do
      not (id =~ hex) ->
        error(:session_id, rfc, "the session_id must be a UUID, not #{inspect(id)}")

      String.at(id, 14) == "4" and String.downcase(String.at(id, 19)) in ~w(8 9 a b) ->
        {:ok, []}

      true ->
        {:ok,
         [
           %{
             rule: :session_not_v4,
             rfc: "8182#3.5.1.3",
             message: "the session_id #{id} isn't a version 4 UUID (D-042)"
           }
         ]}
    end
  end

  @doc """
  Parses a serial: "an unbounded, unsigned positive integer in decimal
  format" (RFC 8182 §3.5.1.3).

      iex> Lumina.RRDP.serial("128436", "8182#3.5.1.3")
      {:ok, 128436}
      iex> {:error, %{rule: :serial}} = Lumina.RRDP.serial("0", "8182#3.5.1.3")
      iex> {:error, %{rule: :serial}} = Lumina.RRDP.serial("+1", "8182#3.5.1.3")

  """
  @spec serial(String.t() | nil, String.t()) :: {:ok, pos_integer()} | {:error, problem()}
  def serial(text, rfc) when is_binary(text) do
    if text =~ ~r/\A[0-9]+\z/ and String.to_integer(text) > 0,
      do: {:ok, String.to_integer(text)},
      else: serial(nil, rfc, text)
  end

  def serial(nil, rfc), do: serial(nil, rfc, nil)

  defp serial(_, rfc, text),
    do: error(:serial, rfc, "a serial must be a positive decimal integer, not #{inspect(text)}")

  @doc """
  Parses a hash attribute: "the hexadecimal encoding of the SHA-256 hash"
  (RFC 8182 §3.5.1.3), so exactly 64 hex digits, either case. Returns the
  32 raw bytes.
  """
  @spec hash(String.t(), String.t()) :: {:ok, <<_::256>>} | {:error, problem()}
  def hash(text, rfc) do
    case byte_size(text) == 64 and Base.decode16(text, case: :mixed) do
      {:ok, bytes} -> {:ok, bytes}
      _ -> error(:hash, rfc, "a hash must be 64 hex digits (SHA-256), not #{inspect(text)}")
    end
  end

  @doc false
  @spec error(atom(), String.t(), String.t()) :: {:error, problem()}
  def error(rule, rfc, message), do: {:error, %{rule: rule, rfc: rfc, message: message}}

  @doc false
  # An XML parser error as an RRDP problem: the file isn't well-formed.
  @spec xml_error(Lumina.RRDP.XML.error() | {:file, term()}, String.t()) :: {:error, problem()}
  def xml_error({:file, reason}, rfc),
    do: error(:file, rfc, "the file can't be read: #{:file.format_error(reason)}")

  def xml_error(%{} = error, rfc), do: {:error, Map.put(error, :rfc, rfc)}

  @doc false
  # Whitespace-only text is allowed between elements and inside elements
  # with no content.
  @spec blank?(binary()) :: boolean()
  def blank?(text), do: text =~ ~r/\A[ \t\n]*\z/
end

defmodule Lumina.URITest do
  @moduledoc """
  Tests repository URI parsing, normalization and cache-path mapping
  (`Lumina.URI`, #70). URIs come from certificates anyone can publish and
  become paths on disk, so besides the normalization rules (RFC 3986 §6.2)
  the tests pin every rejection rule, and check over a corpus of hostile
  inputs that no accepted URI maps outside the cache root. Real URIs, from
  Barry fixtures and the RIR TALs, must parse and map as expected.
  """
  use ExUnit.Case, async: true
  doctest Lumina.URI

  alias Lumina.{TAL, URI}

  @root "/cache"

  defp normal(string) do
    {:ok, uri} = URI.parse(string)
    to_string(uri)
  end

  defp rule(string) do
    {:error, %{rule: rule}} = URI.parse(string)
    rule
  end

  defp path!(string) do
    {:ok, uri} = URI.parse(string)
    URI.cache_path(uri, @root)
  end

  describe "normalization" do
    @tag rfc: "3986#6.2.2.1"
    test "scheme and host are lowercased; the path keeps its case" do
      assert normal("RSYNC://Rpki.Example.NET/Repo/CA.cer") ==
               "rsync://rpki.example.net/Repo/CA.cer"

      assert normal("HTTPS://Rpki.Example.NET/TA.cer") == "https://rpki.example.net/TA.cer"
    end

    @tag rfc: ["3986#6.2.3", "5781#2"]
    test "the default port and an empty port are dropped; other ports are kept" do
      assert normal("rsync://h.example:873/m") == "rsync://h.example/m"
      assert normal("rsync://h.example:/m") == "rsync://h.example/m"
      assert normal("rsync://h.example:0873/m") == "rsync://h.example/m"
      assert normal("https://h.example:443/ta.cer") == "https://h.example/ta.cer"
      assert normal("rsync://h.example:8873/m") == "rsync://h.example:8873/m"
      assert normal("https://h.example:873/ta.cer") == "https://h.example:873/ta.cer"
    end

    @tag rfc: ["6487#4.8.8.1", "6481#2"],
         doc: """
         F-016: no RFC says whether a caRepository URI ends in "/". Both forms
         must name the same directory, module and cache path (#43).
         """
    test "a trailing slash doesn't change the URI, its module or its cache path" do
      {:ok, without} = URI.parse("rsync://localhost:8873/rpki/ca1")
      {:ok, with} = URI.parse("rsync://localhost:8873/rpki/ca1/")

      assert without == with
      assert URI.module(without) == URI.module(with)
      assert URI.cache_path(without, @root) == URI.cache_path(with, @root)
      assert normal("rsync://h.example/") == "rsync://h.example"
    end

    @tag rfc: "3986#3.2.2"
    test "IPv6 literals are accepted, lowercased, with or without a port" do
      assert normal("rsync://[2001:DB8::1]/m") == "rsync://[2001:db8::1]/m"
      assert normal("rsync://[::1]:8873/m") == "rsync://[::1]:8873/m"
      assert path!("rsync://[::1]:8873/m/x.cer") == "/cache/rsync/[::1]:8873/m/x.cer"
    end
  end

  describe "rejection rules" do
    @tag rfc: "8630#2.2"
    test "only rsync and https are accepted" do
      assert rule("http://h.example/ta.cer") == :unsupported_scheme
      assert rule("ftp://h.example/ta.cer") == :unsupported_scheme
      assert rule("file:///etc/passwd") == :unsupported_scheme
      assert rule("rsync:h.example/m") == :missing_authority
      assert rule("h.example/m") == :missing_authority
    end

    @tag rfc: "3986#7.5",
         doc:
           "RFC 5781 allows user@ in rsync URIs; RPKI repositories are public, so Lumina doesn't."
    test "user information is rejected" do
      assert rule("rsync://user@h.example/m") == :userinfo
      assert rule("https://user:pw@h.example/ta.cer") == :userinfo
    end

    @tag rfc: "3986#3.2.2"
    test "an empty, malformed or non-ASCII host is rejected" do
      assert rule("rsync:///m") == :invalid_host
      assert rule("rsync://:873/m") == :invalid_host
      assert rule("rsync://../m") == :invalid_host
      assert rule("rsync://./m") == :invalid_host
      assert rule("rsync://h..example/m") == :invalid_host
      assert rule("rsync://h.example./m") == :invalid_host
      assert rule("rsync://h%2Eexample/m") == :invalid_host
      assert rule("rsync://hé.example/m") == :invalid_host
      assert rule("rsync://[::1/m") == :invalid_host
      assert rule("rsync://[v1.x]/m") == :invalid_host
    end

    @tag rfc: "3986#3.2.3"
    test "a port outside 1-65535 or with non-digits is rejected" do
      assert rule("rsync://h.example:0/m") == :invalid_port
      assert rule("rsync://h.example:65536/m") == :invalid_port
      assert rule("rsync://h.example:+873/m") == :invalid_port
      assert rule("rsync://h.example:87a/m") == :invalid_port
      assert rule("rsync://h.example:8:73/m") == :invalid_port
    end

    @tag rfc: ["3986#3.4", "3986#3.5"]
    test "queries and fragments are rejected" do
      assert rule("https://h.example/ta.cer?x=1") == :query
      assert rule("https://h.example/ta.cer#top") == :fragment
      assert rule("rsync://h.example?m") == :invalid_host
    end

    @tag rfc: ["3986#3.3", "3986#6.2.2.3"],
         doc:
           "Dot segments are rejected, not resolved: resolving them is how a URI escapes the cache."
    test "dot segments and empty segments are rejected" do
      assert rule("rsync://h.example/m/../x") == :dot_segment
      assert rule("rsync://h.example/m/./x") == :dot_segment
      assert rule("rsync://h.example/..") == :dot_segment
      assert rule("rsync://h.example/m//x") == :empty_segment
      assert rule("rsync://h.example//m") == :empty_segment
      assert rule("rsync://h.example/m//") == :empty_segment
    end

    @tag rfc: ["3986#2.1", "5781#2"],
         doc:
           "Decoding percent-encoding would give one file two spellings, and %2F or %2E%2E a way out."
    test "percent-encoding is rejected" do
      assert rule("rsync://h.example/m/%2E%2E/x") == :percent_encoding
      assert rule("rsync://h.example/m/a%2Fb") == :percent_encoding
      assert rule("rsync://h.example/m/a%00") == :percent_encoding
      assert rule("rsync://h.example/m/%41.cer") == :percent_encoding
    end

    @tag rfc: "3986#3.3"
    test "characters outside pchar are rejected" do
      assert rule("rsync://h.example/m/a b.cer") == :invalid_character
      assert rule("rsync://h.example/m/a\\b.cer") == :invalid_character
      assert rule("rsync://h.example/m/a\nb.cer") == :invalid_character
      assert rule("rsync://h.example/m/é.cer") == :invalid_character
      assert rule("rsync://h.example/m/a\"b") == :invalid_character
    end

    test "every error names its rule, RFC section and reason" do
      assert {:error, %{rule: :dot_segment, rfc: "3986#3.3", message: message}} =
               URI.parse("rsync://h.example/m/../x")

      assert message =~ "\"..\""
    end
  end

  describe "modules" do
    @tag rfc: "5781#2"
    test "an rsync URI's module is its first path segment" do
      {:ok, uri} = URI.parse("rsync://repository.lacnic.net/rpki/lacnic/rta-lacnic-rpki.cer")
      {:ok, module} = URI.module(uri)

      assert to_string(module) == "rsync://repository.lacnic.net/rpki"
      assert URI.module(module) == {:ok, module}
    end

    test "an rsync URI with no path, and an https URI, have no module" do
      {:ok, bare} = URI.parse("rsync://h.example/")
      {:ok, https} = URI.parse("https://h.example/ta.cer")

      assert {:error, %{rule: :no_module}} = URI.module(bare)
      assert {:error, %{rule: :no_module}} = URI.module(https)
    end
  end

  describe "cache paths" do
    test "a URI maps to <root>/<scheme>/<host[:port]>/<path>" do
      assert path!("rsync://localhost:8873/rpki/ca1/roa1.roa") ==
               "/cache/rsync/localhost:8873/rpki/ca1/roa1.roa"

      assert path!("https://rrdp.lacnic.net/ta/rta-lacnic-rpki.cer") ==
               "/cache/https/rrdp.lacnic.net/ta/rta-lacnic-rpki.cer"
    end

    test "rsync and https copies of the same host and path don't share a cache path" do
      refute path!("rsync://rpki.ripe.net/ta/ripe-ncc-ta.cer") ==
               path!("https://rpki.ripe.net/ta/ripe-ncc-ta.cer")
    end

    @tag doc: """
         Every combination of a hostile host and a hostile path is either
         rejected or maps strictly inside the cache root, and a rejected one
         always names a rule.
         """
    test "no accepted URI maps outside the cache root" do
      hosts = ["h.example", "..", ".", "", "h.example:8873", "[::1]", "a/b", "%2e%2e", "~"]

      paths = [
        "",
        "/",
        "/m",
        "/m/x.cer",
        "/..",
        "/../x",
        "/m/../../x",
        "/m/./x",
        "//x",
        "/%2e%2e/x",
        "/m/..%2Fx",
        "/~/x",
        "/m/.../x",
        "/m/..x",
        "/m/x..",
        "/m\\..\\x",
        "/m/\u0000x"
      ]

      results =
        for scheme <- ["rsync", "https"], host <- hosts, path <- paths do
          case URI.parse("#{scheme}://#{host}#{path}") do
            {:ok, uri} ->
              cache_path = URI.cache_path(uri, @root)
              expanded = Path.expand(cache_path)

              assert String.starts_with?(expanded, @root <> "/"), cache_path
              assert expanded == cache_path, cache_path
              :ok

            {:error, %{rule: rule}} when is_atom(rule) ->
              :error
          end
        end

      # The corpus must exercise both outcomes.
      assert :ok in results
      assert :error in results
    end
  end

  describe "real URIs" do
    @tag rfc: "8630#2.2"
    test "every URI in every RIR TAL parses, and its text is already normal" do
      for file <- Path.wildcard("test/fixtures/tals/rir/*.tal") do
        {:ok, tal} = TAL.decode_file(file)

        for uri <- tal.uris do
          assert normal(uri) == uri, "#{file}: #{uri}"
        end
      end
    end

    @tag rfc: "5781#2"
    test "every Barry TAL's rsync URI is in module rpki on localhost:8873" do
      for dir <- Mix.Lumina.Fixtures.case_dirs() do
        {:ok, tal} = TAL.decode_file(Path.join(dir, "case.tal"))
        [rsync] = Enum.filter(tal.uris, &String.starts_with?(&1, "rsync:"))
        {:ok, uri} = URI.parse(rsync)

        assert {:ok, module} = URI.module(uri)
        assert to_string(module) == "rsync://localhost:8873/rpki", dir
      end
    end
  end
end

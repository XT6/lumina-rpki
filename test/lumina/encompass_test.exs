defmodule Lumina.EncompassTest do
  @moduledoc """
  Tests the resource set operations resource inclusion needs (#152):
  `Lumina.Resources.intervals/2`, `encompasses?/2` and `outside/2`.

  RFC 6487 §7.1 defines "encompass" through "more specific" and "equal"
  ranges; RFC 3779 §2.3 and §3.3 say a certificate's resources must be
  "subsumed by" its issuer's. IPv4, IPv6 and AS numbers are compared
  separately (erratum 5188 to RFC 6487 §7.1), and as sets, not range by
  range (D-027, F-034): a child range spanning two adjacent ranges of a
  parent is encompassed. `outside/2` gives exactly what an overclaim
  claims beyond the issuer, for reporting (#155).
  """
  use ExUnit.Case, async: true

  alias Lumina.Resources

  @none %{ipv4: [], ipv6: [], as: []}
  @ten {:prefix, 0x0A000000, 8}
  @doc_v6 {:prefix, 0x20010DB8000000000000000000000000, 32}
  @v6_max 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF

  defp set(fields), do: Map.merge(@none, Map.new(fields))

  describe "encompassed" do
    @tag rfc: ["6487#7.1", "3779#2.3", "3779#3.3"]
    test "equal sets encompass each other" do
      x = set(ipv4: [@ten], ipv6: [@doc_v6], as: [{:range, 64496, 64511}])
      assert Resources.encompasses?(x, x)
      assert Resources.outside(x, x) == @none
    end

    @tag rfc: ["6487#7.1", "3779#2.3", "3779#3.3"]
    test "more specific ranges are encompassed" do
      x = set(ipv4: [@ten], ipv6: [@doc_v6], as: [{:range, 64496, 64511}])

      y =
        set(
          ipv4: [{:prefix, 0x0A010000, 16}, {:range, 0x0A020001, 0x0A0200FE}],
          ipv6: [{:prefix, 0x20010DB8000100000000000000000000, 48}],
          as: [{:id, 64500}, {:range, 64502, 64504}]
        )

      assert Resources.encompasses?(x, y)
      refute Resources.encompasses?(y, x)
    end

    @tag rfc: ["6487#7.1", "3779#2.2.3.7"],
         doc: "10.0.0.0/8 written as the range 10.0.0.0-10.255.255.255, either way round."
    test "a prefix and a range covering the same addresses are equal" do
      range = set(ipv4: [{:range, 0x0A000000, 0x0AFFFFFF}])
      prefix = set(ipv4: [@ten])
      assert Resources.encompasses?(prefix, range)
      assert Resources.encompasses?(range, prefix)
    end

    @tag rfc: ["6487#7.1", "3779#3.3"]
    test "AS ids and ranges mix: ids inside a range, and a range made of ids" do
      assert Resources.encompasses?(
               set(as: [{:range, 100, 200}]),
               set(as: [{:id, 100}, {:id, 200}, {:range, 150, 160}])
             )

      assert Resources.encompasses?(
               set(as: [{:id, 1}, {:id, 2}, {:id, 3}]),
               set(as: [{:range, 1, 3}])
             )
    end

    @tag rfc: ["6487#7.1", "3779#2.3"],
         doc: """
         D-027, F-034. The parent lists 10.0.0.0/9 and 10.128.0.0/9, which
         RFC 3779 §2.2.3.6 says must be combined (the profile rejects
         that); the child's 10.0.0.0/8 spans both. Read literally, RFC
         6487 §7.1 wants one range of the parent to cover it.
         """
    test "a child range spanning two adjacent parent ranges is encompassed (set semantics)" do
      x = set(ipv4: [{:prefix, 0x0A000000, 9}, {:prefix, 0x0A800000, 9}])
      assert Resources.encompasses?(x, set(ipv4: [@ten]))

      assert Resources.encompasses?(
               set(as: [{:range, 1, 9}, {:range, 10, 20}]),
               set(as: [{:range, 5, 15}])
             )
    end

    @tag rfc: ["6487#7.1", "3779#2.3", "3779#3.3"]
    test "the empty set is encompassed by anything, even the empty set" do
      assert Resources.encompasses?(@none, @none)
      assert Resources.encompasses?(set(ipv4: [@ten]), @none)
    end
  end

  describe "not encompassed" do
    @tag rfc: ["6487#7.1", "3779#2.3"],
         doc: "One address below 10.0.0.0/8, then one above; the difference is that address."
    test "one address outside, at either boundary, and the difference is exactly that address" do
      x = set(ipv4: [@ten])

      below = set(ipv4: [{:range, 0x09FFFFFF, 0x0A0000FF}])
      refute Resources.encompasses?(x, below)
      assert Resources.outside(below, x) == set(ipv4: [{:prefix, 0x09FFFFFF, 32}])

      above = set(ipv4: [{:range, 0x0AFFFF00, 0x0B000000}])
      refute Resources.encompasses?(x, above)
      assert Resources.outside(above, x) == set(ipv4: [{:prefix, 0x0B000000, 32}])
    end

    @tag rfc: ["6487#7.1", "3779#3.3"]
    test "one AS number outside, at either boundary, and the difference is exactly that number" do
      x = set(as: [{:range, 64496, 64511}])

      assert Resources.outside(set(as: [{:range, 64495, 64500}]), x) ==
               set(as: [{:id, 64495}])

      assert Resources.outside(set(as: [{:id, 64496}, {:id, 64512}]), x) ==
               set(as: [{:id, 64512}])
    end

    @tag rfc: ["6487#7.1", "3779#2.3"],
         doc:
           "The gap between two parent ranges is shown as prefixes where it is one, else a range."
    test "the difference is shown as prefixes where they fit, ranges otherwise" do
      x = set(ipv4: [{:prefix, 0x0A000000, 9}, {:prefix, 0x0B000000, 8}])
      y = set(ipv4: [{:range, 0x0A000000, 0x0B0000FF}])
      assert Resources.outside(y, x) == set(ipv4: [{:prefix, 0x0A800000, 9}])

      y = set(ipv4: [{:range, 0x0A000000, 0x0C000002}])

      assert Resources.outside(y, x) ==
               set(ipv4: [{:prefix, 0x0A800000, 9}, {:range, 0x0C000000, 0x0C000002}])

      assert Resources.format({:range, 0x0C000000, 0x0C000002}, :ipv4) ==
               "12.0.0.0-12.0.0.2"
    end

    @tag rfc: ["6487#7.1", "3779#2.3", "3779#3.3"]
    test "nothing non-empty is encompassed by the empty set" do
      refute Resources.encompasses?(@none, set(ipv4: [{:prefix, 0x0A000000, 32}]))
      refute Resources.encompasses?(@none, set(as: [{:id, 0}]))
      assert Resources.outside(set(as: [{:id, 0}]), @none) == set(as: [{:id, 0}])
    end

    @tag rfc: ["6487#7.1", "3779#2.3"],
         doc: """
         Erratum 5188: §7.1 compares "two IP address or two AS number sets".
         The IPv4 and IPv6 address families are separate too: 0.0.0.0/0
         doesn't cover ::/96, though both are the integers 0 to 2^32-1.
         """
    test "IPv4, IPv6 and AS numbers are independent" do
      x = set(ipv4: [{:prefix, 0, 0}], as: [{:range, 0, 4_294_967_295}])
      y = set(ipv6: [{:prefix, 0, 96}])
      refute Resources.encompasses?(x, y)
      assert Resources.outside(y, x) == set(ipv6: [{:prefix, 0, 96}])

      refute Resources.encompasses?(set(ipv6: [{:prefix, 0, 0}]), set(ipv4: [@ten]))
    end
  end

  describe "extremes" do
    @tag rfc: ["6487#7.1", "3779#2.3", "3779#3.3"],
         doc:
           "0.0.0.0/0, ::/0 and AS0-AS4294967295 hold everything; the last address or number of each is outside anything that stops one short."
    test "the ends of the address and AS number spaces" do
      all =
        set(ipv4: [{:prefix, 0, 0}], ipv6: [{:prefix, 0, 0}], as: [{:range, 0, 4_294_967_295}])

      ends =
        set(
          ipv4: [{:prefix, 0, 32}, {:prefix, 0xFFFFFFFF, 32}],
          ipv6: [{:prefix, 0, 128}, {:prefix, @v6_max, 128}],
          as: [{:id, 0}, {:id, 4_294_967_295}]
        )

      assert Resources.encompasses?(all, ends)
      assert Resources.encompasses?(all, all)

      short =
        set(
          ipv4: [{:range, 0, 0xFFFFFFFE}],
          ipv6: [{:range, 0, @v6_max - 1}],
          as: [{:range, 0, 4_294_967_294}]
        )

      assert Resources.outside(all, short) ==
               set(
                 ipv4: [{:prefix, 0xFFFFFFFF, 32}],
                 ipv6: [{:prefix, @v6_max, 128}],
                 as: [{:id, 4_294_967_295}]
               )

      assert Resources.outside(all, @none) == all
    end
  end

  describe "intervals/2" do
    @tag rfc: ["3779#2.2.3.6", "3779#3.2.3.4"],
         doc:
           "Unsorted, overlapping and adjacent entries, as a non-canonical certificate might list them."
    test "sorts, merges overlapping and adjacent entries, and drops inverted ranges" do
      assert Resources.intervals(
               [
                 {:prefix, 0x0A800000, 9},
                 {:range, 0x0A000000, 0x0A0000FF},
                 {:prefix, 0x0A000000, 9}
               ],
               :ipv4
             ) == [{0x0A000000, 0x0AFFFFFF}]

      assert Resources.intervals(
               [{:range, 10, 20}, {:id, 30}, {:range, 21, 25}, {:range, 9, 1}],
               :as
             ) ==
               [{10, 25}, {30, 30}]
    end
  end

  describe "against brute force" do
    @tag rfc: ["6487#7.1", "3779#3.3"],
         doc: """
         1,000 pairs of random AS sets within 0..63 (fixed seed), mixing
         ids and ranges, overlapping and adjacent: `outside/2` must give
         exactly the numbers of y not in x, and `encompasses?/2` must agree.
         """
    test "outside/2 matches a number-by-number set difference" do
      :rand.seed(:exsss, {1, 2, 3})

      random_set = fn ->
        for _ <- 1..:rand.uniform(4) do
          a = :rand.uniform(64) - 1
          b = min(a + :rand.uniform(8) - 1, 63)
          if a == b, do: {:id, a}, else: {:range, a, b}
        end
      end

      numbers = fn list ->
        MapSet.new(
          Enum.flat_map(list, fn
            {:id, n} -> [n]
            {:range, a, b} -> Enum.to_list(a..b)
          end)
        )
      end

      for _ <- 1..1000 do
        x = random_set.()
        y = random_set.()
        expected = MapSet.difference(numbers.(y), numbers.(x))
        %{as: left} = Resources.outside(set(as: y), set(as: x))
        assert numbers.(left) == expected
        assert Resources.encompasses?(set(as: x), set(as: y)) == (MapSet.size(expected) == 0)
      end
    end
  end
end

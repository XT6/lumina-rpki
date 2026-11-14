# Regenerates doc/token-usage.md: the Claude Code token usage of building
# Lumina, per milestone, priced at API list prices.
#
#   elixir scripts/token_usage.exs [TRANSCRIPT_DIR]
#
# TRANSCRIPT_DIR is the Claude Code project directory holding the session
# transcripts (*.jsonl, subagents included); the default is the one for this
# checkout under ~/.claude/projects. Milestone windows come from GitHub
# (`gh issue list`), so gh must be logged in. Needs Elixir 1.18+ (JSON).

defmodule TokenUsage do
  @out "doc/token-usage.md"

  # USD per million tokens: input, output, cache write (5 min, 1 h), cache
  # read. From the Claude API pricing table bundled with Claude Code
  # (cached 2026-10-06); cache writes are 1.25x (5 min) and 2x (1 h) input.
  @prices %{
    "claude-opus-5-5" => %{i: 4.0, o: 20.0, w5: 5.0, w1: 8.0, r: 0.20},
    "claude-haiku-5-5" => %{i: 0.10, o: 0.50, w5: 0.125, w1: 0.20, r: 0.01}
  }

  # A gap between model calls counts as working time up to this long.
  @active_gap 600

  def main(args) do
    dir = List.first(args) || default_dir()
    calls = calls(dir)
    windows = windows()
    prs = merged_prs()

    rows =
      for {name, _until} <- windows do
        mine = Enum.filter(calls, &(window(&1.at, windows) == name))
        %{name: name, prs: Enum.count(prs, &(window(&1, windows) == name))} |> Map.merge(sum(mine))
      end

    File.write!(@out, render(rows, sum(calls), length(prs), calls))
    IO.puts("wrote #{@out}")
  end

  defp default_dir do
    slug = File.cwd!() |> String.replace(~r/[^A-Za-z0-9]/, "-")
    Path.expand("~/.claude/projects/" <> slug)
  end

  # One entry per model response (streamed chunks share a message id).
  defp calls(dir) do
    Path.wildcard(Path.join(dir, "**/*.jsonl"))
    |> Enum.flat_map(fn file ->
      file
      |> File.stream!()
      |> Stream.map(&decode/1)
      |> Stream.filter(&match?(%{"message" => %{"usage" => %{}}}, &1))
      |> Enum.uniq_by(& &1["message"]["id"])
      |> Enum.map(&call/1)
    end)
    |> Enum.sort_by(& &1.at, DateTime)
  end

  defp decode(line) do
    case JSON.decode(line) do
      {:ok, map} when is_map(map) -> map
      _ -> %{}
    end
  end

  defp call(%{"timestamp" => ts, "message" => %{"model" => model, "usage" => u}}) do
    {:ok, at, _} = DateTime.from_iso8601(ts)
    split = u["cache_creation"] || %{}
    w5 = split["ephemeral_5m_input_tokens"] || 0
    w1 = split["ephemeral_1h_input_tokens"] || 0
    # Without a split, the write is this session's default 1-hour TTL.
    w1 = if w1 + w5 == 0, do: u["cache_creation_input_tokens"] || 0, else: w1

    tokens = %{
      i: u["input_tokens"] || 0,
      o: u["output_tokens"] || 0,
      r: u["cache_read_input_tokens"] || 0,
      w1: w1,
      w5: w5
    }

    price = Map.fetch!(@prices, model)
    cost = Enum.reduce(tokens, 0.0, fn {k, n}, acc -> acc + n * price[k] / 1.0e6 end)
    %{at: at, model: model, tokens: tokens, cost: cost}
  end

  # [{name, until}]: setup until the first M0 issue, then each milestone until
  # its last issue closed, the first one still open taking the rest.
  defp windows do
    {json, 0} =
      System.cmd("gh", ~w(issue list --state all --limit 1000 --json milestone,closedAt,createdAt))

    issues =
      for %{"milestone" => %{"title" => "M" <> _ = title}} = issue <- JSON.decode!(json),
          do: Map.put(issue, "m", title)

    by = Enum.group_by(issues, & &1["m"])
    titles = by |> Map.keys() |> Enum.sort()

    setup_end =
      by |> Map.fetch!(hd(titles)) |> Enum.map(&time(&1["createdAt"])) |> Enum.min(DateTime)

    {windows, _done} =
      Enum.map_reduce(titles, false, fn title, done ->
        closed = Enum.map(by[title], &time(&1["closedAt"]))

        cond do
          done -> {nil, true}
          Enum.all?(closed) -> {{title, Enum.max(closed, DateTime)}, false}
          true -> {{title <> " (in progress)", nil}, true}
        end
      end)

    [{"Setup and planning", setup_end} | Enum.reject(windows, &is_nil/1)]
  end

  defp time(nil), do: nil

  defp time(iso) do
    {:ok, t, _} = DateTime.from_iso8601(iso)
    t
  end

  defp window(at, windows) do
    Enum.find_value(windows, fn {name, until} ->
      if until == nil or DateTime.compare(at, until) != :gt, do: name
    end) || "after the last milestone"
  end

  defp merged_prs do
    {json, 0} = System.cmd("gh", ~w(pr list --state merged --limit 1000 --json mergedAt))
    for %{"mergedAt" => at} <- JSON.decode!(json), do: time(at)
  end

  defp sum(calls) do
    tokens =
      Enum.reduce(calls, %{i: 0, o: 0, r: 0, w1: 0, w5: 0}, fn c, acc ->
        Map.merge(acc, c.tokens, fn _k, a, b -> a + b end)
      end)

    times = Enum.map(calls, & &1.at)

    active =
      times
      |> Enum.zip(Enum.drop(times, 1))
      |> Enum.map(fn {a, b} -> min(DateTime.diff(b, a), @active_gap) end)
      |> Enum.sum()

    %{
      calls: length(calls),
      tokens: tokens,
      total: tokens |> Map.values() |> Enum.sum(),
      cost: calls |> Enum.map(& &1.cost) |> Enum.sum(),
      active: active / 3600
    }
  end

  defp render(rows, total, prs, calls) do
    first = calls |> List.first() |> Map.get(:at)
    last = calls |> List.last() |> Map.get(:at)
    t = total.tokens

    """
    # Token usage

    What building Lumina with Claude Code has used, per milestone, priced at
    Claude API list prices. Generated by `elixir scripts/token_usage.exs`
    from the session transcript and the GitHub milestones; updated with
    every PR. Talk material, like `rfc-findings.md`.

    Last updated: #{iso(last)}. Session started #{iso(first)}.

    | Milestone | Model calls | Active hours | Tokens (M) | Output (M) | PRs merged | Cost (USD) |
    | --- | ---: | ---: | ---: | ---: | ---: | ---: |
    #{Enum.map_join(rows, "\n", &row/1)}
    | **Total** | **#{total.calls}** | **#{f1(total.active)}** | **#{m1(total.total)}** | **#{m2(t.o)}** | **#{prs}** | **#{money(total.cost)}** |

    ## By kind of token

    | Kind | Tokens (M) | Cost (USD) |
    | --- | ---: | ---: |
    #{kind_rows(calls)}

    Without prompt caching, every cached token would have been billed as
    input: about #{money(uncached(calls))} instead of #{money(total.cost)}.

    ## How it is counted

    - **Source:** the per-response `usage` records in the Claude Code
      transcript of the single session that built Lumina (subagent
      transcripts included), one record per model response.
    - **Milestones:** each response counts toward the milestone being worked
      on at its time: setup until the first M0 issue was filed, then each
      milestone until its last issue closed; the milestone in progress takes
      the rest. Boundaries are approximate (planning issues for later
      milestones were filed earlier).
    - **Active hours:** the gaps between consecutive model calls, each
      counted up to 10 minutes, so breaks and nights don't count.
    - **Prices (USD per million tokens):** Claude Opus 5.5 $4 input, $20
      output, $0.20 cache read, $8 cache write (1-hour TTL, 2x input), $5
      (5-minute TTL); Claude Haiku 5.5 (a few helper calls) $0.10 / $0.50.
      From the pricing table bundled with Claude Code (cached 2026-10-06).
    - **Caveats:** an estimate at list prices, not an invoice; usage the
      transcript doesn't record (for example the calls that summarize the
      conversation when it is compacted) isn't counted.
    """
  end

  defp row(r) do
    "| #{r.name} | #{r.calls} | #{f1(r.active)} | #{m1(r.total)} | #{m2(r.tokens.o)} | #{r.prs} | #{money(r.cost)} |"
  end

  defp kind_rows(calls) do
    labels = [
      r: "Cache reads (context re-sent each turn)",
      o: "Output (code, documents, replies, thinking)",
      w1: "Cache writes, 1-hour TTL",
      w5: "Cache writes, 5-minute TTL",
      i: "Uncached input"
    ]

    Enum.map_join(labels, "\n", fn {k, label} ->
      n = calls |> Enum.map(& &1.tokens[k]) |> Enum.sum()
      cost = calls |> Enum.map(&(&1.tokens[k] * @prices[&1.model][k] / 1.0e6)) |> Enum.sum()
      "| #{label} | #{m2(n)} | #{money(cost)} |"
    end)
  end

  defp uncached(calls) do
    calls
    |> Enum.map(fn %{tokens: t, model: m} ->
      p = @prices[m]
      ((t.i + t.r + t.w1 + t.w5) * p.i + t.o * p.o) / 1.0e6
    end)
    |> Enum.sum()
  end

  defp iso(t), do: t |> DateTime.truncate(:second) |> DateTime.to_iso8601()
  defp f1(x), do: :erlang.float_to_binary(x * 1.0, decimals: 1)
  defp m1(n), do: f1(n / 1.0e6)
  defp m2(n), do: :erlang.float_to_binary(n / 1.0e6, decimals: 2)
  defp money(x), do: "$" <> :erlang.float_to_binary(x * 1.0, decimals: 2)
end

TokenUsage.main(System.argv())

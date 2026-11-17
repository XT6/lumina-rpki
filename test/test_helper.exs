# Tests tagged :barry run the real Barry binary (scripts/install-barry.sh).
# They're excluded when it isn't installed.
barry = Path.join([System.get_env("LUMINA_TOOLS") || "_tools", "bin", "barry"])
exclude = if File.regular?(barry), do: [], else: [:barry]

# Tests tagged :realrepo use the maintainer's local, git-ignored copy of
# the LACNIC repository (test/realrepos/). They're excluded without it.
realrepo = "test/realrepos/repo-lacnic/lacnic/rta-lacnic-rpki.cer"
exclude = if File.regular?(realrepo), do: exclude, else: [:realrepo | exclude]

# Tests tagged :rsync run a real rsync daemon and client
# (Lumina.Test.RsyncDaemon). They're excluded without rsync 3.1.0 or later.
# CI sets LUMINA_REQUIRE_RSYNC so they fail instead of being skipped.
exclude =
  case Lumina.Rsync.check() do
    {:ok, _} ->
      exclude

    {:error, reason} ->
      if System.get_env("LUMINA_REQUIRE_RSYNC"),
        do: raise("LUMINA_REQUIRE_RSYNC is set but rsync isn't usable: #{inspect(reason)}")

      [:rsync | exclude]
  end

# Tests tagged :network reach the live RPKI (the M3 done test mirrors
# LACNIC). They take minutes and depend on the Internet, so they never run
# by default: mix test --only network.
exclude = [:network | exclude]

# Tests tagged :large stream gigabytes through a parser to check its memory
# stays bounded (the RRDP XML parser, #198). They take minutes, so they run
# by hand: mix test --only large.
exclude = [:large | exclude]

# The walk syncs a CA's RRDP repository when its certificate names one
# (D-040, #206). Every Barry fixture names https://localhost:8443/..., so
# tests that serve only rsync would reach for a server that isn't there:
# RRDP is off by default in tests, and those that test it pass rrdp: true.
Application.put_env(:lumina, :rrdp, false)

ExUnit.start(exclude: exclude)

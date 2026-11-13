# Tests tagged :barry run the real Barry binary (scripts/install-barry.sh).
# They're excluded when it isn't installed.
barry = Path.join([System.get_env("LUMINA_TOOLS") || "_tools", "bin", "barry"])
exclude = if File.regular?(barry), do: [], else: [:barry]

# Tests tagged :realrepo use the maintainer's local, git-ignored copy of
# the LACNIC repository (test/realrepos/). They're excluded without it.
realrepo = "test/realrepos/repo-lacnic/lacnic/rta-lacnic-rpki.cer"
exclude = if File.regular?(realrepo), do: exclude, else: [:realrepo | exclude]

ExUnit.start(exclude: exclude)

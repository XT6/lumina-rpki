# Tests tagged :barry run the real Barry binary (scripts/install-barry.sh).
# They're excluded when it isn't installed.
barry = Path.join([System.get_env("LUMINA_TOOLS") || "_tools", "bin", "barry"])
exclude = if File.regular?(barry), do: [], else: [:barry]

ExUnit.start(exclude: exclude)

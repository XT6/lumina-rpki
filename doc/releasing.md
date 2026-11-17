# Releasing

Lumina's version is `0.<last milestone completed>.<patch>` ([D-044](decisions.md#d-044-releases-are-0milestonepatch-tagged-and-published-on-github)). M7 closed, so the first release is `0.7.0`. A release between milestones bumps the patch number (`0.7.1`), and the next milestone's release is `0.8.0`.

Each release is an annotated tag `v<version>` on `main`, and a GitHub release with notes and the `lumina` escript. GitHub attaches the source archives itself.

## Steps

1. **Bump the version** in a PR, against the release's issue:
   - `mix.exs`: `version: "0.8.0"`
   - `doc/output.md`: the `"lumina"` value in the example metadata
2. **Merge it** once CI passes, and update the local `main`.
3. **Build the escript** from that commit, and check it:

   ```sh
   git checkout main && git pull
   mix escript.build
   ./lumina help
   ./lumina print --brief test/fixtures/barry/m0-minimal-valid/rsync/ca1/roa1.roa
   ```

4. **Tag** the merge commit and push the tag:

   ```sh
   git tag -a v0.8.0 -m "Lumina 0.8.0: M8, RRDP"
   git push origin v0.8.0
   ```

5. **Publish the release**, attaching the escript:

   ```sh
   gh release create v0.8.0 lumina --title "Lumina 0.8.0" --notes-file notes.md
   ```

   The notes summarise:
   - the milestone (or the fixes, for a patch release)
   - the decisions made since the last release
   - anything that changes for users: new commands or flags, output formats, cache layout

   They also link the milestone, say which Erlang/OTP version the escript needs (`.tool-versions`), and list the RFC findings the maintainer may want to report.

The escript runs on any host with that Erlang/OTP and rsync 3.1.0 or later. It holds no compiled native code.

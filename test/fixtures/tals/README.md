# Test TALs

Trust Anchor Locators for testing TAL parsing (RFC 8630 §2.2).

| Folder | Contents |
| --- | --- |
| `cases/` | Hand-written TALs, valid and malformed, one folder per case (#55) |
| `rir/` | The RIRs' published TALs, committed only after the maintainer approves each source and its terms (#58) |

## Cases

Each `cases/<id>/` holds:
- **`case.tal`:** the TAL, byte for byte. These files are marked `-text` in `.gitattributes`, so git never converts their line endings. CRLF and trailing whitespace are part of what some cases test, so don't let an editor "fix" them.
- **`case.exs`:** literal metadata (`Mix.Lumina.TALCases`): `id`, `title`, `rationale`, `rfc` and `expected`.

The keys come from the RFC 8630 §2.4 example and from a Barry TA certificate, never from a real RIR.

`expected` is one of:

| Form | Meaning |
| --- | --- |
| `:valid` | parses with no warnings |
| `{:valid, warnings: [%{line: n, rule: r}, ...]}` | parses, with exactly these warnings |
| `{:invalid, %{line: n, rule: r}}` | rejected; the first problem is `r` at line `n` |

## Lines and rules

**Line numbers** start at 1. A problem detected at the end of the file (for example "only comments") is reported at the line after the last one.

These are the rules the TAL parser (#54) reports. The grammar follows RFC 8630 §2.2 strictly (D-002).

| Rule | When |
| --- | --- |
| `empty` | the file is empty |
| `no_uri` | the URI section has no URI: the comments are followed by a blank line or by the end of the file |
| `missing_separator` | a key line follows the URIs with no blank line in between. A URI-section line with no `://` that consists only of base64 characters is taken to be the key. |
| `extra_blank_line` | a second blank line, before or after the key |
| `comment_after_uris` | a `#` line after the first URI |
| `empty_key` | nothing follows the blank line |
| `unsupported_scheme` | a URI whose scheme isn't `rsync` or `https` |
| `invalid_uri` | anything else in the URI section that isn't a valid absolute URI, including indented lines |
| `invalid_utf8` | a comment that isn't UTF-8 |
| `invalid_comment_text` | a comment with control characters (RFC 5198 §2) |
| `bad_base64` | a character outside the base64 alphabet, reported on its line; or bad length or padding, reported on the first key line |
| `not_der` | the key decodes but isn't DER (first key line) |
| `not_spki` | the key is DER but not a `SubjectPublicKeyInfo` (first key line) |

| Warning | When |
| --- | --- |
| `trailing_whitespace` | a line ends in spaces or tabs, one warning per line. The whitespace is ignored. |

## Adding a case

1. Create `cases/<id>/case.tal` byte for byte, and `case.exs` with the rationale and expected outcome.
2. Run `mix lumina.test_catalog`.
3. Every rule above must keep at least one case; `test/tal_cases_test.exs` checks it.

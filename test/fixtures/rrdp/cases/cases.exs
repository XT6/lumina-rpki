# Metadata for the hand-written RRDP files in this directory (#199): one
# map per <id>.xml. Read as data by Lumina.RRDP.FilesTest; see README.md.
[
  %{
    id: "notification-valid",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: :ok,
    rationale:
      "A snapshot and two deltas listed out of order, with a comment between them: the deltas sort by serial and the comment is skipped."
  },
  %{
    id: "notification-no-deltas",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: :ok,
    rationale:
      "Delta elements are optional: a new session has only its snapshot (RFC 8182 section 3.3.1). The whole file on one line, as some servers write it."
  },
  %{
    id: "notification-session-v5",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:warning, :session_not_v4},
    rationale:
      "A version 5 UUID, as prefixlogic serves (TD-003): a warning, and the file is used (D-042)."
  },
  %{
    id: "notification-session-not-uuid",
    kind: :notification,
    rfc: ["8182#3.5.1.3", "8182#3.5.4"],
    expected: {:error, :session_id},
    rationale:
      "session_id=\"1\" matches the schema's [-0-9a-fA-F]+ but isn't a UUID; Barry writes it by default (F-038). Rejected (D-042)."
  },
  %{
    id: "notification-namespace",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :namespace},
    rationale: "The XML namespace MUST be http://www.ripe.net/rpki/rrdp; a similar one is not it."
  },
  %{
    id: "notification-no-namespace",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :missing_attribute},
    rationale: "Without xmlns the elements are in no namespace, not RRDP's."
  },
  %{
    id: "notification-version-2",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :version},
    rationale: "The version attribute MUST be \"1\"; a future version 2 isn't understood."
  },
  %{
    id: "notification-missing-serial",
    kind: :notification,
    rfc: ["8182#3.5.4"],
    expected: {:error, :missing_attribute},
    rationale: "The schema requires serial on notification."
  },
  %{
    id: "notification-extra-attribute",
    kind: :notification,
    rfc: ["8182#3.5.4"],
    expected: {:error, :unexpected_attribute},
    rationale:
      "The schema lists notification's attributes; another one (RFC 8181's tag) doesn't conform."
  },
  %{
    id: "notification-serial-zero",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :serial},
    rationale: "The serial is a positive integer; sessions start at ONE (RFC 8182 section 3.3.1)."
  },
  %{
    id: "notification-serial-negative",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :serial},
    rationale: "The serial is unsigned."
  },
  %{
    id: "notification-serial-hex",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :serial},
    rationale: "The serial is in decimal format."
  },
  %{
    id: "notification-no-snapshot",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :snapshot_count},
    rationale: "A notification MUST contain exactly one snapshot element."
  },
  %{
    id: "notification-two-snapshots",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :snapshot_count},
    rationale: "A notification MUST contain exactly one snapshot element."
  },
  %{
    id: "notification-delta-before-snapshot",
    kind: :notification,
    rfc: ["8182#3.5.4"],
    expected: {:error, :schema},
    rationale:
      "The schema is a sequence: the snapshot, then the deltas. Every live notification surveyed (2026-11-17) puts the snapshot first."
  },
  %{
    id: "notification-delta-gap",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :delta_serials},
    rationale: "Deltas 1 and 3 without 2: they MUST form a contiguous sequence."
  },
  %{
    id: "notification-delta-duplicate",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :delta_serials},
    rationale: "Two deltas for serial 3: which one applies is undefined."
  },
  %{
    id: "notification-delta-above-serial",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :delta_serials},
    rationale:
      "A delta for serial 4 in a notification at serial 3: the sequence runs up to the notification's serial."
  },
  %{
    id: "notification-hash-short",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :hash},
    rationale: "The hash is the hexadecimal SHA-256: 64 digits, not the RFC's shortened example."
  },
  %{
    id: "notification-hash-not-hex",
    kind: :notification,
    rfc: ["8182#3.5.1.3", "8182#3.5.4"],
    expected: {:error, :hash},
    rationale: "64 characters, but not hexadecimal."
  },
  %{
    id: "notification-cross-origin-host",
    kind: :notification,
    rfc: ["9674#3.2"],
    expected: {:error, :cross_origin},
    rationale:
      "The snapshot on another host: a cross-origin reference MUST reject the file (RFC 9674)."
  },
  %{
    id: "notification-cross-origin-port",
    kind: :notification,
    rfc: ["9674#3.2"],
    expected: {:error, :cross_origin},
    rationale: "A delta on the same host but another port: a different origin."
  },
  %{
    id: "notification-cross-origin-http",
    kind: :notification,
    rfc: ["9674#3.2"],
    expected: {:error, :cross_origin},
    rationale: "The snapshot over http: another scheme is another origin."
  },
  %{
    id: "notification-wrong-root",
    kind: :notification,
    rfc: ["8182#3.5.4"],
    expected: {:error, :root},
    rationale: "A snapshot file where the notification was expected."
  },
  %{
    id: "notification-text",
    kind: :notification,
    rfc: ["8182#3.5.4"],
    expected: {:error, :schema},
    rationale: "The schema allows no text in a notification; only whitespace between elements."
  },
  %{
    id: "notification-doctype",
    kind: :notification,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :doctype},
    rationale:
      "A DOCTYPE is rejected by the parser (D-041), and the file with it (not well-formed RRDP)."
  },
  %{
    id: "snapshot-valid",
    kind: :snapshot,
    rfc: ["8182#3.5.2.3"],
    expected: :ok,
    rationale:
      "An XML declaration, two objects, one with base64 on one line and one broken into 64-character lines, and a comment: both objects decode."
  },
  %{
    id: "snapshot-empty",
    kind: :snapshot,
    rfc: ["8182#3.5.4"],
    expected: :ok,
    rationale:
      "A snapshot may have no publish elements (RFC 8182 section 3.3.1: a new repository)."
  },
  %{
    id: "snapshot-session-mismatch",
    kind: :snapshot,
    rfc: ["8182#3.5.2.3"],
    expected: {:error, :session_mismatch},
    rationale: "The session_id MUST match the notification's."
  },
  %{
    id: "snapshot-serial-mismatch",
    kind: :snapshot,
    rfc: ["8182#3.5.2.3"],
    expected: {:error, :serial_mismatch},
    rationale: "The serial MUST match the one the notification gives for the snapshot (3)."
  },
  %{
    id: "snapshot-publish-hash",
    kind: :snapshot,
    rfc: ["8182#3.5.2.3", "8182#3.5.4"],
    expected: {:error, :unexpected_attribute},
    rationale: "A snapshot's publish has no hash attribute: the file is a complete state."
  },
  %{
    id: "snapshot-withdraw",
    kind: :snapshot,
    rfc: ["8182#3.5.4"],
    expected: {:error, :schema},
    rationale: "withdraw belongs in deltas only."
  },
  %{
    id: "snapshot-base64-invalid",
    kind: :snapshot,
    rfc: ["8182#3.5.4"],
    expected: {:error, :base64},
    rationale: "* isn't a base64 character."
  },
  %{
    id: "snapshot-base64-padding-bits",
    kind: :snapshot,
    rfc: ["8182#3.5.4"],
    expected: {:error, :base64},
    rationale:
      "QR== decodes to A with leftover bits set; xsd:base64Binary requires them to be zero, so one object can't have two encodings."
  },
  %{
    id: "snapshot-uri-not-rsync",
    kind: :snapshot,
    rfc: ["8182#4.1"],
    expected: {:error, :bad_uri},
    rationale: "Published objects are named by their rsync URIs (RFC 8182 section 4.1)."
  },
  %{
    id: "snapshot-uri-dot-segment",
    kind: :snapshot,
    rfc: ["8182#4.1"],
    expected: {:error, :bad_uri},
    rationale: "A .. segment could put an object outside the cache; Lumina.URI rejects it."
  },
  %{
    id: "snapshot-uri-module-only",
    kind: :snapshot,
    rfc: ["8182#4.1"],
    expected: {:error, :bad_uri},
    rationale: "rsync://host/module names a module, not an object."
  },
  %{
    id: "snapshot-wrong-root",
    kind: :snapshot,
    rfc: ["8182#3.5.4"],
    expected: {:error, :root},
    rationale: "A delta file where the snapshot was expected."
  },
  %{
    id: "delta-valid",
    kind: :delta,
    rfc: ["8182#3.5.3.3"],
    expected: :ok,
    rationale: "A new object, a replaced object (publish with the old hash) and a withdrawn one."
  },
  %{
    id: "delta-empty",
    kind: :delta,
    rfc: ["8182#3.5.4"],
    expected: {:error, :empty_delta},
    rationale: "The schema requires at least one delta element (delta_element+)."
  },
  %{
    id: "delta-withdraw-no-hash",
    kind: :delta,
    rfc: ["8182#3.5.4"],
    expected: {:error, :missing_attribute},
    rationale: "withdraw requires the hash of the object it removes."
  },
  %{
    id: "delta-withdraw-content",
    kind: :delta,
    rfc: ["8182#3.5.4"],
    expected: {:error, :schema},
    rationale: "withdraw is an empty element; content isn't allowed."
  },
  %{
    id: "delta-session-mismatch",
    kind: :delta,
    rfc: ["8182#3.5.3.3"],
    expected: {:error, :session_mismatch},
    rationale: "The session_id MUST match the notification's."
  },
  %{
    id: "delta-serial-mismatch",
    kind: :delta,
    rfc: ["8182#3.5.3.3"],
    expected: {:error, :serial_mismatch},
    rationale: "The serial MUST match the delta element that refers to the file (3)."
  },
  %{
    id: "delta-hash-short",
    kind: :delta,
    rfc: ["8182#3.5.1.3"],
    expected: {:error, :hash},
    rationale: "Hashes are 64 hex digits, as in the notification."
  }
]

# Metadata for the RRDP sync scenarios over m8-rrdp-three (#209); read as
# data by Lumina.M8DoneTest, which builds each case's files. See README.md.
[
  %{
    id: "mutated-delta-hash",
    from: 2,
    rfc: ["9697#3.1", "9697#4", "9697#5"],
    rationale:
      "The notification at serial 3 lists delta 2, already seen, with another hash: the deltas were rewritten. Warn and take the snapshot.",
    expected: %{outcome: :snapshot, warning: :rrdp_desync, store: :snapshot}
  },
  %{
    id: "unchanged-hashes",
    from: 2,
    rfc: ["9697#3", "8182#3.4.1"],
    rationale:
      "The same notification as the fixture's: delta 2's hash is unchanged, so delta 3 is applied.",
    expected: %{outcome: {:deltas, 1}, store: :snapshot}
  },
  %{
    id: "new-session",
    from: 3,
    rfc: ["8182#3.4.1", "8182#3.4.3"],
    rationale:
      "A new session_id at serial 1, below the store's 3: a new session restarts its serials, so its snapshot is taken.",
    expected: %{outcome: :snapshot, store: :snapshot}
  },
  %{
    id: "serial-gap",
    from: 1,
    rfc: ["8182#3.4.1"],
    rationale:
      "The store is at serial 1; the notification at 3 lists only delta 3, so delta 2 is missing: the snapshot, without fetching any delta.",
    expected: %{outcome: :snapshot, store: :snapshot}
  },
  %{
    id: "serial-lower",
    from: 3,
    rfc: ["8182#3.4.3"],
    rationale: "The same session at serial 2, below the store's 3: rejected, the store kept.",
    expected: %{outcome: {:failed, :serial_not_greater}, error: :serial_not_greater, store: :kept}
  },
  %{
    id: "serial-same",
    from: 3,
    rfc: ["8182#3.4.1"],
    rationale: "The same session and serial: nothing to do, nothing downloaded.",
    expected: %{outcome: :unchanged, store: :kept}
  },
  %{
    id: "notification-missing",
    from: 2,
    rfc: ["8182#3.4.5"],
    rationale:
      "The notification answers 404: the sync fails, the store is kept, and the walk falls back to rsync (D-040).",
    expected: %{outcome: {:failed, :notification_failed}, error: :http_status, store: :kept}
  },
  %{
    id: "notification-invalid",
    from: 2,
    rfc: ["8182#3.5.1.3"],
    rationale: "The notification has version 2: rejected, the store kept.",
    expected: %{outcome: {:failed, :notification_rejected}, error: :version, store: :kept}
  },
  %{
    id: "snapshot-hash-mismatch",
    from: 2,
    rfc: ["8182#3.4.3"],
    rationale:
      "The notification at 3 lists no deltas and a snapshot hash that isn't the file's: rejected, the store kept at 2.",
    expected: %{outcome: {:failed, :snapshot_hash_mismatch}, store: :kept}
  },
  %{
    id: "snapshot-session-mismatch",
    from: 2,
    rfc: ["8182#3.5.2.3"],
    rationale:
      "The snapshot file names another session than the notification: rejected, the store kept.",
    expected: %{outcome: {:failed, :snapshot_rejected}, error: :session_mismatch, store: :kept}
  },
  %{
    id: "snapshot-serial-mismatch",
    from: 2,
    rfc: ["8182#3.5.2.3"],
    rationale:
      "The snapshot file names serial 4 where the notification says 3: rejected, the store kept.",
    expected: %{outcome: {:failed, :snapshot_rejected}, error: :serial_mismatch, store: :kept}
  },
  %{
    id: "snapshot-duplicate-publish",
    from: 2,
    rfc: ["8182#3.5.2.3"],
    rationale:
      "The snapshot publishes one URI twice, with different content: which is the object is ambiguous (F-041), so it is rejected (D-046).",
    expected: %{outcome: {:failed, :snapshot_rejected}, error: :duplicate_publish, store: :kept}
  },
  %{
    id: "delta-hash-mismatch",
    from: 2,
    rfc: ["8182#3.4.2"],
    rationale: "Delta 3 isn't the file the notification's hash names: the snapshot instead.",
    expected: %{outcome: :snapshot, fallback: :delta_hash_mismatch, store: :snapshot}
  },
  %{
    id: "delta-session-mismatch",
    from: 2,
    rfc: ["8182#3.5.3.3"],
    rationale: "Delta 3 names another session: the snapshot instead.",
    expected: %{
      outcome: :snapshot,
      fallback: :delta_rejected,
      error: :session_mismatch,
      store: :snapshot
    }
  },
  %{
    id: "delta-serial-mismatch",
    from: 2,
    rfc: ["8182#3.5.3.3"],
    rationale: "Delta 3's file says serial 4: the snapshot instead.",
    expected: %{
      outcome: :snapshot,
      fallback: :delta_rejected,
      error: :serial_mismatch,
      store: :snapshot
    }
  },
  %{
    id: "delta-withdraw-not-held",
    from: 2,
    rfc: ["8182#3.4.2"],
    rationale:
      "Delta 3 withdraws a URI the store doesn't hold (erratum 6919, F-037): the snapshot instead.",
    expected: %{
      outcome: :snapshot,
      fallback: :delta_rejected,
      error: :withdraw_not_held,
      store: :snapshot
    }
  },
  %{
    id: "delta-withdraw-hash-mismatch",
    from: 2,
    rfc: ["8182#3.4.2"],
    rationale: "Delta 3 withdraws a held object by another object's hash: the snapshot instead.",
    expected: %{
      outcome: :snapshot,
      fallback: :delta_rejected,
      error: :withdraw_hash_mismatch,
      store: :snapshot
    }
  },
  %{
    id: "delta-replace-not-held",
    from: 2,
    rfc: ["8182#3.4.2"],
    rationale:
      "Delta 3 replaces (a publish with a hash) a URI the store doesn't hold: the snapshot instead.",
    expected: %{
      outcome: :snapshot,
      fallback: :delta_rejected,
      error: :replace_not_held,
      store: :snapshot
    }
  },
  %{
    id: "delta-replace-hash-mismatch",
    from: 2,
    rfc: ["8182#3.4.2"],
    rationale:
      "Delta 3 replaces a held object, naming another object's hash: the snapshot instead.",
    expected: %{
      outcome: :snapshot,
      fallback: :delta_rejected,
      error: :replace_hash_mismatch,
      store: :snapshot
    }
  },
  %{
    id: "delta-publish-without-hash",
    from: 2,
    rfc: ["8182#3.4.2"],
    rationale:
      "Delta 3 publishes, without a hash, a URI the store already holds: the snapshot instead.",
    expected: %{
      outcome: :snapshot,
      fallback: :delta_rejected,
      error: :publish_without_hash,
      store: :snapshot
    }
  },
  %{
    id: "notification-cross-origin-uri",
    from: 2,
    rfc: ["9674#3.2"],
    rationale:
      "The notification's snapshot URI is on another host: RRDP can't be used for this repository; the store is kept.",
    expected: %{outcome: {:failed, :cross_origin}, error: :cross_origin, store: :kept}
  },
  %{
    id: "notification-cross-origin-redirect",
    from: 2,
    rfc: ["9674#3.2"],
    rationale: "The notification redirects to another host: refused, the store kept.",
    expected: %{outcome: {:failed, :cross_origin}, error: :cross_origin_redirect, store: :kept}
  },
  %{
    id: "snapshot-cross-origin-redirect",
    from: 2,
    rfc: ["9674#3.2"],
    rationale:
      "The notification at 3 lists no deltas; its snapshot redirects to another host: refused, the store kept.",
    expected: %{outcome: {:failed, :cross_origin}, error: :cross_origin_redirect, store: :kept}
  },
  %{
    id: "delta-cross-origin-redirect",
    from: 2,
    rfc: ["9674#3.2"],
    rationale:
      "Delta 3 redirects to another host: RRDP can't be used for this repository, so the snapshot isn't tried either (unlike a rejected delta); the store is kept.",
    expected: %{outcome: {:failed, :cross_origin}, error: :cross_origin_redirect, store: :kept}
  }
]

# Native SDK validation

Final source: `7379c4ffbb497b2ba14971f102f4383f292fa1a3`. Image: `codex-swap-kms-sdk-builder:security-review-sdk-cleanup`. Export: `prefix-sdk-cleanup`.

The official SDK and crypto stack are retained. The SDK has an explicitly maintained request-lifecycle patch; all other source dependencies are unmodified immutable upstream revisions. The installed `sdk-source.json` records base revision, patch SHA-256 and effective `rest.c` SHA-256, with the exact patch installed alongside it.

- Clean Linux ARM64 native build with upstream `-Werror`, no uninitialized-variable suppression.
- Credential cleanup CTest and all 16 deterministic SDK failure/completion tests passed; current harness uses an atomic waiter handshake. The unpatched SDK fails 10 of the same 16 cases. Both previously uninitialized SDK pointers fail GCC negative-control compilation; the patched source compiles.
- All 45 local official SDK tests passed against the patched source; external-service `test_rest_call_blocking` is excluded. All 29 official json-c Release tests had passed against the unchanged current pin.
- Parent ASan/UBSan/LeakSanitizer parser stress passed 14,684 cases with no errors/leaks against this patched image.
- Exact patch cache reuse passed. Both an old patch and an unrelated tracked modification were rejected; the unrelated edit was preserved rather than reset.

See `results.json` and referenced logs for hashes and evidence. Native tests do not establish live AWS policy enforcement or hardware Nitro attestation.

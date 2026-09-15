# Final native adapter validation

Native source commit `6daf8ab73b2a4edb4059faec1a53041ee62dd357`. Prefix `prefix-strict-input`; image `codex-swap-kms-sdk-builder:security-review-strict-input`.

The actual KMS response KeyId was already validated before unwrap in the prior implementation; no prior key mismatch bypass was demonstrated. Output now explicitly uses the official SDK response key_id. Stable exit codes retain safe failure categories without forwarding raw messages.

The helper now rejects duplicate flat IPC members, including escaped-equivalent names. Fifteen real stdin cases cover duplicate/nested-overwrite inputs, legal escaping, surrogates/control characters and valid requests. The previous helper fails this regression. Empty session tokens remain accepted under the official AWS optional-token API; the pinned SigV4 implementation omits an empty token. Temporary credentials still require their issued token. The pinned bootstrap release was already NULL-safe; the new explicit guard is defensive. Historical 35-second alarm claims do not apply to the existing 12-second helper cap.

All 3 CTests passed: credential cleanup and strict input; 20 response key/output cases and 38 error classifications; 16 SDK lifecycle cases. The actual invalid-input helper exits 64 with no stdout. ASan/UBSan/LeakSanitizer passed 14,684 parser stress cases and both strict-input/response contract CTests, with networking disabled.

The official SDK/dependency library bytes, manifest, NSM lock and SDK patch provenance are unchanged from the build that passed 45 official SDK and 29 json-c tests. Only the application adapter changed; those unchanged-library tests are retained separately. See `results.json` and referenced logs for exact hashes and scope. Native tests do not prove live AWS enforcement or Nitro hardware attestation.

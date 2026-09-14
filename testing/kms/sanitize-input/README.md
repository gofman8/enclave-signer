# Helper input sanitizer check

Run `sh testing/kms/sanitize-input/run.sh` after building the production
`kms-tool-builder` image as `codex-swap-kms-sdk-builder:security-review`.
`KMS_SDK_IMAGE` can select another image built from the same pinned source.

This compiles the actual adapter with AddressSanitizer and UndefinedBehaviorSanitizer,
then exercises truncated, malformed UTF-8/JSON, mutated, nested, and boundary-sized
input through its parser, field validation, and credential cleanup. The Docker
container has networking disabled. No KMS, TLS or NSM request is made, and no real
credentials are used. This is a bounded deterministic stress check, not exhaustive
fuzzing. Upstream dependency objects are the production build and are not compiled
with sanitizers; this check does not claim full upstream instrumentation.

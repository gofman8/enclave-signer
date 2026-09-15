# Pinned official SDK request-lifecycle cleanup

Reviewed official AWS Nitro Enclaves SDK for C commit
`cd61b6187c8b20867ba4368d1ae62c5790c0269a` (v0.4.5). At inspection,
the official main branch still resolved to that commit. The saved upstream
REST source, rest.c history, pull-request inventory, and relevant PR file
responses contain no merged official correction for these paths. No upstream
message or PR was sent.

## Confirmed defects and reachability

- `s_on_sign_complete`: signing failure or signing-result application failure
  jumps to cleanup before the local `stream` declaration; cleanup reads an
  indeterminate pointer.
- `aws_nitro_enclaves_rest_client_request_blocking`: mutex/condition-variable
  initialization failure and early response-allocation failure jump to cleanup
  before `sign_request` is declared; cleanup reads an indeterminate pointer.
- Request stream/message/signable allocation failures were not checked.
  Partial response construction could pass a NULL HTTP response message to its
  destructor, causing a NULL access rather than safe failure.
- Signing is documented by AWS CRT to complete either synchronously or
  asynchronously. The unconditional request wait could miss a synchronous
  failure notification, or return early on a spurious wake. This was reproduced
  without a network or NSM device.

Application validation rejects missing, empty, oversized and malformed IPC
credential fields before SDK construction. Accepted nonempty but incorrect
credentials normally sign locally and receive a remote authorization failure;
we did not demonstrate them triggering the uninitialized-pointer paths. The
confirmed triggers are local allocation/synchronization/signing failures. That
limits demonstrated reachability; it does not make undefined behavior safe.

## Maintained patch

`build/patches/nitro-sdk-cleanup.patch` is a canonical Git diff over the exact
upstream commit. It initializes the two cleanup pointers to NULL, checks the
three missing request allocations, permits partial response destruction, and
publishes request completion while holding the same mutex as the waiter's
predicate loop. Request synchronization resources are cleaned on both exits.
It does not duplicate TLS, SigV4, attestation, CMS or KMS cryptography.

The application now owns this small lifecycle patch until an official SDK
revision includes the corrections. Build-time clean-tree/apply checks, exact
whole-diff verification on reused sources, and recorded base commit, patch
SHA-256 and effective source SHA-256 make the deviation explicit and reject
unreviewed cache mutations. The previous uninitialized-warning suppression is
removed.

## Regression evidence

`enclave/kms-tool/tests/sdk_cleanup.c` links the actual SDK with deterministic,
test-only GNU linker wrappers at allocation/signing/transport boundaries. It
retains real CRT mutex, condition-variable wait and notification behavior.
Sixteen isolated cases cover mutex, condition-variable, input stream, request
message, response struct, response message, signable and signing-init failure;
synchronous signing/apply/stream-create/stream-activate failure; asynchronous
signing/stream failure and success; and a spurious wake. An atomic waiter
handshake makes asynchronous cases independent of scheduler timing; subprocess
alarms fail hangs. Unknown case names fail. Child processes run exit handlers
so sanitizer finalizers are not skipped.

- `native/sdk-cleanup-negative-test.log`: the final harness against the prior
  unpatched library failed 10/16 cases: invalid stream cleanup pointers,
  allocation segfaults, missed completion timeouts and a spurious-wake timeout.
- `native/sdk-cleanup-compiler-control.log`: GCC 10.2.1 with `-O3 -Wall -Wextra
  -Werror=maybe-uninitialized` rejected pristine rest.c for **both** cleanup
  pointers; the same compilation of patched rest.c succeeded. The original
  mutex/early-response runtime cases happened to observe a NULL signable in
  that binary, so their runtime pass alone is not presented as proof of safety.
- The production build's CTest `sdk-request-cleanup` runs all 16 cases on the
  patched installed SDK. Native final-build evidence is recorded separately.

The checked-in CTest is reproducible with the ordinary native build script.
The negative control can be reproduced by building the same test target against
an installation of the exact unpatched SDK base; it must exit nonzero. The
compiler control compares pristine and patched `source/rest.c` using the same
reviewed dependency prefix and header compatibility include.

## Bounded residual

The separate SDK `rest_client_new` connection-setup path still waits without a
completion predicate. An early setup notification can therefore be lost. It
remains outside this request patch: the helper's existing 12-second process
deadline bounds the resulting availability failure; initialization fails closed
and may be retried. This review does not claim that all SDK lifecycle defects
have been eliminated.

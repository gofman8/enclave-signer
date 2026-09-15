# Independent final integration review

Reviewed clean production `dfb3cce0611a115c4058c706c5dce09cf2449971` on 15 September 2026 local time. This focused
follow-up confirmed no new critical or high-severity defect and required no
further production source changes. The exact reviewed hashes and evidence are
recorded in `FINAL-INTEGRATION-REVIEW.json` and `final-source-verification.json`.

## Automatic startup and identity protection

There is no production creation switch. `recover_seed` first loads S3 ciphertext
and reuses it with or without an expected identity pin. Only an explicit missing
object with no pin reaches KMS generation and conditional creation. Read errors,
invalid ciphertext and decryption errors cannot fall back to generation. A pin
blocks missing-state generation/write and rejects a different recovered identity
before activation. The deployment gate infers image classification from the
expected address; operational PCR rollout and retirement of generation authority
remain required before funding. The legacy compatibility fixture alone retains
the retired setting needed by its frozen historical binary.

## Initialization and deadline review

- `state.rs`: Initial → Initializing reservation occurs under the phase mutex,
  which is released before external I/O. Competing transitions reject
  Initializing; keys/signing require Active. RAII restores Initial on failure or
  unwind. The later phase guard drops before the reservation, avoiding a
  self-deadlock. Activation requires a valid recovered manager, any configured
  identity pin to match, and an unexpired aggregate deadline.
- Request ingress and custody dispatch share an absolute deadline; custody is
  capped at 25 seconds with response time reserved. Broker connect/read/write
  operations share a shrinking sub-deadline. Partial reads cannot restart the
  budget, and late completed derivation is rejected before activation.
- The fixed-path helper receives an empty environment and bounded private pipes.
  Its limit is the smaller of 12 seconds or remaining custody time. Timeout
  kills/reaps the helper before joining pipe workers. Generation returns only
  ciphertext; recovery decrypts the committed storage winner and validates the
  exact 64-byte seed and KMS key identity.
- A timed-out conditional S3 PUT can commit later, but the abandoned attempt
  cannot activate. The next initializer loads that winner. Broker worker
  capacity remains occupied until delayed AWS calls finish, bounding retries.

## Native SDK integration

The SDK is explicitly patched for request lifecycle safety. The canonical patch
initializes both cleanup pointers, checks partial allocations, permits partial
response destruction and publishes completion under the waiter's mutex with a
predicate loop. Source integrity checks bind the exact upstream commit, patch
and effective source hashes. Official TLS, SigV4, attestation and CMS code remains
in use. Sensitive helper fields are wiped after independent AWS copies exist;
NSM SONAME and runtime paths match the pinned library.

Retained native evidence covers the same final helper/patch/test source bytes:
16 fault/completion cases and 45 official SDK tests passed; the unpatched SDK
failed 10 cases. GCC rejected both original uninitialized cleanup pointers and
compiled the patch with those warnings treated as errors. These are retained
source-matched results, not a claim that native tests were rerun in this review.
The coordinating workstreams record final process E2E/runtime/EIF results.

## Fresh final-revision checks

All **47 deployment tests** and **222 independent IAM simulation cases** passed.
The testing checkout `73db4917cd0b3eecd6ff39310d1b9ac7e68191dd` contains the production revision and uses
byte-identical validator and policy sources. Counts, commands, timestamps,
source hashes and result hashes are in `final-test-verification.json`; raw logs
and all IAM verdicts are retained alongside it.

## Explicit limits

The separate upstream connection-setup wait can still lose an early notification;
the helper's 12-second deadline bounds that availability failure, which fails
initialization closed and permits retry. An unpinned identity cannot establish
that a dishonest broker supplied the intended same-context ciphertext. Pin the
independently verified identity and complete backup/recovery validation before
funding. Software deadlines cannot force progress under indefinite process or
kernel descheduling. Conditional inherited webpki and optional Helios advisory
limitations remain in `REMEDIATION.md`. Local policy simulation does not prove
real AWS/Nitro enforcement or production backup recovery.

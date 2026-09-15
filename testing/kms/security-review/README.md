# RGB swap KMS review remediation

Validation date: 15 September 2026. This report addresses both supplied branch
reviews, including the second round of deadline/resource-exhaustion findings and
low hardening items, plus the dependency findings in the 14 September security audit. The original audit
is retained as a historical assessment of `9eae978`, not a report of the final code.

Production revision: `6cc65d635717ee6e69a0ac27c8cc78bd6f711800`.
Tested E2E source: `530dc8a2d3079c6e7c48643bf992cf5d78956d7f` on `kms-testing`.
The final evidence commit adds reports only; it does not alter the tested
production or E2E implementation. The policy and sanitizer checks are independently
rerunnable on the testing branch.

## Automatic seed initialization

Removed `SWAP_KMS_ALLOW_CREATE` from the runtime, Dockerfiles, build scripts,
Makefile, CI configuration, deployment approvals and current-signer E2E fixtures.
Initialization loads the existing ciphertext. Only a confirmed missing object can
trigger generation and an atomic create-if-absent write; concurrent creators use
the stored winner. Read errors, invalid ciphertext and decryption failures never
trigger replacement.

`SWAP_KMS_EXPECTED_EVM_ADDRESS` remains an optional identity pin. If configured,
missing ciphertext fails before generation or writing, and a restored different
identity is rejected. The production deployment procedure requires this protection
and retirement of generation authority before funding. No replacement creation
switch was introduced. The immutable legacy client fixture alone retains its old
setting so migration compatibility remains testable.

## Review findings

| Finding | Implemented response |
| --- | --- |
| M1: initialization exceeds request deadline and holds phase mutex | Shared absolute deadline starts at connection acceptance, includes queueing and framing, reserves two seconds for the reply and caps recovery at 25 seconds. Each helper is capped at 12 seconds. The new Initializing phase reserves initialization while releasing the phase lock during external I/O. Expired, failed or panicking recovery returns to Initial and cannot activate late. |
| M2: broker can outlive the enclave request | Broker operations return within seven seconds; enclave broker exchanges have an eight-second total deadline. Removed nested AWS/create retries. Uncancelable late calls retain bounded worker slots. A retry loads the durable conditional-write winner rather than overwriting it. |
| M3: CID authorization gives full instance-role credentials | Added an exact key/object/bucket identity policy with explicit denials outside the dedicated role's scope, including other keys/objects and role assumption. Documented that CID allowlisting is not image identity and grants the whole role. Actual KMS recipient attestation remains the decryption boundary. |
| M4: templates are not tied to approved EIF measurements | Added an offline deployment validator that invokes nitro-cli on actual EIF files, checks approved whole-file hashes, recorded/measured PCRs, CRC/signature status, embedded public custody settings and exact lifecycle policy semantics. It rejects placeholders, debug-zero and known fixture values. The production gate requires restore-only authorization and recorded live AWS/Nitro evidence. |
| M5: incomplete S3 protection denials | Added bucket public-access, ACL, ownership, encryption and replication denials plus object ACL, retention, encryption and tagging denials. Used the actual AWS IAM action `s3:PutBucketPublicAccessBlock`; the review's `s3:PutPublicAccessBlock` spelling is not the correct bucket-policy action. |
| M6: bootstrap poisoning | Documented a pre-funding quarantine and recovery procedure using a fresh protected object/seed namespace or reviewed administrator recovery. Kept deletion protections for funded identities. No automatic deletion, silent reseeding or routine break-glass exception was introduced. |

The validator checks release artifacts and supplied evidence records locally. It
does not authenticate a human approver, inspect the live account, apply policies,
or establish that a referenced live test actually ran. Those responsibilities are
explicit in the deployment procedure.

## Other corrections

- Removed unused `kms_host`, generalized the identity-mismatch error and reused Rust
  protocol limits. Added cross-language limit and timeout hierarchy checks.
- Added real local socket tests for broker framing, malformed responses and slow
  prefix/body trickles. Applied shrinking absolute socket deadlines to prevent a
  peer extending recovery through repeated small reads.
- Preserved an absolute deadline through the ingress queue, preventing queue delay
  from giving initialization a fresh budget after the parent has timed out.
- Deserialize credentials directly into protected strings, including partial parse
  failure cleanup. Erase live json-c credential copies through its public API and
  make helper stdin unbuffered. Short-lived upstream parser scratch copies remain
  a documented limitation; complete zeroization of every upstream allocation is
  not claimed.
- Corrected the CMake minimum, detached build tools from manifest stdin and disabled
  interactive Git prompts. Preserved the upstream NSM `libnsm.so.0` ABI in runtime
  images and test adapters.
- Gave swap-enabled Helios distinct default ports and reject collisions with the
  KMS relay/broker. Reject broker port overrides that differ from the measured port.
- Added bounded accept-loop recovery and constant-code logging; hardened the KMS
  relay service with a dynamic user and systemd restrictions.
- Pinned the broker's complete Python wheel set and installer with hashes. Added a
  native production Docker-stage build to CI and retained full EIF descriptors.
- Fixed the README/Makefile KMS configuration guidance and documented that the dev
  swap image intentionally uses development seed import.

## Dependency maintenance and additional finding

The native stack uses immutable official upstream revisions for AWS-LC 5.8.0,
s2n-tls 1.7.10, the coordinated AWS CRT 1.0.0 libraries and NSM 0.5.2. The official Nitro SDK 0.4.5 supplies KMS transport, attestation and cryptography.
A small checked-in request-lifecycle patch initializes cleanup pointers, checks
failed allocations and prevents lost completion notifications. Compiler/CMake
compatibility options address changes in CRT includes and exports without copying
the SDK implementation into the adapter. The patch is pinned, applied explicitly
and recorded in build provenance; it remains maintenance work until upstream
includes an equivalent correction.
The build uses a checksum-verified Go 1.27.1 toolchain.

These versions address the previously identified s2n TLS-record and signature-policy
issues and the aws-c-http HPACK issue. Rust rustls and parent h2 were updated to
0.23.45 and 0.4.16 respectively and tested across the existing feature matrix.
The remaining optional Helios h2 0.4 path was then updated to 0.4.16 and checked
with the Helios feature enabled. That final lock-only patch leaves normal swap and
parent runtime graphs unchanged; the earlier matrix retains its original lock hashes.

An additional ASan/UBSan check found a json-c 0.19 optimized-build memory leak:
container deallocation occurred only inside an assertion, so `NDEBUG` removed the
call. The manifest now pins unmodified upstream commit
`2094974201fc75b07673110cc40a3e144cbd3b0d`, which includes the correction and
subsequent object-lifetime fixes. The same reproducer now passes all 14,684 cases
under ASan, UBSan and LeakSanitizer with no errors. The test is confined to `kms-testing`; it compiles the
actual adapter and uses no credentials or network access.

The final source review also confirmed upstream SDK request error paths releasing
uninitialized pointers and a synchronous completion callback that could notify
before the waiting thread started. No official corrected SDK revision was
available. These defects are corrected by the narrowly scoped lifecycle
patch and fault-injection regressions; TLS, attestation and cryptographic
algorithms are unchanged. The earlier blanket claim that all SDK source remains
unmodified no longer describes this final maintenance decision.

## Validation evidence

| Check | Result |
| --- | --- |
| Rust CI matrix | 27 positive commands passed; 3,968 passing test executions, zero failed/ignored. Counts overlap across feature profiles. |
| Production feature/release guards | Six invalid combinations rejected with the expected compile errors. |
| Existing non-swap cloning | All ten legacy cloning integration cases passed in the CCD profile. |
| Final Rust regression | 577 swap and 542 mint/burn tests passed after round-two fixes; both production-feature Clippy lanes and formatting passed. The Linux connector and actual enclave binary compiled, and eight Linux forwarder tests passed. |
| Broker, CID relay and deployment validator | 62 tests passed in a fresh hash-locked Python environment. |
| Independent IAM simulation | 222 cases passed across bootstrap, transition and restore, role/session principals and broad attached identity permissions. This is local simulation, not AWS enforcement. |
| Build wiring and protocol bounds | 17 tests passed after removing the obsolete mode-validation test. |
| Upstream json-c | All 29 Release tests passed at the corrected source revision. |
| Native helper/upstream SDK | Final native CTests passed: 15 strict-input/credential cases, 20 response-key/output cases, 38 failure classifications and 16 SDK lifecycle cases. Earlier 45 official SDK and 29 json-c tests cover byte-identical dependency libraries; the external AWS SDK test was excluded. |
| Actual production runtime/EIF | Exact production RGB Dockerfile built for linux/arm64 at the clean final source with secret-mounted private access. Both executables load under shipped AL2023. All runtime layers and metadata passed the build-credential scan. Two actual EIF builds have valid CRCs and identical PCR0/1/2; the removed setting is absent from runtime ENV and both EIF descriptors. |
| Helper input sanitizers | 14,684 deterministic cases plus the strict-input/response CTests passed with ASan, UBSan and LeakSanitizer against the final adapter. The same harness reproduced the 0.19 leak before the upstream correction. |
| SDK request lifecycle faults | All 16 fault-injection cases passed; the same harness exposes ten failures against unpatched upstream. Strict compiler checks and patch-integrity negative controls passed. |
| Local persistence E2E | 44/44 scenarios passed from a clean, unchanged source commit, including restart/replica identity, legacy ciphertext, signatures, concurrent bootstrap, malformed/duplicate helper inputs, KMS responses, policy denials, safe diagnostic categories, broker quota rejection/recovery and TLS negative cases with successful trusted controls. |

The original 27-command Rust matrix predates the optional Helios lock patch and
final automatic-creation change; its original source/lock manifest is retained.
The Helios lane was checked separately, and the affected final swap and mint/burn
lanes plus production E2E were rerun. Native dependency libraries are unchanged from the tested SDK-cleanup build.
The adapter was subsequently hardened for response provenance and strict input;
its CTests and sanitizers were rerun, and the final runtime matches that helper.

The built EIF uses public fixture KMS settings, is unsigned, and intentionally
cannot pass the production approval gate. It validates the build and measured
configuration, not an approved deployment.

The signing implementation, HD derivation and mint/burn Dockerfiles have no diff
from the dev baseline. Shared Rust dependency patch updates received regression
coverage; the non-swap seed/clone behavior remains unchanged.

## Remaining boundaries

- Real Nitro hardware, the NSM trust chain and actual AWS recipient-attestation
  policy enforcement require the deployment account and Nitro host. Local Moto,
  policy simulation and test NSM adapters cannot prove them.
- Before funding: independently verify stored ciphertext, backup recovery, restored
  public identity, negative PCR/context enforcement and retirement of bootstrap
  generation authority. KMS/S3 administrators remain trusted for availability.
- An inherited rustls-webpki 0.101.7 path remains through minreq/Esplora in the
  private RGB dependency stack. Its name-constraint advisories require certificate
  misissuance; its CRL panic path is not configured by minreq. Replacing that TLS
  chain requires coordinated API compatibility work, rather than a safe lock-only
  patch. It is not part of the new KMS TLS stack.
- Optional Helios also retains an old h2 0.3 and Hickory DNS chain outside the
  normal swap/parent runtime graphs. That optional profile needs a separate
  coordinated dependency migration; see the complete advisory disposition.
- The inherited lru advisory requires unwinding after a panicking key destructor;
  the production panic=abort profile excludes that described recovery path.
  Informational unmaintained-package records are retained in the advisory inventory.
- Repeated EIF measurements used the same image, host and Nitro blobs. They do
  not prove reproducible source builds across hosts. Whole EIF files differ due
  to build timestamp metadata. No complete OS-package vulnerability scan was run.
- Native error categories reflect only SDK errors actually propagated to the
  caller and authenticated KMS status/type information. Unknown or lost upstream
  async error details remain internal/invalid-response failures; they are never
  optimistically classified as retryable.
- A separate upstream SDK connection-setup wait can consume the full bounded
  helper timeout after an early or failed notification; it fails closed and retry
  remains possible. The request-lifecycle patch does not claim to correct every
  upstream wait path.
- Builds and tests do not certify absence of vulnerabilities. The bounded sanitizer
  test instruments the adapter, not all upstream objects, and is not exhaustive
  fuzzing. Host Rust tests do not execute Linux vsock or real NSM.

The socket-activated host relay uses distro-managed systemd and socat; these
are outside the Cargo/Python lock inventory. Unit syntax was verified with
systemd 252.39 and socat 1.7.4.4 in Debian ARM64. This is distinct from actually
activating AF_VSOCK on a Nitro parent. Keep host distribution security updates
applied; no complete host OS-package scan is claimed.

Test fixtures, sanitizer tooling and reports belong on `kms-testing`. Production
fixes belong on `codex/rgb-swap-kms-persistence`.

## Round-two review disposition

The second review describes the earlier `9eae978` source. Its broker-deadline and
phase-mutex blocker was already addressed by the first remediation commits. The
additional confirmed gaps were fixed without changing signing algorithms or
non-swap mint/burn transport behavior.

| Finding | Final response |
| --- | --- |
| B1: slow broker trickle wedges all signing | Broker framing uses one shrinking absolute deadline; custody I/O runs outside the phase mutex. Prefix/body trickle and panicking/expired recovery regressions pass. |
| H1: one CID consumes all broker capacity | Global admission plus per-CID connection and AWS-worker quotas. Late timed-out AWS workers retain their permits. Per-CID dispatch rate limits reject excess work before AWS calls. |
| H2: unbounded forwarder threads/connects | Every RGB-swap forwarder uses four workers, eight queued sockets and at most four additional copy threads. The deadline begins at accept and includes the queue. Connect is capped at two seconds; broker lifetime at eight seconds; other swap egress has a 60-second idle and five-minute total limit. Half-close propagates while allowing the response to drain; errors close both directions. Linux loopback tests exercise admission, trickle, failure and half-close. Non-swap transport behavior is preserved. |
| H3: relay accepts every CID | Replaced the unrestricted KMS proxy unit with a systemd socket, a small peer-CID guard and maintained socat byte forwarding. systemd bounds per-CID/global connections, service lifetime and aggregate tasks/memory. The guard checks the actual kernel peer before outbound traffic. Existing task/memory hardening predated this review; CID enforcement was the remaining gap. |
| M7: bind failure panics | Required custody-forwarder failure now logs a fixed startup error and exits explicitly. It does not attach seed custody to an unrelated occupied local port. |
| M8: S3 amplification | Nested retries were already removed: one create performs at most one conditional PUT and one GET. Per-CID token buckets additionally cap sustained AWS dispatch, with no waiting queue. |
| M9: mutex poisoning | Recovery and its helper threads remain outside the phase lock. In swap unwind builds, an immutable active-key callback panic drops its phase guard before resuming the panic; the next signing operation retains the same identity/signature. No poisoned mutable state is blindly accepted. Release panic=abort behavior remains unchanged. |
| M10: Helios collision/docs | Swap Helios defaults are 8005/8006; KMS/broker retain 8003/8004. Colliding overrides are rejected. README and deployment diagrams now agree. Supplied Dockerfiles do not enable Helios. |
| M11: response key provenance | The earlier helper already checked the real KMS KeyId before unwrapping, so the echo was not a key-selection bypass. It now emits the checked official SDK response key_id directly. Key mismatch, missing/malformed fields and unexpected plaintext are rejected; generation still returns ciphertext only. |
| M12: lost error provenance | Helper exit categories and a strict broker error-code envelope distinguish configuration/key/ciphertext, authorization, unavailable and invalid-response failures. Only fixed allowlisted diagnostics cross IPC; arbitrary provider/host text and helper stderr are never forwarded. |

Additional low findings were handled as follows:

- The helper rejects duplicate flat-IPC fields, including escaped duplicate keys,
  after JSON validation. Lone-surrogate values still fail the ASCII field checks;
  regressions cover these parser differences. Empty session tokens remain valid
  for long-term AWS credentials; temporary credentials must supply their token.
- The retained bootstrap pointer has an explicit NULL guard, although the pinned
  upstream release function is already NULL-safe. Both Rust and the native alarm
  are bounded at 12 seconds; a native alarm signal is reported as retryable.
- Broker thread-spawn failure releases its permits, closes the connection and
  resumes admission. S3 retry asymmetry is gone because retries are bounded to a
  single SDK attempt; callers receive a safe retryable category where applicable.
- Startup logs distinguish loading saved ciphertext from attempting conditional
  creation. These messages contain no seed, ciphertext, credential or identity.
  Automatic reuse is intentional: it is the requested behavior after removing
  the creation setting. The address pin and pre-funding recovery procedure remain
  the protection against adopting an unintended existing identity.
- The README now lists all four current enclave custody settings and states that
  cloning secrets do not apply to swaps. Runtime pins accept optional `0x`; the
  deployment approval schema uses canonical `0x` form. Cloning-test instructions
  select a non-swap profile, and CI builds/tests/clippy—including parent—use
  `--locked`.
- Published historical commits were not rewritten to split an old lockfile
  regeneration. Current dependency and security changes have explicit commits;
  the advisory inventory and locked builds identify the actual dependency state.

Fixed diagnostics intentionally expose coarse availability/configuration state
that the host already observes through S3, KMS transport and initialization
outcomes. They disclose no secret material. Hiding whether a poison write caused
failure is not a custody defense; identity pinning, conditional storage, restrictive
policies and independently verified recovery provide that defense.

The CID and rate limits bound resource use and protect capacity between configured
peers. They cannot guarantee availability against a host that stops the enclave,
changes its own relay, or refuses network/storage service. The new relay requires
systemd 252 or newer and socat; follow the migration instructions to stop the old
unrestricted proxy and enable the socket. Actual AF_VSOCK socket activation on an
AWS Nitro parent remains part of deployment validation.

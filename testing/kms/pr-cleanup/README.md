# RGB swap persistence: PR scope cleanup

The PR implements one behavior: RGB swap initialization restores the same
KMS-encrypted seed from S3, or atomically creates it after confirmed absence.
The saved ciphertext format, key derivation and signing algorithms are unchanged.
Mint/burn retains its existing key and cloning lifecycle.

Production: `c980fda77d7631e22879d6cc6477e97249ae65b7`.
Tested E2E source: `625433349048a4e502801ebe1abc737fa13c32d1` on `kms-testing`.
The subsequent evidence commit changes documentation and reports only.

Compared with `dev`, the cleanup reduces the PR from **56 files, +9,406/-6,138**
to **36 files, +4,536/-92**: about 70% fewer changed lines. Published history is
preserved; the cleanup is applied through ordinary commits.

Removed from the implementation branch:

- Deployment approvals, validation framework, custom relay and added systemd units.
- Production Python test suites and native C regression programs; applicable tests
  now live only under `testing/kms` on `kms-testing`.
- The generic forwarder rewrite and signing callback panic-handling change.
- Parent lockfile regeneration, unrelated Rust dependency upgrades and broad CI edits.

The broker remains because the enclave needs a host bridge for AWS credentials
and S3 ciphertext storage. It keeps its framing limits, timeouts, CID admission
and conditional-write behavior. The enclave now connects directly to the broker
over VSOCK, removing its extra TCP listener and forwarding threads. The existing
Bitcoin/EVM forwarder is byte-identical to `dev`.

The remaining native adapter uses the official Nitro SDK for TLS, SigV4,
attestation and recipient cryptography. A necessary SDK request-lifecycle fix
remains: 41 added and 14 removed source lines in `source/rest.c`. Official
v0.4.5 still has the reproduced invalid-pointer cleanup and lost-notification
bugs. The patch does not change cryptographic algorithms. Its regression tests
are maintained on the testing branch.

The integration guide and two manually configured AWS policy examples describe
the required deployment inputs. They do not provide a deployment framework or
claim to constrain arbitrary additional host IAM grants. The existing host
supervisor and standard AWS `vsock-proxy` supply process/network integration.

Validation of the cleaned implementation:

- 569 swap and 542 mint/burn tests; both affected Clippy lanes and formatting.
- 15 Linux persistence tests and a Linux build of the direct VSOCK connector.
- 37 broker tests, 216 IAM simulation cases and seven existing build-wiring tests.
- All three relocated native regression suites passed. The rebuilt helper is
  byte-identical to the previously tested helper.
- 44/44 local E2E scenarios: 37 lifecycle/protocol/transport cases and seven
  policy/API-authentication scenarios. Restart, replica identity, old-client
  ciphertext, concurrent creation, malformed input, timeouts, quotas, policy
  denials and all three trusted TLS controls passed.
- The actual production RGB Dockerfile built for ARM64, both executables loaded
  under AL2023, and one actual Nitro CLI EIF build passed CRC verification. All
  ten image layers passed the credential scan.

The EIF uses public fixture KMS settings and is unsigned. Local emulation and
EIF construction do not prove real Nitro attestation or AWS enforcement.

The earlier `security-review` evidence describes the historical expanded
implementation at `6cc65d6`. Generic transport hardening, deployment tooling and
unrelated dependency updates from that version are outside the cleaned PR.
The parent lockfile is unchanged from `dev`; the test harness maintains its own
resolved parent lockfile on the testing branch.

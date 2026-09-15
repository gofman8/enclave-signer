# Dependency advisory remediation review

Snapshot: 14 September 2026 UTC (15 September local time). Final public package query at production `00b2ae318811c68b04620d1d7ebbe986c3242dc5`, including the optional Helios h2 patch and json-c upstream cleanup fixes. Source SHA256s for both Rust locks, the native NSM lock, native manifest and broker lock are recorded in `osv-results.json` and `disposition.json`. Every recorded source hash matches that committed production state; hashes identify the exact audited inputs.

## Completed dependency fixes

- **New native TLS/HTTP stack:** s2n-tls 1.7.10 is beyond the published 1.7.6 TLS record-suppression fix and earlier signature/exit fixes; aws-c-http 1.0.0 is beyond the 0.11.0 HPACK double-free fix. AWS-LC 5.8.0 is beyond the published 1.69/1.71 PKCS7, AES-CCM, CRL and name-constraint fixes. All nine other repository advisory feeds had no entries at query time; that is not a guarantee of absence.
- **Additional defect found by sanitizer testing:** json-c 0.19 put cleanup used `free` inside `assert`, leaking in Release/NDEBUG builds. The native manifest now pins official upstream post-release commit `2094974201fc75b07673110cc40a3e144cbd3b0d`, which includes that cleanup fix and later lifetime corrections. This was discovered through testing despite its empty advisory feed. Native rebuild/ASan/EIF evidence is maintained by the native-build workstream; this inventory does not substitute for those checks.
- **Inherited rustls:** main and parent locks now use 0.23.45, resolving RUSTSEC-2026-0285 for the modern TLS stack. Old 0.23.43 appears only in the dev baseline.
- **Inherited h2:** parent runtime and root's optional Helios modern HTTP stack now use 0.4.16, resolving RUSTSEC-2026-0258 there. Root lock-only patch is commit `a357c55`; full host `cargo check --locked --offline -p utexo-bridge-enclave --no-default-features --features rgb-swap,evm-rpc,helios` passed (25 seconds). The normal production swap graph contains no h2 dependency.
- **Broker installation:** exact-version SHA256 wheel lock covers boto3/botocore 1.43.94, jmespath 1.1.0, python-dateutil 2.9.0.post0, s3transfer 0.19.2, six 1.17.0, urllib3 2.7.0 and pip 26.2.1. Fresh installation succeeded. A pip-audit scan initially identified the venv's inherited pip 25.0.1; pinning the patched installer removed those matches. All eight final packages have zero known OSV/pip-audit matches. Evidence: `work/security-fixes/deploy-pip-audit.json`.

## Remaining matches and actual scope

The scan queried **873 distinct public package versions** across current locks, `origin/dev` locks, NSM and the broker lock. It returned 21 advisory records including baseline-only versions, duplicate identifiers and maintenance notices. These are not 21 exploitable application bugs. No currently matched package is newly introduced relative to the earlier branch/baseline, except the already-disclosed additional NSM use of unmaintained serde_cbor.

Locked, offline normal-edge graphs target `aarch64-unknown-linux-gnu`: swap features `vsock,rgb-swap,evm-rpc`, parent default profile, and separate optional `helios` graph. **No known-vulnerability match appears in the parent normal graph.** The normal swap graph has these conditional/informational residuals:

| Package / advisory | Disposition and safe follow-up |
| --- | --- |
| rustls-webpki 0.101.7; RUSTSEC-2026-0098, -0099, -0104 (also GHSA aliases) | Inherited through `rgb-ops -> esplora-client 0.12.3 -> minreq 2.14.1 -> rustls 0.21.12`. Name-constraint bugs require CA misissuance; mere parent traffic interception is insufficient. CRL-parsing panic requires CRLs, absent from minreq's stock ClientConfig builder. Production defaults select Electrum, so this Esplora HTTPS branch is also configuration-dependent. Proper removal needs minreq 3 / modern webpki through the pinned RGB/Esplora integration, not a compatible lockfile patch. Keep as a separate transitive API migration; do not silently change private RGB/signing behavior. |
| lru 0.16.4; RUSTSEC-2026-0253 | Inherited through alloy-provider. Described UAF requires a panicking key destructor, unwinding and catch_unwind followed by another cache operation. Production uses `panic = "abort"`, excluding that sequence. Moving alloy's LRU dependency to >=0.18.2 is transitive major-version maintenance; not a demonstrated production memory corruption here. |
| serde_cbor 0.11.2; RUSTSEC-2021-0127 | Existing enclave use plus official NSM. Advisory is unmaintained status, not a vulnerability. Native NSM decodes device responses, not arbitrary parent network CBOR. Track upstream maintenance; do not fork its serialization ABI merely to suppress a notice. |
| paste 1.0.15; RUSTSEC-2024-0436 | Unmaintained proc macro; present in normal build graph but no demonstrated runtime vulnerability. Upstream maintenance migration. |

Additional inherited matches in the optional Helios graph: **h2 0.3.27** (old Hyper/Reqwest chain; no patched 0.3 release is listed) and **hickory-proto 0.25.2** (NSEC3 validation loop and quadratic name compression). Neither is in the normal production swap/parent graph. Enabling Helios requires separately upgrading its old HTTP/DNS chain before treating that optional configuration as fully patched. The NSEC3 issue also depends on DNSSEC validation and crafted DNS responses; no production exploit was reproduced. h2 0.4.15 has been removed from current locks.

Other inherited lock matches—derivative 2.2.0, instant 0.1.13, libsecp256k1 0.7.2, rustls-pemfile 1.0.4 and tracing-subscriber 0.2.25—are retained in the inventory. The first four are maintenance notices; old tracing-subscriber has an ANSI-log-injection advisory and is absent from all three normal graphs examined.

## Evidence and limits

- `query-advisories.py`, `osv-query.log`, `osv-results.json`: reproducible OSV inventory; only public package names/versions are sent, never private Git source.
- `disposition.json`: source hashes, matched package scopes and graph membership.
- `swap-runtime-tree.txt`, `parent-runtime-tree.txt`, `optional-helios-runtime-tree.txt`, `optional-helios-check.log`: graph and compile checks.
- `native/*-advisories.json`: twelve official GitHub advisory feeds. Their 21 entries include absent Rust wrappers and server-only paths; range review is in the native workstream.
- Broker/policy gate: 62 local tests, plus 222 independent open-source IAM simulation cases across three phases and role/session principals, including broad identity grants. These prove local behavior, not AWS enforcement.

There is no new known unremediated advisory in the introduced custody stack at this snapshot. This does not assert vulnerability-free dependencies; inherited optional/conditional limitations above remain explicit. Final native/runtime/E2E build evidence must match the final source hashes before release. Real AWS/Nitro enforcement and backup recovery remain mandatory deployment checks.

## Primary references

- [TLS record suppression](https://github.com/aws/s2n-tls/security/advisories/GHSA-684c-v35q-fvx7)
- [HTTP HPACK](https://github.com/awslabs/aws-c-http/security/advisories/GHSA-rmjr-3qpm-vh98)
- [rustls handshake](https://rustsec.org/advisories/RUSTSEC-2026-0285.html)
- [h2 DATA frames](https://rustsec.org/advisories/RUSTSEC-2026-0258.html)
- [webpki URI constraints](https://rustsec.org/advisories/RUSTSEC-2026-0098.html), [wildcard constraints](https://rustsec.org/advisories/RUSTSEC-2026-0099.html), [CRL parsing](https://rustsec.org/advisories/RUSTSEC-2026-0104.html)
- [LRU panic preconditions](https://rustsec.org/advisories/RUSTSEC-2026-0253.html)
- [minreq major-version migration](https://github.com/neonmoe/minreq/blob/master/Cargo.toml)

## Final SDK lifecycle remediation

Final committed state: `6cc65d635717ee6e69a0ac27c8cc78bd6f711800`. `final-source-verification.json` verifies that
all four package locks are byte-identical to the saved public-query inputs and
all native upstream repository coordinates are unchanged. The manifest's
comment now discloses a maintained SDK patch. The original public-query
snapshot and its hashes remain preserved; this final verification is not
misrepresented as another query.

The SDK request lifecycle now has a small application-maintained cleanup and
completion patch over exact upstream `cd61b61`, with strict canonical-diff build
verification and explicit runtime provenance. The official upstream main had no
merged correction. It initializes cleanup pointers, guards partial allocations,
and synchronizes request completion with a predicate; official TLS, SigV4,
attestation and CMS algorithms remain in use. All 16 injected fault/completion
cases and 45 official SDK tests pass. The same harness failed 10/16 cases against
the unpatched SDK; GCC rejected both original uninitialized pointers and accepts
the patched source with the diagnostic treated as an error. Details and exact
negative-control limits are in `sdk-cleanup/DISPOSITION.md`.

A separate upstream connection-setup wait remains susceptible to a missed early
notification; the helper's 12-second deadline bounds that availability failure.
Initialization fails closed and can be retried. No blanket claim of eliminating
all SDK lifecycle defects is made. Inherited webpki and optional Helios
limitations listed above remain unchanged.

Automatic startup in this final revision has no creation switch. Existing S3
ciphertext is always recovered; only a confirmed missing object without an
expected identity pin permits conditional creation. A configured identity pin
blocks missing-storage replacement. The deployment gate infers image lifecycle
classification from that pin; operational retirement of generation authority
remains required before funding. Fresh final-revision checks passed all 62
deployment tests and all 222 independent IAM cases, recorded in
`final-test-verification.json` and its referenced logs.

The subsequent transport review adds per-CID broker concurrency/rate admission,
CID-gated socket activation for the KMS relay, bounded swap forwarder workers,
and fixed diagnostic categories. These source changes introduce no new Cargo,
NSM or pip package coordinates. systemd and socat are distro-managed parent
packages, outside this saved public-package query. See
`../round-two/relay-systemd-verification.json` for exact locally verified versions
and `../round-two/host-dependency-disposition.md` for the separate host-package
scope. Native helper source changed in this round; the retained SDK patch proof
applies to the unchanged upstream/patch/fault-test bytes, while the final helper,
process E2E and EIF checks are recorded by the current native/E2E workstreams.

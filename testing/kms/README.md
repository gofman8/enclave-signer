# Local KMS persistence E2E

This tooling belongs only on `kms-testing`. The production implementation branch
is `codex/rgb-swap-kms-persistence`. Never merge the testing feature, local CA/PCR
hooks, emulator, or generated artifacts into that branch.

The suite launches actual enclave, seed-broker, and parent-service processes,
plus the real AWS Nitro Enclaves C SDK helper in a Linux container. The
enclave generates its seed through a local KMS API, commits the encrypted blob to
local S3, decrypts the committed blob, derives its normal keys, and signs through
the existing gas transaction path. It then repeats this across process restarts
and replicas. No AWS account, cloud resources, LocalStack token, or Nitro device
is needed. Docker runs the Linux-only official SDK and NSM test adapter.

The current minimal integration keeps the credential/S3 broker and two manually
configured AWS usage-policy examples. The removed deployment validator, custom
systemd relay, and broad permissions-boundary templates are not current feature
coverage. A dedicated test-only role and explicit bootstrap/restore policy edits
model the deployment prerequisites; they are not additional production tooling.

The cleaned revision passed **44/44 scenarios** at testing `6254333`, containing
production `c980fda`. See [cleanup validation](pr-cleanup/README.md) for the exact
scope, source revisions, regression results and actual Docker/EIF evidence.

The earlier security-hardening revision passed **44/44 scenarios** on 2026-09-15
at testing `530dc8a`, production `6cc65d6`. Its
[security review evidence](security-review/README.md) is historical and includes
framework code removed by the subsequent scope cleanup. New cleanup validation
belongs in a separate `.artifacts/kms-pr-cleanup/` run; do not overwrite or relabel
that historical report as evidence for different source or policy guarantees.

The previous 37-scenario baseline passed on 2026-09-14 with the official SDK helper,
including restoration of ciphertext produced by the previous Rust KMS client.
This includes the stricter helper IPC contract and malformed-input checks.
The report records the source revision and hashes of the actual helper, enclave,
parent, and legacy client binaries. The original 35-scenario report predates
this SDK migration and is retained only as historical evidence.

## Run

Prerequisites: Docker, Rust/Cargo 1.96, Python 3.12, Node.js 22 or newer, npm, and the
repository's normal native build dependencies (including CMake, Perl, and
protoc). Existing GitHub access must be able to fetch the private RGB and parent
protocol dependencies. The runner rewrites only this process's private SSH
aliases to HTTPS so Git's existing credential helper can be used; it does not
read or print GitHub tokens or change global Git configuration.

From the repository root:

```sh
docker build --target kms-tool-builder \
  -t codex-swap-kms-sdk-builder:security-review \
  -f build/Dockerfile.enclave.rgb .
mkdir -p .artifacts/kms-sdk/prefix
container_id=$(docker create codex-swap-kms-sdk-builder:security-review)
docker cp "$container_id:/opt/swap-kms/." .artifacts/kms-sdk/prefix/
docker rm "$container_id"
python3.12 -m venv .artifacts/kms-e2e/venv
.artifacts/kms-e2e/venv/bin/python -m pip install -r deploy/requirements-swap-kms.txt
.artifacts/kms-e2e/venv/bin/python -m pip install \
  -r testing/kms/requirements.txt -c testing/kms/requirements.lock
npm ci --prefix testing/kms
.artifacts/kms-e2e/venv/bin/python testing/kms/run.py
```

The production Docker stage builds the exact pinned libraries listed in
`build/swap-kms-dependencies.tsv`. The runner then compiles the production helper
source with only the test linker wrappers and mock NSM library. It builds both
enclave/client binaries and both parent/client binaries
with locked Cargo dependencies, starts the local services, runs the assertions,
and stops its processes even on failure. It returns nonzero on the first failure.
The emulator, clients, and broker bind only to loopback. The container connects
through Docker Desktop/Colima's `host.docker.internal`; native Linux uses host
networking to reach loopback. It refuses occupied ports
instead of stopping another service. Defaults:

| Port | Local service |
| --- | --- |
| 3445 | Verified TLS endpoint for KMS and S3 |
| 3446 | Production seed broker's development TCP listener |
| 15000 | Moto IAM/STS and HTTP transport negative tests |
| 15001 | Test-only fixture, fault, and audit controls |
| Ephemeral | Enclave and parent TCP/gRPC listeners |

Use `--kms-port`, `--broker-port`, `--aws-port`, and `--control-port` for port
overrides; `--node /path/to/node` selects a Node executable. `--sdk-image`,
`--sdk-prefix` select an existing builder image and installed dependency prefix.
Preflight rejects exports whose dependency manifest, reviewed SDK cleanup patch,
or SDK source provenance differs from this checkout. The report retains the
upstream SDK commit, patch hash and effective REST source hash. Verify this check
with `python -m unittest discover -s testing/kms -p 'test_sdk_provenance.py'`.
The prefix includes the pinned upstream CMS header; the helper build does not
require a separate SDK source checkout. `CARGO_TARGET_DIR`
selects the enclave build cache and `KMS_E2E_PARENT_TARGET_DIR` selects the parent
cache. `--skip-build` reuses those binaries. The normal invocation builds the
testing feature itself; it does not enable `dev-mode` or `allow-seed-import`.

Reports, logs, a short-lived test TLS private key, and the Python environment live
under `.artifacts/kms-e2e/`, which is ignored by Git and Docker. Node dependencies
are also ignored. Fake AWS credentials are created in local Moto IAM/STS and held
only in process memory/environment. Inherited AWS credentials, profiles, proxy
settings, and external indexer settings are removed or replaced for the suite.
The JSON report is `.artifacts/kms-e2e/report.json`.

The current suite also checks fixed configuration/authorization/transient error
categories, duplicate-key IPC rejection, and the production broker peer quota.
It refills the unchanged 4/sec, burst-8 quota between deliberate fault cases so
rate limiting cannot mask the intended failure. A separate burst scenario
requires overload rejection and successful initialization after refill.

The runner also builds the previous Rust KMS client from the fixed Git commit
`3d5086558faba04d589ddc63abc6bfc43a8743b9` into an isolated artifact directory.
Keep repository history available when cloning. Its existing encrypted seed is
then restored by the new SDK helper, comparing every public key and the verified
signature. Only that frozen legacy process receives its retired creation setting;
current-signer fixtures have no creation switch and choose from S3 state and the
optional identity pin. The original 35 scenarios, migration check, and direct helper IPC check make
the current expanded suite. Fresh reports identify the exact scenario count and source revision.

## What runs

- Direct helper IPC rejects malformed, missing, unexpected and oversized input
  before contacting KMS. Generation returns exactly ciphertext/key identity and
  no seed; recovery returns exactly the expected 64-byte seed/key identity.

- Bootstrap uses `GenerateDataKey(NumberOfBytes=64)`, attested Recipient CMS,
  conditional `PutObject`, and `Decrypt` of the committed winning ciphertext.
  The parent/broker never receive the response's plaintext seed.
- An unpinned restart loads existing ciphertext without another generation or
  write; a corrupt existing object fails without replacement. A pinned signer
  refuses missing ciphertext before generation or storage mutation.
- All public-key fields and a cryptographically verified EIP-1559 gas signature
  remain identical after restarting both enclave and broker and starting another
  replica. The actual parent gRPC `EVM_GAS_TX` route produces the same signature.
- Two bootstrap enclaves are synchronized after generation to force competing
  `IfNoneMatch="*"` writes. Both activate the same stored identity and signature.
- Ciphertext generated and persisted by the pinned pre-migration Rust client
  restores through the official SDK with the same keys and signature.
- Missing recovery state, altered ciphertext, another valid ciphertext, and a
  wrong expected identity all fail initialization without generating a replacement.
- Native IAM read/write/KMS denial and malformed KMS response cases leave the
  enclave uninitialized. Clearing a transient fault allows retry in that same
  process. Recovery failures preserve the existing ciphertext and identity.
- Swaps reject cloning and raw seed import in the tested feature set.
- A delayed KMS response exercises the real initialization deadline, concurrent worker responsiveness, inactive failure state, and successful retry.
- The concrete production policy templates are evaluated for bootstrap/recovery,
  wrong role/PCR/context, absent Recipient, extra context keys, prohibited key
  operations, HTTPS, conditional object creation, object scope, and deletion.
- Validly authorized requests with an incorrect SigV4 secret are rejected.
  Post-signing payload tampering is also rejected. The enclave rejects an
  untrusted CA, wrong TLS hostname, and plaintext HTTP endpoint.

The transaction exercised across process boundaries is an existing gas-key
EIP-1559 transaction. This suite validates swap seed custody and recovery; it
does not fabricate a Bitcoin/EVM chain or an RGB consignment. Existing RGB
validation/signing and mint/burn regression tests cover those rules separately.
No signing implementation is changed by this branch's test hooks.

## Open-source components and simulation boundary

[Moto 5.2.3](https://github.com/getmoto/moto/tree/5.2.3) (Apache-2.0) supplies IAM
users/roles, STS sessions, signature authentication, KMS random generation and
AES-GCM ciphertext, authenticated encryption context, and S3 storage and
conditional writes. IAM authorization is enabled after local fixture bootstrap;
the suite does not leave Moto's default authentication bypass enabled.

Moto does not implement Nitro Recipient responses and its resource-policy
condition coverage is limited. `emulator.py` therefore wraps its real KMS result
in AWS-compatible streaming BER CMS using RSA-OAEP SHA256/MGF1 SHA256 and
AES-256-CBC, taking the recipient key
from the repository's explicitly mocked CBOR attestation. It removes `Plaintext`
and supplies the AWS `Decrypt.EncryptionAlgorithm` field omitted by Moto. It also
checks an incoming KMS payload hash against the body before native SigV4
authentication; Moto otherwise trusts that header without rehashing the body.
These are test adapter behaviors, not changes to the production KMS client.

The production KMS/S3 usage-policy examples are loaded with fixture substitutions.
`policy_fixtures.py` models manual rollout: it authorizes bootstrap/restore PCRs
and explicitly retires generation for the restore image. The exact-scope identity
in `signer-role-policy.json` is **testing-only** and is installed in Moto IAM.
It has no account-wide permissions boundary; adding another broad Allow can
expand its privileges. The minimal deployment requires an appropriately scoped
role, and the tests no longer claim that production templates prevent all
bucket-administration changes despite arbitrary attached permissions.

Separate scenarios add broad identity access to verify the key policy's explicit
recipient/context/API denies and the bucket policy's overwrite/deletion/HTTPS
denies. Policies run through
[@actsecurity/iam-simulate 0.1.177](https://github.com/act-security-labs/iam-simulate)
(AGPL-3.0-or-later) after Moto's signature/identity checks. The engine evaluates
Principal, action/resource, PCR, context and explicit denies in Strict mode;
validation errors abort the suite. These are local checks, not proof of AWS
hardware attestation or service-policy enforcement.

The pinned simulator's action metadata filter drops some valid dynamic KMS
context keys. The adapter validates the policy, recognizes only the known AWS
KMS context keys, and uses the same engine's public unfiltered entry point to
retain them. Audit entries identify retained context keys. Unknown ignored keys
or engine errors fail the test; production policies are not weakened to fit an
emulator.

Native processes use the gated `local-kms-e2e` feature to select the test helper
wrapper and forward only a local CA, port, and mock PCR0
(`aa` repeated 48 bytes for bootstrap, `bb` for recovery). The production helper
source is compiled unchanged against the same AWS SDK static libraries. Linker
wrappers substitute its socket endpoint and use the SDK's public TLS trust-store
override for the generated local CA, retaining AWS hostname/SNI, certificate and
hostname validation, SigV4, and response/CMS processing. A replacement `libnsm.so`
returns explicitly mocked CBOR containing the SDK's actual RSA public key. The
SDK requests no nonce; the emulator also continues to accept the previous Rust
client's 32-byte nonce form. The SDK's entropy-seeding call still reads the mock
NSM RNG; only its privileged entropy-counter ioctl is simulated. No container
capability is granted for that operation.

The native wrapper uses bounded private stdin/stdout pipes and an explicit Docker
socket selected before the enclave starts. Credentials never enter Docker
arguments or helper environment variables. Release compilation with this
feature is prohibited. These mocks do
not validate AWS's Nitro trust chain, real NSM evidence, vsock transport, or AWS
service-policy enforcement. Those still require a real Nitro deployment.

The fixture control API deliberately permits out-of-band ciphertext replacement
and corruption to model a hostile or faulty storage host. That control is not an
AWS API or part of the production broker. Moto state lives for one suite run;
the suite restarts the signer and broker while the emulated S3 service stays up.

## Production fixes found and backported

The official SDK's pinned CRT could destroy an HTTP connection's event loop
when the local server closed its response, before client cleanup released the
connection. The production helper now retains one CRT bootstrap reference until
after KMS client destruction. This uses the official reference-counting APIs and
leaves upstream sources unchanged. Every successful E2E helper call requires a
clean exit and exercises this server-close path. The fix, checked-in NSM Cargo
lockfile, and verified build-cache fixes are in production commit `12b1419`.

The test-only CMS adapter now emits the streaming BER format consumed by AWS's
SDK parser. This emulator change stays on `kms-testing`.

## Earlier broker restart fix

An immediate restart of the broker's development TCP listener failed because its
closed connections remained in `TIME_WAIT`. Enabling `SO_REUSEADDR` on that TCP
listener fixes the restart; the production vsock listener is unchanged.

- Testing commit: `45f3b10`.
- Backport to `codex/rgb-swap-kms-persistence`: `c9b71d9`.

No emulator dependencies, local trust hooks, or generated test artifacts are
included in that backport. RGB mint/burn and the signing implementations are
unchanged.

Linux release binaries for both flows and a real ARM64 validation EIF were also
built successfully. See [build evidence and reproduction commands](build-validation-notes.md)
for the pinned tools, artifact hashes, runtime compatibility checks, and limits.

## Focused testing-only checks

```sh
.artifacts/kms-e2e/venv/bin/python -m unittest discover -s testing/kms -p test_seed_broker.py -v
.artifacts/kms-e2e/venv/bin/python testing/kms/policy-checks.py
```

The migrated broker suite retains conditional-write races, framing/trickle,
per-CID concurrency/rate quotas, late completion, and fixed-error regressions.
The independent policy report records removed framework-only coverage separately
from the usage-policy cases. `--repo PATH` can validate policy examples from a
separate production checkout without copying them into the testing branch.
The preserved C fault/input/response suites run through the standalone
[native harness](native-tests/README.md); they are no longer production build targets.

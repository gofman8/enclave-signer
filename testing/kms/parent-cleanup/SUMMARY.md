# Parent broker and unmodified SDK validation

Production source: `5caf21e61b10114f77f34175d7224cd7e7f8f83a`. The complete local E2E run passed **44/44 scenarios** on clean testing source `d866f4c638c542a7eeed37aad7ac0f389fdaad13`; the checkout remained clean for the entire run. The attached report is copied unchanged from that run.

Validation also passed:

- **43 parent tests**: 20 broker tests, 5 attestation tests and 18 existing gRPC tests. The actual parent binary built with `--locked --offline`; its Clippy check passed with `-D warnings`.
- **Linux parent compilation**, including the real VSOCK listener, passed with `--locked --offline`. The recorded container was used only as a Rust toolchain/cache; this check does not link its older C SDK or exercise a Nitro device.
- The production **native SDK builder stage built successfully**, and all **4 native CTest entries** passed. Two entries verify helper input/output contracts. The other two explicitly reproduce unmodified SDK GenerateDataKey/Decrypt failure on a closed connection: each reaches the expected 12-second child alarm and is reaped. These are bounded upstream failures, not successful KMS requests or repaired SDK behavior.
- **7 SDK provenance tests** passed, covering the exact pristine source receipt, stale patch metadata and mismatches.
- **216 offline IAM simulations** passed against the two test-only policy fixtures. This is fixture validation, not a production deployment framework or proof of an account's effective AWS permissions. Additional broad grants remain an operator responsibility.

The parent binary was rebuilt from production `5caf21e` and used both as the optional broker and for normal gRPC forwarding. Its SHA-256 is `5d66c414f2527db8ffabcacd7c1dcc03a12c38d52a8ae8a57e9ff22c260bf11f`. The enclave and test clients were reused from the prior `309ef40` run: relevant enclave source, Cargo inputs and client/protocol source are unchanged; the enclave hash matches that earlier report exactly. This run used `--skip-build` for those Rust binaries and rebuilt the local helper against the unmodified SDK. It does not claim those reused binaries were freshly compiled at `d866f4c`.

The native builder originally ran with the cleanup edits uncommitted over `9eb7597`; all eight recorded native input hashes now match committed production `5caf21e`. All six recorded parent source/lock hashes likewise match `5caf21e`. The native report retains the original build provenance rather than relabeling it as a clean-commit build.

The SDK is unchanged upstream commit `cd61b6187c8b20867ba4368d1ae62c5790c0269a`; pristine `source/rest.c` SHA-256 is `60655b9be64b730d333238b13be7846c0a6eba00b540b3dfb9eef35aef39522c`. Production helper SHA-256 is `9baddb3eddbf55d45c99750f3146fbcc4b7c70f64e4b7ddf09e6b9cb740b46c6`. The SDK-only `-Wno-error=maybe-uninitialized` preserves upstream diagnostics as warnings. Known SDK completion/early-cleanup defects remain; process boundaries and deadlines bound failures without proving SDK memory safety.

E2E uses real enclave, Rust parent/broker and official C SDK code with Moto KMS/S3/STS, an IAM simulator, mock NSM attestation, local TLS endpoint wrappers and simulated entropy ioctl. Together, the checks above verify generation, conditional persistence, recovery, concurrent bootstrap, identity protection, signing, denial/error diagnostics, quotas and timeout recovery. They do **not** validate the AWS attestation trust chain, Nitro hardware, live AWS policies, or a new production runtime/EIF image.

Reproduce from the testing checkout using the dependency/build setup in `../README.md`:

```sh
cargo test --locked --offline --manifest-path parent/Cargo.toml
cargo build --locked --offline --manifest-path parent/Cargo.toml --bin utexo-bridge-parent
cargo clippy --locked --offline --manifest-path parent/Cargo.toml --bin utexo-bridge-parent -- -D warnings
.artifacts/kms-e2e/venv/bin/python -m unittest discover -s testing/kms -p test_sdk_provenance.py
.artifacts/kms-e2e/venv/bin/python testing/kms/policy-checks.py --node /path/to/node --output .artifacts/policy-checks.json
```

The exact Linux command is in `parent-linux-check.json`. Native test setup is in `../native-tests/README.md`; the E2E command and pinned SDK image/prefix setup are in `../README.md`. Preserve the production broker quotas and use the recorded unmodified SDK receipt when reproducing this milestone. Historical evidence directories describe older implementations and are not current validation claims.

# Rust regression evidence

Status: PASS.

27 positive commands; 3968 passing test executions; 6 expected compile rejections.

All 10/10 legacy cloning integration tests ran in the non-swap CCD lane. Both Cargo.lock files were unchanged by locked builds, linting and tests.

| Lane | Result | Tests passed |
| --- | --- | --- |
| workspace-format | PASS | 0 |
| parent-format | PASS | 0 |
| workspace-build | PASS | 0 |
| workspace-clippy | PASS | 0 |
| workspace-test | PASS | 539 |
| parent-build | PASS | 0 |
| parent-clippy | PASS | 0 |
| parent-test | PASS | 23 |
| production-combo-build | PASS | 0 |
| production-combo-clippy | PASS | 0 |
| spv-swap-test | PASS | 506 |
| rgb-swap-build | PASS | 0 |
| rgb-swap-clippy | PASS | 0 |
| rgb-swap-test | PASS | 566 |
| rgb-mint-burn-build | PASS | 0 |
| rgb-mint-burn-clippy | PASS | 0 |
| bfa-mint-build | PASS | 0 |
| bfa-mint-clippy | PASS | 0 |
| bfa-mint-test | PASS | 579 |
| ccd-build | PASS | 0 |
| ccd-clippy | PASS | 0 |
| ccd-test | PASS | 352 |
| minimal-build | PASS | 0 |
| minimal-clippy | PASS | 0 |
| minimal-test | PASS | 326 |
| evm-rpc-test | PASS | 561 |
| default-mock-test | PASS | 516 |
| release-guard-allow-seed-import | Expected rejection verified | — |
| release-guard-mock-attestation | Expected rejection verified | — |
| release-guard-dev-mode | Expected rejection verified | — |
| feature-guard-missing-spv | Expected rejection verified | — |
| feature-guard-both-flows | Expected rejection verified | — |
| feature-guard-missing-flow | Expected rejection verified | — |

Source SHA256 manifest: `sources-d0aa78521ea69ce7ffe99f6991761c3a60777869aec67c6636ad8a4d765d7822.json`. Exact commands, source hashes, timing and log hashes are in `results.json` and `guards.json`.

This is macOS host verification; Linux/vsock/NSM and AWS service validation are separate. Test counts overlap across feature profiles.

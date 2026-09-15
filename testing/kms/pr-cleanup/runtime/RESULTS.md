# Minimal PR runtime validation

Source: `c980fda77d7631e22879d6cc6477e97249ae65b7`. Actual `build/Dockerfile.enclave.rgb`, Linux ARM64.

Both enclave and helper load successfully on the production AL2023 runtime. The helper is byte-identical to the previously tested binary. Runtime manifest and exact SDK patch match the repository, and tracked source remained unchanged during the build.

Image: `sha256:6955eb017c1880e4934f6a91d762e4984e99299625f382d47ba4f986ad601e33`.

EIF SHA-256: `3da821daeceb3a9559173020e1fa9159733347577cb15d4336276c7be7567e64`. Actual `nitro-cli build-enclave` and `describe-eif` succeeded; CRC is valid. PCR values and input blob hashes are in `results.json`.

All 10 final image layers were checked, including deleted files: no build credential, secret environment entry, or temporary credential/askpass path was found.

This is an unsigned fixture EIF for local build verification. It does not validate live AWS KMS/S3 permissions, Nitro hardware attestation, real vsock execution, or production readiness. Earlier review images and reproducibility experiments remain historical.

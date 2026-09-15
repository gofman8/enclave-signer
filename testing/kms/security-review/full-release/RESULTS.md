# Final production RGB swap image and EIF validation

Built from clean production commit `6cc65d635717ee6e69a0ac27c8cc78bd6f711800` for `linux/arm64` using the actual `build/Dockerfile.enclave.rgb`, GitHub credentials supplied only as a BuildKit secret, and public local fixture KMS settings. The repository remained unchanged during the build. Source SHA-256 values and executable command arrays are retained alongside these results.

Runtime image: `codex-kms-swap-production-validation:security-review-final-hardening`

Image ID: `sha256:ff0c639631959cceb5563f176a5e9af7b7b6d061ed4020d8917396d4622d1d76`

The removed `SWAP_KMS_ALLOW_CREATE` setting is absent from the build arguments, final runtime environment and both actual EIF descriptors. This initial-startup fixture has no expected-address pin. The production validator infers initial startup from that empty pin and validates the measured public custody settings.

The final AL2023 loader resolves both binaries. The runtime helper and NSM hashes exactly equal the tested native prefix. Its installed dependency manifest, SDK patch, and base/patch/effective-source provenance match the repository and tested native prefix. The native adapter now emits the authoritative SDK response key, retains safe failure categories, and rejects duplicate IPC names. The official SDK/dependency library bytes are unchanged from their upstream test run.

Every final runtime layer was scanned, including files deleted by later layers: 10/10 layers and 3379 regular files. No exact build-credential matches, temporary authentication files, or secret environment names were found. Credential bytes were checked only in memory and never recorded.

Actual `nitro-cli 1.4.5 build-enclave` and `describe-eif` succeeded twice. Both EIF files have valid CRC. PCR0, PCR1 and PCR2 match between two builds from the same host, normalized runtime image and Nitro blobs. This verifies that specific repeat-build scope; it does not establish cross-host reproducibility. The full EIF hashes differ because build metadata timestamps differ.

- PCR0: `d97d9316884643f9a1cb468206f9b98662c74704bf04b6187b98dcf9c1a29dabf243a8dc85134c8a2b5755efa9e973bb`
- PCR1: `745004eab9a0fb4a67973b261c6e7fa5418dc870292927591574385649338e54686cdeb659f3c6c2e72ba11aba2158a8`
- PCR2: `4e31fd32bc26b6c50f5f94ce75eb592c77e45afb5be747d34e1c4960fc579b7e6e5b5d4f9ecc54d699f2610efec8127f`
- First EIF SHA-256: `ec0071287fa766445fd40a64899bf5351e3c8824d756c892c5da85623d33e874`
- Repeated EIF SHA-256: `cef479069cdcdbcd5ed93182bb29a74c4b1db7275f2c02f5164f20b0fbc083ba`

As an additional negative control, the updated validator inspected the previous actual EIF and rejected its obsolete setting. The production deployment validator inspected the actual EIF through the actual Nitro CLI and accepted its structural/hash/CRC/measured-configuration checks. A changed measured seed ID was rejected. The full approval validator rejected the local fixture account. This is an unsigned local validation image with fixture KMS settings, **not an approved deployment**; no live AWS policy/service enforcement, Nitro NSM device, real vsock, enclave execution or attestation was claimed.

Native validation is in `../native/results.json`: unchanged SDK/dependency library bytes retain their 45 official SDK and 29 json-c test results. The final helper passed credential cleanup, 15 strict IPC cases, 20 key/output cases, 38 error classifications, 16 SDK lifecycle cases, and 14,684 sanitizer parser cases plus sanitized input/response contract tests. The original SDK fails 10 of those 16 lifecycle cases and fails compiler negative controls for both uninitialized pointers. SDK patch cache integrity accepts only the exact reviewed patch and preserves rejected unrelated changes. Rust startup behavior and local service E2E tests are documented separately by their test runners.

Earlier images and EIFs are retained under explicitly named historical directories; the unqualified files here are the final response/IPC and resource-hardening build.

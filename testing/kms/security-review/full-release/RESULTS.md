# Final production RGB swap image and EIF validation

Built from clean production commit `dfb3cce0611a115c4058c706c5dce09cf2449971` using the actual `build/Dockerfile.enclave.rgb`, GitHub credentials supplied only as a BuildKit secret, and public local fixture KMS settings. The repository remained unchanged during the build. Source SHA-256 values and executable command arrays are retained alongside these results.

Runtime image: `codex-kms-swap-production-validation:security-review-automatic-create`

Image ID: `sha256:592df409ee04a7b602b4f09ed491c45e55502032e5fce076c37d9e3038bcccde`

The removed `SWAP_KMS_ALLOW_CREATE` setting is absent from the build arguments, final runtime environment and both actual EIF descriptors. This initial-startup fixture has no expected-address pin. The production validator infers initial startup from that empty pin and validates the measured public custody settings.

The final AL2023 loader resolves both binaries. The runtime helper and NSM hashes exactly equal the native binaries used for SDK and sanitizer testing. Its installed dependency manifest, SDK patch, and base/patch/effective-source provenance match the repository and tested native prefix. Native SDK code is unchanged by this startup-flow revision.

Every final runtime layer was scanned, including files deleted by later layers: 10/10 layers and 3379 regular files. No exact build-credential matches, temporary authentication files, or secret environment names were found. Credential bytes were checked only in memory and never recorded.

Actual `nitro-cli 1.4.5 build-enclave` and `describe-eif` succeeded twice. Both EIF files have valid CRC. PCR0, PCR1 and PCR2 match between two builds from the same host, normalized runtime image and Nitro blobs. This verifies that specific repeat-build scope; it does not establish cross-host reproducibility. The full EIF hashes differ because build metadata timestamps differ.

- PCR0: `bccc73d93a81eefb4d62dcc5f604a7721bfd573073124f6308b698d8a9485e49071832383b34ac9f8d2aef32116a4faf`
- PCR1: `745004eab9a0fb4a67973b261c6e7fa5418dc870292927591574385649338e54686cdeb659f3c6c2e72ba11aba2158a8`
- PCR2: `4c3eeebe1dc50477a4141dcf405c2125a143366f59f2e9881da9b722837a1da6a93ab6ec5eb466c4d902a792d19b2547`
- First EIF SHA-256: `ddccba5d36a45413a4b1f0c8577f4be8b2cce66272e4a8f75044658220eb0184`
- Repeated EIF SHA-256: `6c53d64dc1f158291a5bc7ede94bee99c03bc4dbdd4ffd681432af64bbd9ca9f`

As an additional negative control, the updated validator inspected the previous actual EIF and rejected its obsolete setting. The production deployment validator inspected the actual EIF through the actual Nitro CLI and accepted its structural/hash/CRC/measured-configuration checks. A changed measured seed ID was rejected. The full approval validator rejected the local fixture account. This is a local validation image, **not an approved deployment**; no live AWS policy/service enforcement, Nitro NSM device, real vsock, enclave execution or attestation was claimed.

Native validation is in `../native/results.json`: 45 official local SDK tests, 29 official json-c Release tests, the credential cleanup test, 16 SDK lifecycle cases, and 14,684 sanitizer parser cases passed against the unchanged helper. The original SDK fails 10 of those 16 lifecycle cases and fails compiler negative controls for both uninitialized pointers. SDK patch cache integrity accepts only the exact reviewed patch and preserves rejected unrelated changes. Rust startup behavior and local service E2E tests are documented separately by their test runners.

Earlier images and EIFs are retained under explicitly named historical directories; the unqualified files here are the final automatic-creation build.

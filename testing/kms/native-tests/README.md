# Native helper checks

These tests include the current production helper source and link the same unmodified pinned SDK libraries. They test credential cleanup/strict IPC and authoritative KMS response keys/error categories. The closed-connection checks use the real AWS signer and HTTP transport without wrappers.

Run inside the Linux SDK builder with the repository mounted at `/repo`:

```sh
cmake -GNinja -S /repo/testing/kms/native-tests -B /tmp/swap-kms-native-tests \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/opt/swap-kms
cmake --build /tmp/swap-kms-native-tests --parallel 4
LD_LIBRARY_PATH=/opt/swap-kms/lib \
  ctest --test-dir /tmp/swap-kms-native-tests --output-on-failure --parallel 2
```

There are four CTest entries. For both KMS operation targets, the closed-connection test requires that the actual SDK request begins and then exhausts the isolated child's 12-second alarm; the parent verifies SIGALRM and reaps it. This records the pinned SDK's known failure behavior, not a repaired SDK or real Nitro/KMS operation. Rust separately tests rejection of failed/late helper processes, and local E2E covers successful generation, persistence and recovery.

The prior patched-SDK fault suite has been retired. Its synthetic callback/allocation cases are not success requirements for the unmodified dependency. An SDK upgrade that fixes notification handling must update the explicit timeout expectation.

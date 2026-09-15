# Native helper regressions

These tests include the current production helper source and link the same pinned SDK libraries. Test-only linker wrappers inject request failures; production code has no test hooks. The closed-connection regression uses the real signer and HTTP transport without wrappers.

Run inside the Linux SDK builder with the repository mounted at `/repo`:

```sh
cmake -GNinja -S /repo/testing/kms/native-tests -B /tmp/swap-kms-native-tests \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/opt/swap-kms
cmake --build /tmp/swap-kms-native-tests --parallel 4
LD_LIBRARY_PATH=/opt/swap-kms/lib \
  ctest --test-dir /tmp/swap-kms-native-tests --output-on-failure
```

The five CTest entries check credential cleanup and strict IPC, authoritative KMS response keys and fixed error categories, 11 SDK request lifecycle cases, and closed-connection handling for both KMS operation targets. The last two must fail against the unpatched SDK as a negative control when changing the maintained patch. Forced allocation-NULL cases are excluded: the pinned allocator aborts on OOM.

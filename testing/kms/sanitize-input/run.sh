#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
image=${KMS_SDK_IMAGE:-codex-swap-kms-sdk-builder:security-review}
docker run --rm --network none \
  --mount "type=bind,src=$repo,dst=/source,readonly" \
  --env LD_LIBRARY_PATH=/opt/swap-kms/lib \
  --env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1 \
  --env UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
  "$image" sh -c '
    cmake -GNinja -S /source/testing/kms/sanitize-input -B /tmp/input-sanitizers \
      -DCMAKE_PREFIX_PATH=/opt/swap-kms -DCMAKE_BUILD_TYPE=Debug
    cmake --build /tmp/input-sanitizers --parallel 2
    /tmp/input-sanitizers/input-stress
  '

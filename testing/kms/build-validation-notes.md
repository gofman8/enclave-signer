# Local Linux release and EIF build validation

On 2026-09-14, the RGB-swap ARM64 release binary and official AWS Nitro
Enclaves SDK helper were built and packaged into an unsigned EIF. The Rust
binary uses `vsock,rgb-swap,evm-rpc` with default features disabled and no
mock, seed-import or development features. Signing code is unchanged. The
source inputs match production commit
`12b1419d8b0998e5c67b1288380d552e2256f411`; the Rust source is identical to
its release build at `9ec30276b138dd7b81c7f7a6620b2fc9bff757c4`.

The SDK is pinned to `cd61b6187c8b20867ba4368d1ae62c5790c0269a`, using its
unmodified source and the dependency revisions from its
`containers/Dockerfile.al2`. The adapter retains an official CRT bootstrap
reference until connection cleanup, preventing a shutdown crash observed
when the local KMS server closed its connection. No SDK source is patched.
The build driver uses the committed NSM Cargo lock and gives `libnsm.so` a
SONAME so it loads from the runtime's normal library directory.

The assembled AL2023 runtime passes loader checks for the Rust executable,
SDK helper and NSM library without `LD_LIBRARY_PATH`. Its CA certificate
package supplies `/etc/pki/tls/certs/ca-bundle.crt`, one of the official CRT's
runtime-detected trust-store paths. Nitro CLI 1.4.5 and its ARM64 blobs
produce an EIF for which `describe-eif` reports `CheckCRC: true`.

| Current SDK artifact | SHA-256 |
| --- | --- |
| RGB-swap release binary | `4f1e475ce00399adf70938da2c7e063bf01c2e9ebe141f99c0130ad03eb5987f` |
| Official SDK helper | `6a06a7670867a6bc631433acc98710cd73bf44407de54b0352582bf213d76f42` |
| NSM runtime library | `394b96e9f4d67ac7e38bcfe2f36363f4ae3891e724d40a61caad11491d549af3` |
| RGB-swap validation EIF | `9ee33ead58746d2aad0caa64265d23e877d826a09ff96f402ffe3a8b9d7a1421` |

These artifacts supersede the earlier custom-client swap EIF. The EIF uses
a fixture KMS ARN and seed ID, and is a build-validation artifact. No Nitro
hardware execution or real AWS call was performed. The Rust binary used the
pinned Bookworm builder and Cargo release defaults without the production
Dockerfile's path-remapping flags; SDK dependencies used the pinned Bullseye
builder. Local Docker used the legacy builder. These results do not assert
production PCR reproducibility or provide deployable measurements. Detailed
logs, source hashes and artifact checksums are recorded in the validation
output's `build-validation.json` and `SHA256SUMS`.

## Reusable commands

Run from the repository root with Docker, Python 3, Git and private Rust
dependencies already fetched into the host Cargo cache. Keep generated files
in the ignored `.artifacts` directory. This reproduces the procedure, not
identical hashes: timestamps, source changes and build paths can change PCRs.

```bash
KMS_REPO_ROOT="$(pwd)"
KMS_BUILD_DIR="$KMS_REPO_ROOT/.artifacts/kms-build-validation"
KMS_CARGO_CACHE="${CARGO_HOME:-$HOME/.cargo}"
KMS_RUST_IMAGE=rust:1.96.1-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663
mkdir -p "$KMS_BUILD_DIR/target" "$KMS_BUILD_DIR/out" "$KMS_BUILD_DIR/sdk-prefix"
```

Build the production SDK stage, which needs only public dependencies. Extract
that stage into a standalone Dockerfile so a legacy Docker builder does not
need to parse the later private-dependency BuildKit mounts. Its dependency
sources, CMake version and build flags come directly from the production
Dockerfile and `build/build-swap-kms-tool.sh`.

```bash
python3 - "$KMS_REPO_ROOT" "$KMS_BUILD_DIR" <<'PYSDK'
from pathlib import Path
import sys
repo, build = map(Path, sys.argv[1:])
text = (repo / 'build/Dockerfile.enclave.rgb').read_text()
stage = text.split('FROM kms-tool-builder AS builder', 1)[0]
(build / 'Dockerfile.sdk').write_text(stage)
PYSDK
DOCKER_BUILDKIT=0 docker build --platform linux/arm64 \
  -f "$KMS_BUILD_DIR/Dockerfile.sdk" \
  -t codex-kms-sdk-build-validation:local "$KMS_REPO_ROOT"
KMS_SDK_CONTAINER=$(docker create codex-kms-sdk-build-validation:local)
trap 'docker rm "$KMS_SDK_CONTAINER" >/dev/null' EXIT
docker cp "$KMS_SDK_CONTAINER:/opt/swap-kms/." "$KMS_BUILD_DIR/sdk-prefix/"
docker rm "$KMS_SDK_CONTAINER" >/dev/null
trap - EXIT
```

Build the Rust swap release using the existing private-dependency cache.
The SDK helper and Rust executable are separate processes, so the Rust build
does not need to link the C dependency prefix.

```bash
docker run --rm --platform linux/arm64 --cpus 3 \
  -e CARGO_TARGET_DIR=/target -e CARGO_BUILD_JOBS=3 -e CARGO_INCREMENTAL=0 \
  -v "$KMS_REPO_ROOT:/build:ro" \
  -v "$KMS_CARGO_CACHE/registry:/usr/local/cargo/registry" \
  -v "$KMS_CARGO_CACHE/git:/usr/local/cargo/git" \
  -v "$KMS_BUILD_DIR/target:/target" -v "$KMS_BUILD_DIR/out:/out" \
  -w /build "$KMS_RUST_IMAGE" sh -ec '
    apt-get update
    apt-get install -y --no-install-recommends cmake
    cargo build --offline --locked --release -p utexo-bridge-enclave \
      --bin utexo-bridge-enclave --no-default-features \
      --features vsock,rgb-swap,evm-rpc
    cp /target/release/utexo-bridge-enclave /out/utexo-bridge-enclave-rgb-swap-aarch64-linux
  '
```

Reuse the production runtime stage and substitute all four artifact COPY
sources: Rust executable, SDK helper, NSM library and dependency provenance.
Keep the runtime's `ca-certificates` and `libgcc` installation. The helper
requires the default NSM library location because Rust clears its environment.

```bash
python3 - "$KMS_REPO_ROOT" "$KMS_BUILD_DIR/out" "$KMS_BUILD_DIR/sdk-prefix" <<'PYRUNTIME'
from pathlib import Path
import shutil, sys
repo, out, sdk = map(Path, sys.argv[1:])
runtime = (repo / 'build/Dockerfile.enclave.rgb').read_text().split('# --- Runtime ---', 1)[1]
replacements = {
    'COPY --from=builder /build/target/release/utexo-bridge-enclave /app/utexo-bridge-enclave':
        'COPY utexo-bridge-enclave-rgb-swap-aarch64-linux /app/utexo-bridge-enclave',
    'COPY --from=kms-tool-builder /opt/swap-kms/bin/swap-kms-tool /usr/local/bin/swap-kms-tool':
        'COPY swap-kms-tool /usr/local/bin/swap-kms-tool',
    'COPY --from=kms-tool-builder /opt/swap-kms/lib/libnsm.so /usr/lib64/libnsm.so':
        'COPY libnsm.so /usr/lib64/libnsm.so',
    'COPY --from=kms-tool-builder /opt/swap-kms/share/swap-kms /usr/share/swap-kms':
        'COPY swap-kms-provenance /usr/share/swap-kms',
    'COPY build/entrypoint.sh /app/entrypoint.sh':
        'COPY entrypoint.sh /app/entrypoint.sh',
}
for source, destination in replacements.items():
    assert source in runtime, source
    runtime = runtime.replace(source, destination)
(out / 'Dockerfile.swap-validation').write_text(runtime)
shutil.copy2(repo / 'build/entrypoint.sh', out / 'entrypoint.sh')
shutil.copy2(sdk / 'bin/swap-kms-tool', out / 'swap-kms-tool')
shutil.copy2(sdk / 'lib/libnsm.so', out / 'libnsm.so')
shutil.copytree(sdk / 'share/swap-kms', out / 'swap-kms-provenance', dirs_exist_ok=True)
(out / '.dockerignore').write_text(
    '*\n!Dockerfile.swap-validation\n!utexo-bridge-enclave-rgb-swap-aarch64-linux\n'
    '!swap-kms-tool\n!libnsm.so\n!swap-kms-provenance/\n!swap-kms-provenance/**\n!entrypoint.sh\n')
PYRUNTIME
DOCKER_BUILDKIT=0 docker build --platform linux/arm64 \
  --build-arg SWAP_KMS_KEY_ARN=arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-123456789012 \
  --build-arg SWAP_KMS_REGION=eu-west-1 \
  --build-arg SWAP_KMS_SEED_ID=official-sdk-build-validation-only \
  --build-arg SWAP_KMS_ALLOW_CREATE=1 \
  --build-arg SWAP_KMS_EXPECTED_EVM_ADDRESS= \
  -f "$KMS_BUILD_DIR/out/Dockerfile.swap-validation" \
  -t codex-kms-swap-build-validation:local "$KMS_BUILD_DIR/out"

docker run --rm --entrypoint /bin/sh \
  codex-kms-swap-build-validation:local -ec '
    /lib/ld-linux-aarch64.so.1 --verify /app/utexo-bridge-enclave
    /lib/ld-linux-aarch64.so.1 --list /app/utexo-bridge-enclave
    /lib/ld-linux-aarch64.so.1 --verify /usr/local/bin/swap-kms-tool
    /lib/ld-linux-aarch64.so.1 --list /usr/local/bin/swap-kms-tool
    /lib/ld-linux-aarch64.so.1 --list /usr/lib64/libnsm.so
    test -s /etc/pki/tls/certs/ca-bundle.crt
  '
```

Build the public Nitro CLI tool with an isolated Cargo cache. The source
revision checked below is the inspected v1.4.5 tag.

```bash
git clone --depth 1 --branch v1.4.5 \
  https://github.com/aws/aws-nitro-enclaves-cli.git "$KMS_BUILD_DIR/nitro-src"
test "$(git -C "$KMS_BUILD_DIR/nitro-src" rev-parse HEAD)" = \
  18a5f6f35f110c0f235f193ae3caff9434d64ee1
mkdir -p "$KMS_BUILD_DIR/nitro-cargo" "$KMS_BUILD_DIR/nitro-target"
docker run --rm --platform linux/arm64 --cpus 2 -e CARGO_HOME=/nitro-cargo \
  -e CARGO_TARGET_DIR=/nitro-target -e CARGO_BUILD_JOBS=2 \
  -v "$KMS_BUILD_DIR/nitro-src:/nitro-src:ro" \
  -v "$KMS_BUILD_DIR/nitro-cargo:/nitro-cargo" \
  -v "$KMS_BUILD_DIR/nitro-target:/nitro-target" \
  -v "$KMS_BUILD_DIR/out:/out" -w /nitro-src "$KMS_RUST_IMAGE" sh -ec '
    apt-get update
    apt-get install -y --no-install-recommends cmake
    cargo build --locked --release -p nitro-cli
    cp /nitro-target/release/nitro-cli /out/nitro-cli
    /out/nitro-cli --version
  '

docker run --rm --platform linux/arm64 -e NITRO_CLI_BLOBS=/blobs \
  -e NITRO_CLI_ARTIFACTS=/tmp/nitro-artifacts \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$KMS_BUILD_DIR/nitro-src/blobs/aarch64:/blobs:ro" \
  -v "$KMS_BUILD_DIR/out:/out" "$KMS_RUST_IMAGE" sh -ec '
    mkdir -p /tmp/nitro-artifacts /var/log/nitro_enclaves /run/nitro_enclaves
    /out/nitro-cli build-enclave \
      --docker-uri codex-kms-swap-build-validation:local \
      --output-file /out/rgb-swap-official-sdk-validation-arm64.eif
    /out/nitro-cli describe-eif --eif-path /out/rgb-swap-official-sdk-validation-arm64.eif \
      > /out/rgb-swap-official-sdk-validation-arm64.describe.json
    cd /out
    sha256sum utexo-bridge-enclave-rgb-swap-aarch64-linux swap-kms-tool libnsm.so \
      rgb-swap-official-sdk-validation-arm64.eif > SHA256SUMS
  '
```

The Docker socket mount lets Nitro CLI read the local validation image and
package its filesystem. It does not execute an enclave. With Docker Desktop
or Colima, this path is the socket inside the Linux Docker daemon host; it
need not exist as `/var/run/docker.sock` on macOS. The procedure uses ARM64
builder images, executable and Nitro blobs; all three must match when using
another architecture.
